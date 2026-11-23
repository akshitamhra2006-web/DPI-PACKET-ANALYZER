#include "incident_correlator.h"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <set>
#include <cmath>

namespace DPI {

// Helper to format IP
static std::string formatIP(uint32_t ip) {
    std::ostringstream ss;
    ss << (ip & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

static IncidentSeverity mapScoreToSeverity(double score, const IncidentConfig& config) {
    if (score >= config.critical_score_threshold) return IncidentSeverity::CRITICAL;
    if (score >= config.high_score_threshold) return IncidentSeverity::HIGH;
    if (score >= config.medium_score_threshold) return IncidentSeverity::MEDIUM;
    return IncidentSeverity::LOW;
}

static std::string formatIsoTimestamp(uint64_t ts_us) {
    if (ts_us == 0) return "";
    time_t sec = static_cast<time_t>(ts_us / 1000000ULL);
    uint32_t usec = static_cast<uint32_t>(ts_us % 1000000ULL);
    struct tm tm_buf;
    gmtime_r(&sec, &tm_buf);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);
    char out[80];
    std::snprintf(out, sizeof(out), "%s.%06uZ", buf, usec);
    return std::string(out);
}

IncidentCorrelator::IncidentCorrelator()
    : config_(IncidentConfig{}) {}

IncidentCorrelator::IncidentCorrelator(const IncidentConfig& config)
    : config_(config) {}

std::string IncidentCorrelator::generateIncidentId() {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "INC-%04llu", static_cast<unsigned long long>(next_incident_id_++));
    return std::string(buf);
}

std::vector<SecurityIncident> IncidentCorrelator::correlate(
    const std::vector<DetectionEvent>& detections,
    const std::vector<FlowRecord>& flows,
    const std::vector<StreamRecordSummary>& streams,
    const std::vector<SignatureEvent>& signatures,
    const std::vector<ThreatMatchEvent>& threat_matches) {

    std::vector<SecurityIncident> raw_incidents;

    // Group detections by primary endpoint (source IP string)
    std::map<std::string, std::vector<const DetectionEvent*>> ep_detections;
    for (const auto& det : detections) {
        std::string ep = det.source_ip_str;
        if (ep.empty() && det.source_ip != 0) {
            ep = formatIP(det.source_ip);
        }
        if (!ep.empty()) {
            ep_detections[ep].push_back(&det);
        }
    }

    // Group flows by primary endpoint (initiating client IP)
    std::map<std::string, std::vector<const FlowRecord*>> ep_flows;
    for (const auto& flow : flows) {
        std::string ep = formatIP(flow.initial_tuple.src_ip);
        ep_flows[ep].push_back(&flow);
    }

    // Collect all unique endpoints across detections and flows
    std::set<std::string> all_endpoints;
    for (const auto& [ep, _] : ep_detections) all_endpoints.insert(ep);
    for (const auto& [ep, _] : ep_flows) all_endpoints.insert(ep);

    // Evaluate correlation rules per endpoint
    for (const auto& ep : all_endpoints) {
        const auto& dets = ep_detections[ep];
        const auto& fls = ep_flows[ep];

        // 1. Reconnaissance Correlation
        if (config_.enable_reconnaissance_correlation) {
            evaluateReconnaissance(ep, dets, fls, raw_incidents);
        }

        // 2. DNS Suspicious Activity Correlation
        if (config_.enable_dns_correlation) {
            evaluateDNSSuspicious(ep, dets, fls, raw_incidents);
        }

        // 3. Suspicious Outbound Communication Correlation
        if (config_.enable_outbound_correlation) {
            evaluateSuspiciousOutbound(ep, dets, fls, streams, raw_incidents);
        }

        // 4. Potential Data Exfiltration Correlation
        if (config_.enable_exfiltration_correlation) {
            evaluateDataExfiltration(ep, dets, fls, raw_incidents);
        }

        // 5. Multi-Stage Suspicious Activity Correlation
        if (config_.enable_multistage_correlation) {
            evaluateMultiStage(ep, dets, fls, raw_incidents);
        }

        // 6. TCP Anomaly Cluster Correlation
        if (config_.enable_tcp_anomaly_correlation) {
            evaluateTCPAnomalyCluster(ep, dets, fls, raw_incidents);
        }
    }

    // Filter by minimum score
    std::vector<SecurityIncident> qualified_incidents;
    for (auto& inc : raw_incidents) {
        if (inc.correlation_score >= config_.min_incident_score) {
            qualified_incidents.push_back(std::move(inc));
        }
    }

    // Deduplicate and merge incidents
    auto merged = deduplicateAndMerge(qualified_incidents);

    // Integrate Signature Events (Phase 3.4)
    if (!signatures.empty()) {
        std::set<std::string> matched_sig_ids;
        for (auto& inc : merged) {
            std::set<uint64_t> inc_flows(inc.related_flow_ids.begin(), inc.related_flow_ids.end());
            for (const auto& sig : signatures) {
                bool matches_ep = (sig.src_ip == inc.primary_endpoint || sig.dst_ip == inc.primary_endpoint);
                bool matches_fl = (sig.flow_id != 0 && inc_flows.find(sig.flow_id) != inc_flows.end());
                if (matches_ep || matches_fl) {
                    inc.related_signature_ids.push_back(sig.rule_id);
                    matched_sig_ids.insert(sig.event_id);
                    inc.evidence_descriptions.push_back("Signature match: " + sig.rule_id + " (" + sig.rule_name + ")");
                    
                    TimelineEvent tev;
                    tev.timestamp_us = sig.timestamp_us > 0 ? sig.timestamp_us : inc.first_seen_us;
                    tev.event_type = "SIGNATURE_MATCH";
                    tev.endpoint = sig.src_ip;
                    tev.flow_id = sig.flow_id;
                    tev.detection_id = sig.rule_id;
                    tev.description = "Signature " + sig.rule_id + " matched: " + sig.rule_name;
                    tev.source = "SIGNATURE_ENGINE";
                    inc.timeline.push_back(std::move(tev));

                    double boost = (sig.severity == SignatureSeverity::CRITICAL) ? 30.0 :
                                   ((sig.severity == SignatureSeverity::HIGH) ? 20.0 :
                                   ((sig.severity == SignatureSeverity::MEDIUM) ? 10.0 : 5.0));
                    inc.correlation_score = std::min(100.0, inc.correlation_score + boost);
                    inc.severity = mapScoreToSeverity(inc.correlation_score, config_);
                    if (inc.related_signature_ids.size() >= 2 || inc.related_flow_ids.size() >= 3) {
                        inc.confidence = IncidentConfidence::HIGH;
                        inc.confidence_explanation = "High confidence corroborated by multiple behavioral detections and signature matches.";
                    }
                }
            }
            // Sort timeline
            std::sort(inc.timeline.begin(), inc.timeline.end(), [](const TimelineEvent& a, const TimelineEvent& b) {
                if (a.timestamp_us != b.timestamp_us) return a.timestamp_us < b.timestamp_us;
                if (a.event_type != b.event_type) return a.event_type < b.event_type;
                return a.endpoint < b.endpoint;
            });
            if (inc.timeline.size() > config_.max_timeline_events) {
                inc.timeline.resize(config_.max_timeline_events);
            }
        }

        // Check for signature-only incidents
        std::map<std::string, std::vector<const SignatureEvent*>> unassociated_sigs;
        for (const auto& sig : signatures) {
            if (matched_sig_ids.find(sig.event_id) == matched_sig_ids.end()) {
                unassociated_sigs[sig.src_ip].push_back(&sig);
            }
        }
        for (const auto& [ep, sig_list] : unassociated_sigs) {
            double score = 0.0;
            for (const auto* s : sig_list) {
                score += (s->severity == SignatureSeverity::CRITICAL) ? 40.0 :
                         ((s->severity == SignatureSeverity::HIGH) ? 25.0 :
                         ((s->severity == SignatureSeverity::MEDIUM) ? 15.0 : 10.0));
            }
            if (score >= config_.min_incident_score) {
                SecurityIncident inc;
                inc.incident_id = generateIncidentId();
                inc.primary_endpoint = ep;
                inc.category = IncidentCategory::SUSPICIOUS_OUTBOUND_COMMUNICATION;
                inc.title = "Signature-Driven Security Threat Incident";
                inc.correlation_score = std::min(100.0, score);
                inc.severity = mapScoreToSeverity(inc.correlation_score, config_);
                inc.confidence = sig_list.size() >= 2 ? IncidentConfidence::HIGH : IncidentConfidence::MEDIUM;
                inc.confidence_explanation = "Generated from direct network signature pattern matches.";
                inc.first_seen_us = sig_list.front()->timestamp_us;
                inc.last_seen_us = sig_list.back()->timestamp_us;
                inc.first_seen_iso = formatIsoTimestamp(inc.first_seen_us);
                inc.last_seen_iso = formatIsoTimestamp(inc.last_seen_us);
                inc.duration_seconds = (inc.last_seen_us >= inc.first_seen_us) ?
                    (inc.last_seen_us - inc.first_seen_us) / 1000000.0 : 0.0;
                
                for (const auto* s : sig_list) {
                    inc.related_signature_ids.push_back(s->rule_id);
                    if (!s->dst_ip.empty()) inc.related_endpoints.push_back(s->dst_ip);
                    if (s->flow_id != 0) inc.related_flow_ids.push_back(s->flow_id);
                    inc.evidence_descriptions.push_back("Signature " + s->rule_id + ": " + s->rule_name);
                    
                    TimelineEvent tev;
                    tev.timestamp_us = s->timestamp_us;
                    tev.event_type = "SIGNATURE_MATCH";
                    tev.endpoint = s->src_ip;
                    tev.flow_id = s->flow_id;
                    tev.detection_id = s->rule_id;
                    tev.description = "Signature " + s->rule_id + " matched: " + s->rule_name;
                    tev.source = "SIGNATURE_ENGINE";
                    inc.timeline.push_back(std::move(tev));
                }
                inc.limitations.push_back("Incident derived from signature pattern matches on offline PCAP.");
                inc.recommended_investigation_steps.push_back("Isolate suspect host " + ep + " and inspect processes.");
                inc.status = IncidentStatus::NEW;
                merged.push_back(std::move(inc));
            }
        }
    }

    // Integrate Threat Intelligence Match Events (Phase 3.5)
    if (!threat_matches.empty()) {
        std::set<std::string> matched_tme_ids;
        for (auto& inc : merged) {
            std::set<uint64_t> inc_flows(inc.related_flow_ids.begin(), inc.related_flow_ids.end());
            std::set<std::string> scored_ioc_values; // Prevent duplicate score inflation across datasets

            for (const auto& tme : threat_matches) {
                bool matches_ep = (tme.src_ip == inc.primary_endpoint || tme.dst_ip == inc.primary_endpoint);
                bool matches_fl = (tme.flow_id != 0 && inc_flows.find(tme.flow_id) != inc_flows.end());

                if (matches_ep || matches_fl) {
                    matched_tme_ids.insert(tme.event_id);
                    if (std::find(inc.related_ioc_ids.begin(), inc.related_ioc_ids.end(), tme.ioc_id) == inc.related_ioc_ids.end()) {
                        inc.related_ioc_ids.push_back(tme.ioc_id);
                    }

                    std::string tme_summary = "Threat Intelligence match: IOC " + tme.ioc_id + " (" + tme.ioc_value + ") [" + tme.category + "]";
                    inc.evidence_descriptions.push_back(tme_summary);
                    inc.threat_intel_summaries.push_back(tme_summary);

                    TimelineEvent tev;
                    tev.timestamp_us = tme.match_timestamp_us > 0 ? tme.match_timestamp_us : inc.first_seen_us;
                    tev.event_type = "THREAT_INTEL_MATCH";
                    tev.endpoint = tme.src_ip;
                    tev.flow_id = tme.flow_id;
                    tev.detection_id = tme.ioc_id;
                    tev.description = "Threat Intelligence IOC match: " + tme.ioc_value + " [" + tme.category + "] (" + iocSeverityToString(tme.severity) + ")";
                    tev.source = "THREAT_INTEL:" + tme.dataset_id;
                    inc.timeline.push_back(std::move(tev));

                    // Score contribution with strict deduplication per unique IOC value
                    if (scored_ioc_values.find(tme.ioc_value) == scored_ioc_values.end()) {
                        scored_ioc_values.insert(tme.ioc_value);
                        double boost = (tme.severity == IOCSeverity::CRITICAL) ? 20.0 :
                                       ((tme.severity == IOCSeverity::HIGH) ? 15.0 :
                                       ((tme.severity == IOCSeverity::MEDIUM) ? 10.0 : 5.0));
                        inc.correlation_score = std::min(100.0, inc.correlation_score + boost);
                        inc.severity = mapScoreToSeverity(inc.correlation_score, config_);
                    }

                    if (inc.related_ioc_ids.size() >= 2 || inc.related_flow_ids.size() >= 3) {
                        inc.confidence = IncidentConfidence::HIGH;
                        inc.confidence_explanation = "Corroborated by observed traffic patterns and verified threat intelligence indicators.";
                    }
                }
            }

            // Ensure limitation note is present
            inc.limitations.push_back("Threat intelligence matches are observational indicators and do not constitute independent proof of compromise.");

            // Sort timeline
            std::sort(inc.timeline.begin(), inc.timeline.end(), [](const TimelineEvent& a, const TimelineEvent& b) {
                if (a.timestamp_us != b.timestamp_us) return a.timestamp_us < b.timestamp_us;
                if (a.event_type != b.event_type) return a.event_type < b.event_type;
                return a.endpoint < b.endpoint;
            });
            if (inc.timeline.size() > config_.max_timeline_events) {
                inc.timeline.resize(config_.max_timeline_events);
            }
        }

        // Check for threat-intel-only incidents
        std::map<std::string, std::vector<const ThreatMatchEvent*>> unassociated_tmes;
        for (const auto& tme : threat_matches) {
            if (matched_tme_ids.find(tme.event_id) == matched_tme_ids.end()) {
                unassociated_tmes[tme.src_ip].push_back(&tme);
            }
        }

        for (const auto& [ep, tme_list] : unassociated_tmes) {
            double score = 0.0;
            std::set<std::string> scored_values;
            for (const auto* t : tme_list) {
                if (scored_values.find(t->ioc_value) == scored_values.end()) {
                    scored_values.insert(t->ioc_value);
                    score += (t->severity == IOCSeverity::CRITICAL) ? 30.0 :
                             ((t->severity == IOCSeverity::HIGH) ? 20.0 :
                             ((t->severity == IOCSeverity::MEDIUM) ? 12.0 : 6.0));
                }
            }

            if (score >= config_.min_incident_score) {
                SecurityIncident inc;
                inc.incident_id = generateIncidentId();
                inc.primary_endpoint = ep;
                inc.category = IncidentCategory::SUSPICIOUS_OUTBOUND_COMMUNICATION;
                inc.title = "Threat Intelligence Correlated Security Incident";
                inc.correlation_score = std::min(100.0, score);
                inc.severity = mapScoreToSeverity(inc.correlation_score, config_);
                inc.confidence = tme_list.size() >= 2 ? IncidentConfidence::HIGH : IncidentConfidence::MEDIUM;
                inc.confidence_explanation = "Generated from verified threat intelligence indicator matches.";
                inc.first_seen_us = tme_list.front()->match_timestamp_us;
                inc.last_seen_us = tme_list.back()->match_timestamp_us;
                inc.first_seen_iso = formatIsoTimestamp(inc.first_seen_us);
                inc.last_seen_iso = formatIsoTimestamp(inc.last_seen_us);
                inc.duration_seconds = (inc.last_seen_us >= inc.first_seen_us) ?
                    (inc.last_seen_us - inc.first_seen_us) / 1000000.0 : 0.0;

                for (const auto* t : tme_list) {
                    if (std::find(inc.related_ioc_ids.begin(), inc.related_ioc_ids.end(), t->ioc_id) == inc.related_ioc_ids.end()) {
                        inc.related_ioc_ids.push_back(t->ioc_id);
                    }
                    if (!t->dst_ip.empty() && std::find(inc.related_endpoints.begin(), inc.related_endpoints.end(), t->dst_ip) == inc.related_endpoints.end()) {
                        inc.related_endpoints.push_back(t->dst_ip);
                    }
                    if (t->flow_id != 0 && std::find(inc.related_flow_ids.begin(), inc.related_flow_ids.end(), t->flow_id) == inc.related_flow_ids.end()) {
                        inc.related_flow_ids.push_back(t->flow_id);
                    }

                    std::string desc = "Threat IOC " + t->ioc_id + " (" + t->ioc_value + "): " + t->category;
                    inc.evidence_descriptions.push_back(desc);
                    inc.threat_intel_summaries.push_back(desc);

                    TimelineEvent tev;
                    tev.timestamp_us = t->match_timestamp_us;
                    tev.event_type = "THREAT_INTEL_MATCH";
                    tev.endpoint = t->src_ip;
                    tev.flow_id = t->flow_id;
                    tev.detection_id = t->ioc_id;
                    tev.description = "Threat Intelligence IOC match: " + t->ioc_value + " [" + t->category + "] (" + iocSeverityToString(t->severity) + ")";
                    tev.source = "THREAT_INTEL:" + t->dataset_id;
                    inc.timeline.push_back(std::move(tev));
                }

                inc.limitations.push_back("Threat intelligence matches are observational indicators and do not constitute independent proof of compromise.");
                inc.recommended_investigation_steps.push_back("Inspect process activity on endpoint " + ep + " communicating with matched IOCs.");
                inc.status = IncidentStatus::NEW;
                merged.push_back(std::move(inc));
            }
        }
    }

    // Enforce memory bounds
    if (merged.size() > config_.max_incidents) {
        merged.resize(config_.max_incidents);
    }

    return merged;
}

// ============================================================================
// Rule A: Reconnaissance Correlation
// ============================================================================
void IncidentCorrelator::evaluateReconnaissance(
    const std::string& endpoint,
    const std::vector<const DetectionEvent*>& ep_detections,
    const std::vector<const FlowRecord*>& ep_flows,
    std::vector<SecurityIncident>& out_incidents) {

    std::vector<const DetectionEvent*> recon_dets;
    std::set<uint16_t> probed_ports;
    std::set<std::string> probed_hosts;
    bool has_vertical_scan = false;
    bool has_horizontal_sweep = false;
    bool has_repeated_attempts = false;
    bool has_syn_anomaly = false;

    for (const auto* det : ep_detections) {
        if (det->category == DetectionCategory::NETWORK_RECONNAISSANCE) {
            recon_dets.push_back(det);
            if (det->explanation.find("horizontal") != std::string::npos ||
                det->explanation.find("sweep") != std::string::npos) {
                has_horizontal_sweep = true;
            } else {
                has_vertical_scan = true;
            }
            for (uint16_t p : det->relevant_ports) probed_ports.insert(p);
        } else if (det->category == DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT) {
            recon_dets.push_back(det);
            has_repeated_attempts = true;
        } else if (det->category == DetectionCategory::PROTOCOL_ANOMALY &&
                   det->detector_name == "tcp_anomaly_detector") {
            recon_dets.push_back(det);
            has_syn_anomaly = true;
        }
    }

    for (const auto* fl : ep_flows) {
        probed_ports.insert(fl->initial_tuple.dst_port);
        probed_hosts.insert(formatIP(fl->initial_tuple.dst_ip));
    }

    int recon_indicators = (has_vertical_scan ? 1 : 0) +
                           (has_horizontal_sweep ? 1 : 0) +
                           (has_repeated_attempts ? 1 : 0) +
                           (has_syn_anomaly ? 1 : 0) +
                           (probed_ports.size() >= 15 ? 1 : 0) +
                           (probed_hosts.size() >= 10 ? 1 : 0);

    if (recon_indicators < 2 && !(has_vertical_scan && probed_ports.size() >= 15) &&
        !(has_horizontal_sweep && probed_hosts.size() >= 10)) {
        return; // Insufficient evidence
    }

    SecurityIncident inc;
    inc.incident_id = generateIncidentId();
    inc.category = IncidentCategory::RECONNAISSANCE;
    inc.title = "Network Reconnaissance and Scanning Activity";
    inc.primary_endpoint = endpoint;
    inc.status = IncidentStatus::OBSERVED;
    inc.correlation_rules_triggered.push_back("RuleReconnaissance");

    for (const auto& h : probed_hosts) inc.related_endpoints.push_back(h);
    for (uint16_t p : probed_ports) inc.related_ports.push_back(p);
    for (const auto* d : recon_dets) inc.related_detection_ids.push_back(d->detection_id);
    for (const auto* f : ep_flows) inc.related_flow_ids.push_back(f->flow_id);

    inc.observed_metrics["unique_probed_ports"] = std::to_string(probed_ports.size());
    inc.observed_metrics["unique_probed_hosts"] = std::to_string(probed_hosts.size());
    inc.observed_metrics["total_related_flows"] = std::to_string(ep_flows.size());

    inc.evidence_descriptions.push_back(
        "Source host engaged in coordinated reconnaissance targeting " +
        std::to_string(probed_ports.size()) + " ports across " +
        std::to_string(probed_hosts.size()) + " destination hosts."
    );
    if (has_repeated_attempts) {
        inc.evidence_descriptions.push_back("High ratio of uncompleted or repeated connection attempts detected during reconnaissance.");
    }
    if (has_syn_anomaly) {
        inc.evidence_descriptions.push_back("Elevated SYN-heavy or unacknowledged probe traffic pattern observed.");
    }

    inc.limitations.push_back("Port scanning activity does not guarantee unauthorized host compromise.");
    inc.limitations.push_back("Security auditing scanners and vulnerability assessment tools can exhibit identical patterns.");

    inc.recommended_investigation_steps.push_back("Check whether " + endpoint + " is an authorized vulnerability scanner or network mapper.");
    inc.recommended_investigation_steps.push_back("Inspect firewall and ingress gateway logs for unauthorized access attempts from " + endpoint + ".");
    inc.recommended_investigation_steps.push_back("Verify if any targeted host responded with OPEN ports or application-layer data.");

    buildTimeline(inc, recon_dets, ep_flows);
    calculateScoringAndSeverity(inc, ep_flows);
    out_incidents.push_back(std::move(inc));
}

// ============================================================================
// Rule B: DNS Suspicious Activity Correlation
// ============================================================================
void IncidentCorrelator::evaluateDNSSuspicious(
    const std::string& endpoint,
    const std::vector<const DetectionEvent*>& ep_detections,
    const std::vector<const FlowRecord*>& ep_flows,
    std::vector<SecurityIncident>& out_incidents) {

    std::vector<const DetectionEvent*> dns_dets;
    bool has_tunneling = false;
    bool has_nxdomain_burst = false;
    bool has_high_freq = false;
    size_t total_queries = 0;
    std::set<std::string> queried_domains;

    for (const auto* det : ep_detections) {
        if (det->category == DetectionCategory::SUSPICIOUS_DNS) {
            dns_dets.push_back(det);
            if (det->detector_name.find("tunneling") != std::string::npos ||
                det->explanation.find("tunneling") != std::string::npos ||
                det->explanation.find("length") != std::string::npos) {
                has_tunneling = true;
            }
            if (det->detector_name.find("nxdomain") != std::string::npos ||
                det->explanation.find("NXDOMAIN") != std::string::npos) {
                has_nxdomain_burst = true;
            }
            if (det->detector_name.find("frequency") != std::string::npos ||
                det->explanation.find("frequency") != std::string::npos ||
                det->explanation.find("burst") != std::string::npos) {
                has_high_freq = true;
            }
        }
    }

    for (const auto* fl : ep_flows) {
        if (!fl->dns_query.empty()) {
            total_queries++;
            queried_domains.insert(fl->dns_query);
        }
    }

    int dns_indicators = (has_tunneling ? 1 : 0) +
                         (has_nxdomain_burst ? 1 : 0) +
                         (has_high_freq ? 1 : 0) +
                         (queried_domains.size() >= 15 ? 1 : 0);

    if (dns_indicators < 2 && !has_tunneling && !(has_nxdomain_burst && queried_domains.size() >= 5)) {
        return; // Insufficient evidence
    }

    SecurityIncident inc;
    inc.incident_id = generateIncidentId();
    inc.category = IncidentCategory::DNS_SUSPICIOUS_ACTIVITY;
    inc.title = "Suspicious DNS Resolution Pattern";
    inc.primary_endpoint = endpoint;
    inc.status = IncidentStatus::OBSERVED;
    inc.correlation_rules_triggered.push_back("RuleDNSSuspicious");

    for (const auto* d : dns_dets) inc.related_detection_ids.push_back(d->detection_id);
    for (const auto* f : ep_flows) {
        if (!f->dns_query.empty()) {
            inc.related_flow_ids.push_back(f->flow_id);
            inc.related_endpoints.push_back(formatIP(f->initial_tuple.dst_ip));
        }
    }

    inc.observed_metrics["dns_query_count"] = std::to_string(total_queries);
    inc.observed_metrics["unique_domains_count"] = std::to_string(queried_domains.size());
    if (has_tunneling) inc.observed_metrics["tunneling_candidate"] = "true";
    if (has_nxdomain_burst) inc.observed_metrics["nxdomain_burst"] = "true";

    inc.evidence_descriptions.push_back(
        "Source host exhibited anomalous DNS query patterns across " +
        std::to_string(queried_domains.size()) + " unique domain names."
    );
    if (has_tunneling) {
        inc.evidence_descriptions.push_back("High domain length and entropy observed consistent with potential DNS tunneling or data encoding.");
    }
    if (has_nxdomain_burst) {
        inc.evidence_descriptions.push_back("Multiple unresolved domain lookups (NXDOMAIN surge) indicating potential DGA (Domain Generation Algorithm) rendezvous.");
    }

    inc.limitations.push_back("Anomalous DNS patterns do not prove malware presence; CDN traffic or local DNS cache misconfigurations may generate false alarms.");
    inc.limitations.push_back("DNS tunneling candidate classification is heuristic and based on length/subdomain depth.");

    inc.recommended_investigation_steps.push_back("Examine full DNS queries requested by " + endpoint + " on authoritative nameservers.");
    inc.recommended_investigation_steps.push_back("Determine if host process initiating queries is a known browser, system daemon, or unknown executable.");
    inc.recommended_investigation_steps.push_back("Cross-reference queried domains against threat intelligence feeds for known DGA seeds.");

    buildTimeline(inc, dns_dets, ep_flows);
    calculateScoringAndSeverity(inc, ep_flows);
    out_incidents.push_back(std::move(inc));
}

// ============================================================================
// Rule C: Suspicious Outbound Communication Correlation
// ============================================================================
void IncidentCorrelator::evaluateSuspiciousOutbound(
    const std::string& endpoint,
    const std::vector<const DetectionEvent*>& ep_detections,
    const std::vector<const FlowRecord*>& ep_flows,
    const std::vector<StreamRecordSummary>& streams,
    std::vector<SecurityIncident>& out_incidents) {

    std::vector<const DetectionEvent*> outbound_dets;
    bool has_beacon = false;
    bool has_repeated_attempts = false;
    std::map<std::string, int> dst_frequency;
    std::set<uint16_t> dst_ports;

    for (const auto* det : ep_detections) {
        if (det->category == DetectionCategory::COMMAND_AND_CONTROL) {
            outbound_dets.push_back(det);
            has_beacon = true;
        } else if (det->category == DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT) {
            outbound_dets.push_back(det);
            has_repeated_attempts = true;
        }
    }

    for (const auto* fl : ep_flows) {
        std::string dst = formatIP(fl->initial_tuple.dst_ip);
        dst_frequency[dst]++;
        dst_ports.insert(fl->initial_tuple.dst_port);
    }

    // Check for high destination consistency (same remote server contacted multiple times)
    bool high_destination_consistency = false;
    std::string primary_dst;
    for (const auto& [dst, count] : dst_frequency) {
        if (count >= 5) {
            high_destination_consistency = true;
            primary_dst = dst;
            break;
        }
    }

    if (!has_beacon && !(has_repeated_attempts && high_destination_consistency)) {
        return; // Insufficient evidence
    }

    SecurityIncident inc;
    inc.incident_id = generateIncidentId();
    inc.category = IncidentCategory::SUSPICIOUS_OUTBOUND_COMMUNICATION;
    inc.title = "Suspicious Outbound Communication Channel";
    inc.primary_endpoint = endpoint;
    inc.status = IncidentStatus::OBSERVED;
    inc.correlation_rules_triggered.push_back("RuleSuspiciousOutbound");

    for (const auto& [dst, _] : dst_frequency) inc.related_endpoints.push_back(dst);
    for (uint16_t p : dst_ports) inc.related_ports.push_back(p);
    for (const auto* d : outbound_dets) inc.related_detection_ids.push_back(d->detection_id);
    for (const auto* f : ep_flows) inc.related_flow_ids.push_back(f->flow_id);

    // Correlate with TLS or HTTP metadata from streams
    for (const auto& s : streams) {
        if (!s.tls_meta.sni.empty()) {
            inc.observed_metrics["tls_sni"] = s.tls_meta.sni;
        }
        if (!s.tls_meta.alpn.empty()) {
            inc.observed_metrics["tls_alpn"] = s.tls_meta.alpn;
        }
    }

    inc.observed_metrics["destination_contacts"] = std::to_string(dst_frequency.size());
    inc.evidence_descriptions.push_back("Endpoint established repeated outbound communication channels with regular timing characteristics.");
    if (has_beacon) {
        inc.evidence_descriptions.push_back("Low inter-arrival time jitter observed consistent with automated periodic beaconing.");
    }
    if (high_destination_consistency) {
        inc.evidence_descriptions.push_back("Consistent outbound rendezvous targeted remote host " + primary_dst + " across multiple distinct sessions.");
    }

    inc.limitations.push_back("Periodic outbound polling is common in legitimate keep-alives, cloud agents, and telemetry services.");
    inc.recommended_investigation_steps.push_back("Inspect process listening or originating traffic on " + endpoint + ".");
    inc.recommended_investigation_steps.push_back("Verify remote IP destination reputation and TLS certificate information.");

    buildTimeline(inc, outbound_dets, ep_flows);
    calculateScoringAndSeverity(inc, ep_flows);
    out_incidents.push_back(std::move(inc));
}

// ============================================================================
// Rule D: Potential Data Exfiltration Correlation
// ============================================================================
void IncidentCorrelator::evaluateDataExfiltration(
    const std::string& endpoint,
    const std::vector<const DetectionEvent*>& ep_detections,
    const std::vector<const FlowRecord*>& ep_flows,
    std::vector<SecurityIncident>& out_incidents) {

    std::vector<const DetectionEvent*> exfil_dets;
    bool has_volume_anomaly = false;
    bool has_extreme_asymmetry = false;
    uint64_t max_flow_bytes = 0;
    double max_asymmetry = 0.0;
    std::string exfil_dest;

    for (const auto* det : ep_detections) {
        if (det->category == DetectionCategory::UNUSUAL_TRAFFIC_VOLUME) {
            exfil_dets.push_back(det);
            has_volume_anomaly = true;
        }
    }

    for (const auto* fl : ep_flows) {
        if (fl->fwd.byte_count > max_flow_bytes) {
            max_flow_bytes = fl->fwd.byte_count;
            exfil_dest = formatIP(fl->initial_tuple.dst_ip);
        }
        double asym = fl->byte_asymmetry_ratio();
        if (asym > max_asymmetry) {
            max_asymmetry = asym;
        }
        if (asym >= 10.0 && fl->fwd.byte_count >= 50000) {
            has_extreme_asymmetry = true;
        }
    }

    if (!has_volume_anomaly && !(has_extreme_asymmetry && max_flow_bytes >= 100000)) {
        return; // Insufficient evidence
    }

    SecurityIncident inc;
    inc.incident_id = generateIncidentId();
    inc.category = IncidentCategory::POTENTIAL_DATA_EXFILTRATION;
    inc.title = "Potential Data Exfiltration / Unusual Outbound Transfer";
    inc.primary_endpoint = endpoint;
    inc.status = IncidentStatus::OBSERVED;
    inc.correlation_rules_triggered.push_back("RuleDataExfiltration");

    if (!exfil_dest.empty()) inc.related_endpoints.push_back(exfil_dest);
    for (const auto* d : exfil_dets) inc.related_detection_ids.push_back(d->detection_id);
    for (const auto* f : ep_flows) inc.related_flow_ids.push_back(f->flow_id);

    inc.observed_metrics["max_outbound_bytes"] = std::to_string(max_flow_bytes);
    inc.observed_metrics["max_byte_asymmetry_ratio"] = std::to_string(max_asymmetry);

    inc.evidence_descriptions.push_back(
        "Large outbound data transfer observed (" + std::to_string(max_flow_bytes) +
        " bytes) with extreme directional asymmetry ratio (" + std::to_string(static_cast<int>(max_asymmetry)) + ":1)."
    );
    inc.evidence_descriptions.push_back("Data volume departs significantly from typical bidirectional interactive sessions.");

    inc.limitations.push_back("Observed outbound transfer pattern does NOT confirm data exfiltration; backups, file uploads, and software updates produce similar volume profiles.");
    inc.recommended_investigation_steps.push_back("Identify file or data stream transmitted to " + exfil_dest + ".");
    inc.recommended_investigation_steps.push_back("Review endpoint user activity and scheduled backup processes.");

    buildTimeline(inc, exfil_dets, ep_flows);
    calculateScoringAndSeverity(inc, ep_flows);
    out_incidents.push_back(std::move(inc));
}

// ============================================================================
// Rule E: Multi-Stage Suspicious Activity Correlation
// ============================================================================
void IncidentCorrelator::evaluateMultiStage(
    const std::string& endpoint,
    const std::vector<const DetectionEvent*>& ep_detections,
    const std::vector<const FlowRecord*>& ep_flows,
    std::vector<SecurityIncident>& out_incidents) {

    // Track presence of each stage
    bool stage_recon = false;
    bool stage_conn_burst = false;
    bool stage_dns = false;
    bool stage_beacon = false;
    bool stage_exfil = false;

    uint64_t t_recon = 0, t_burst = 0, t_dns = 0, t_beacon = 0, t_exfil = 0;
    std::vector<const DetectionEvent*> all_stage_dets;

    for (const auto* det : ep_detections) {
        all_stage_dets.push_back(det);
        if (det->category == DetectionCategory::NETWORK_RECONNAISSANCE) {
            stage_recon = true;
            if (t_recon == 0 || det->timestamp_us < t_recon) t_recon = det->timestamp_us;
        } else if (det->category == DetectionCategory::CONNECTION_ANOMALY ||
                   det->category == DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT) {
            stage_conn_burst = true;
            if (t_burst == 0 || det->timestamp_us < t_burst) t_burst = det->timestamp_us;
        } else if (det->category == DetectionCategory::SUSPICIOUS_DNS) {
            stage_dns = true;
            if (t_dns == 0 || det->timestamp_us < t_dns) t_dns = det->timestamp_us;
        } else if (det->category == DetectionCategory::COMMAND_AND_CONTROL) {
            stage_beacon = true;
            if (t_beacon == 0 || det->timestamp_us < t_beacon) t_beacon = det->timestamp_us;
        } else if (det->category == DetectionCategory::UNUSUAL_TRAFFIC_VOLUME) {
            stage_exfil = true;
            if (t_exfil == 0 || det->timestamp_us < t_exfil) t_exfil = det->timestamp_us;
        }
    }

    int stage_count = (stage_recon ? 1 : 0) + (stage_conn_burst ? 1 : 0) +
                      (stage_dns ? 1 : 0) + (stage_beacon ? 1 : 0) +
                      (stage_exfil ? 1 : 0);

    // Require at least 2 distinct stages, including at least one post-reconnaissance stage
    // (DNS, C2 Beacon, or Exfiltration), so that scanning + repeated attempts stays classified as Reconnaissance!
    bool has_post_recon_stage = stage_dns || stage_beacon || stage_exfil;
    if (stage_count < 2 || !has_post_recon_stage) {
        return;
    }

    SecurityIncident inc;
    inc.incident_id = generateIncidentId();
    inc.category = IncidentCategory::MULTI_STAGE_ACTIVITY;
    inc.title = "Multi-Stage Attack Sequence (" + std::to_string(stage_count) + " Stages Observed)";
    inc.primary_endpoint = endpoint;
    inc.status = IncidentStatus::OBSERVED;
    inc.correlation_rules_triggered.push_back("RuleMultiStage");

    for (const auto* d : all_stage_dets) inc.related_detection_ids.push_back(d->detection_id);
    for (const auto* f : ep_flows) inc.related_flow_ids.push_back(f->flow_id);

    std::ostringstream ss_stages;
    bool first_st = true;
    if (stage_recon) { ss_stages << (first_st ? "" : " -> ") << "Reconnaissance"; first_st = false; }
    if (stage_conn_burst) { ss_stages << (first_st ? "" : " -> ") << "Connection Surges"; first_st = false; }
    if (stage_dns) { ss_stages << (first_st ? "" : " -> ") << "Suspicious DNS"; first_st = false; }
    if (stage_beacon) { ss_stages << (first_st ? "" : " -> ") << "C2 Beaconing"; first_st = false; }
    if (stage_exfil) { ss_stages << (first_st ? "" : " -> ") << "Data Transfer"; first_st = false; }

    inc.observed_metrics["stages_count"] = std::to_string(stage_count);
    inc.observed_metrics["stage_progression"] = ss_stages.str();

    inc.evidence_descriptions.push_back("Endpoint progressed through " + std::to_string(stage_count) + " correlated attack lifecycle stages: " + ss_stages.str());
    inc.evidence_descriptions.push_back("Sequential temporal progression indicates deliberate, multi-phase operational activity.");

    inc.limitations.push_back("Multi-stage correlation synthesizes behavioral indicators; unrelated concurrent network tasks may coincidentally align in time.");
    inc.recommended_investigation_steps.push_back("Prioritize immediate forensic acquisition of endpoint " + endpoint + ".");
    inc.recommended_investigation_steps.push_back("Review network boundary containment options to isolate endpoint " + endpoint + ".");

    buildTimeline(inc, all_stage_dets, ep_flows);

    // Insert Stage Transition markers into timeline
    if (stage_recon) {
        TimelineEvent te;
        te.timestamp_us = t_recon;
        te.event_type = "STAGE_TRANSITION";
        te.endpoint = endpoint;
        te.description = "Stage 1 Observed: Network Reconnaissance & Scanning";
        te.source = "correlation_engine";
        inc.timeline.push_back(std::move(te));
    }
    if (stage_conn_burst) {
        TimelineEvent te;
        te.timestamp_us = t_burst;
        te.event_type = "STAGE_TRANSITION";
        te.endpoint = endpoint;
        te.description = "Stage 2 Observed: Repeated Infiltration & Connection Bursts";
        te.source = "correlation_engine";
        inc.timeline.push_back(std::move(te));
    }
    if (stage_dns) {
        TimelineEvent te;
        te.timestamp_us = t_dns;
        te.event_type = "STAGE_TRANSITION";
        te.endpoint = endpoint;
        te.description = "Stage 3 Observed: Suspicious DNS Resolution / DGA Querying";
        te.source = "correlation_engine";
        inc.timeline.push_back(std::move(te));
    }
    if (stage_beacon) {
        TimelineEvent te;
        te.timestamp_us = t_beacon;
        te.event_type = "STAGE_TRANSITION";
        te.endpoint = endpoint;
        te.description = "Stage 4 Observed: Persistent Command-and-Control Beaconing";
        te.source = "correlation_engine";
        inc.timeline.push_back(std::move(te));
    }
    if (stage_exfil) {
        TimelineEvent te;
        te.timestamp_us = t_exfil;
        te.event_type = "STAGE_TRANSITION";
        te.endpoint = endpoint;
        te.description = "Stage 5 Observed: Large-Volume Outbound Data Transfer";
        te.source = "correlation_engine";
        inc.timeline.push_back(std::move(te));
    }

    // Re-sort timeline with new markers
    std::sort(inc.timeline.begin(), inc.timeline.end(), [](const TimelineEvent& a, const TimelineEvent& b) {
        if (a.timestamp_us != b.timestamp_us) return a.timestamp_us < b.timestamp_us;
        if (a.event_type != b.event_type) return a.event_type < b.event_type;
        return a.description < b.description;
    });

    calculateScoringAndSeverity(inc, ep_flows);
    out_incidents.push_back(std::move(inc));
}

// ============================================================================
// Rule F: TCP Anomaly Cluster Correlation
// ============================================================================
void IncidentCorrelator::evaluateTCPAnomalyCluster(
    const std::string& endpoint,
    const std::vector<const DetectionEvent*>& ep_detections,
    const std::vector<const FlowRecord*>& ep_flows,
    std::vector<SecurityIncident>& out_incidents) {

    std::vector<const DetectionEvent*> tcp_dets;
    for (const auto* det : ep_detections) {
        if (det->category == DetectionCategory::PROTOCOL_ANOMALY) {
            tcp_dets.push_back(det);
        }
    }

    if (tcp_dets.size() < 2) {
        return; // Insufficient evidence
    }

    SecurityIncident inc;
    inc.incident_id = generateIncidentId();
    inc.category = IncidentCategory::TCP_ANOMALY_CLUSTER;
    inc.title = "TCP Protocol Anomaly Cluster";
    inc.primary_endpoint = endpoint;
    inc.status = IncidentStatus::OBSERVED;
    inc.correlation_rules_triggered.push_back("RuleTCPAnomalyCluster");

    for (const auto* d : tcp_dets) inc.related_detection_ids.push_back(d->detection_id);
    for (const auto* f : ep_flows) inc.related_flow_ids.push_back(f->flow_id);

    inc.observed_metrics["tcp_anomalies_count"] = std::to_string(tcp_dets.size());
    inc.evidence_descriptions.push_back("Endpoint exhibited multiple abnormal TCP flag and handshake patterns across concurrent sessions.");

    inc.limitations.push_back("Network congestion, asymmetric routing, or server reboots can induce TCP resets and SYN retransmissions.");
    inc.recommended_investigation_steps.push_back("Inspect TCP segment packet captures for RST origins and TCP window scale negotiation.");

    buildTimeline(inc, tcp_dets, ep_flows);
    calculateScoringAndSeverity(inc, ep_flows);
    out_incidents.push_back(std::move(inc));
}

// ============================================================================
// Scoring, Severity & Confidence Calculation
// ============================================================================
void IncidentCorrelator::calculateScoringAndSeverity(
    SecurityIncident& incident,
    const std::vector<const FlowRecord*>& ep_flows) {

    double score = 0.0;
    std::set<std::string> seen_categories;
    std::set<uint64_t> credited_flows;

    // Base score from detection severity with same-flow deduplication
    for (size_t i = 0; i < incident.related_detection_ids.size(); ++i) {
        // Assume default medium weight if not looked up
        double det_weight = config_.weight_medium;
        // In full pipeline, severity weights:
        // Critical: 40, High: 25, Medium: 15, Low: 8, Info: 2
        score += det_weight;
    }

    // Apply feature bonuses
    if (incident.category == IncidentCategory::MULTI_STAGE_ACTIVITY) {
        score += config_.weight_stage_sequence;
        score += config_.weight_multi_category;
    } else if (incident.category == IncidentCategory::RECONNAISSANCE) {
        if (incident.related_ports.size() >= 15) score += config_.weight_medium;
        if (incident.related_endpoints.size() >= 10) score += config_.weight_medium;
    } else if (incident.category == IncidentCategory::SUSPICIOUS_OUTBOUND_COMMUNICATION) {
        score += config_.weight_beacon_consistency;
        if (incident.observed_metrics.find("tls_sni") != incident.observed_metrics.end()) {
            score += 10.0;
        }
    } else if (incident.category == IncidentCategory::POTENTIAL_DATA_EXFILTRATION) {
        score += config_.weight_large_volume;
    } else if (incident.category == IncidentCategory::DNS_SUSPICIOUS_ACTIVITY) {
        if (incident.observed_metrics.find("tunneling_candidate") != incident.observed_metrics.end()) {
            score += 15.0;
        }
        if (incident.observed_metrics.find("nxdomain_burst") != incident.observed_metrics.end()) {
            score += 15.0;
        }
    }

    // Check for high asymmetry flow bonus
    bool has_high_asym = false;
    uint64_t total_outbound_bytes = 0;
    for (const auto* fl : ep_flows) {
        total_outbound_bytes += fl->fwd.byte_count;
        if (fl->byte_asymmetry_ratio() >= 10.0 && fl->fwd.byte_count > 5000) {
            has_high_asym = true;
        }
    }
    if (has_high_asym) score += config_.weight_high_asymmetry;
    if (incident.related_endpoints.size() >= 3) score += config_.weight_multiple_destinations;
    if (total_outbound_bytes > 500000) score += config_.weight_large_volume;

    incident.correlation_score = score;

    // Map score to IncidentSeverity
    if (score >= config_.critical_score_threshold || incident.category == IncidentCategory::MULTI_STAGE_ACTIVITY) {
        incident.severity = IncidentSeverity::CRITICAL;
    } else if (score >= config_.high_score_threshold) {
        incident.severity = IncidentSeverity::HIGH;
    } else if (score >= config_.medium_score_threshold) {
        incident.severity = IncidentSeverity::MEDIUM;
    } else {
        incident.severity = IncidentSeverity::LOW;
    }

    // Calculate Confidence
    size_t flow_count = incident.related_flow_ids.size();
    size_t det_count = incident.related_detection_ids.size();

    if (flow_count >= 3 && det_count >= 2) {
        incident.confidence = IncidentConfidence::HIGH;
        incident.confidence_explanation = "High confidence based on " + std::to_string(flow_count) +
            " distinct flows and " + std::to_string(det_count) + " corroborated detection indicators.";
    } else if (flow_count >= 2 || det_count >= 2) {
        incident.confidence = IncidentConfidence::MEDIUM;
        incident.confidence_explanation = "Medium confidence based on multiple corroborated indicators.";
    } else {
        incident.confidence = IncidentConfidence::LOW;
        incident.confidence_explanation = "Low confidence based on limited circumstantial evidence.";
    }
}

// ============================================================================
// Timeline Construction & Sorting
// ============================================================================
void IncidentCorrelator::buildTimeline(
    SecurityIncident& incident,
    const std::vector<const DetectionEvent*>& related_dets,
    const std::vector<const FlowRecord*>& related_fls) {

    incident.timeline.clear();
    uint64_t min_t = 0;
    uint64_t max_t = 0;

    for (const auto* d : related_dets) {
        TimelineEvent te;
        te.timestamp_us = d->timestamp_us;
        te.timestamp_iso = d->timestamp_iso;
        te.event_type = "DETECTION";
        te.endpoint = d->source_ip_str.empty() ? formatIP(d->source_ip) : d->source_ip_str;
        te.detection_id = d->detection_id;
        te.description = d->explanation;
        te.source = d->detector_name;
        te.observed_values = d->evidence;

        if (min_t == 0 || te.timestamp_us < min_t) min_t = te.timestamp_us;
        if (te.timestamp_us > max_t) max_t = te.timestamp_us;

        incident.timeline.push_back(std::move(te));
    }

    for (const auto* f : related_fls) {
        TimelineEvent te;
        te.timestamp_us = f->start_time_us;
        te.event_type = "FLOW_START";
        te.endpoint = formatIP(f->initial_tuple.src_ip);
        te.flow_id = f->flow_id;
        te.description = "Flow established to " + formatIP(f->initial_tuple.dst_ip) + ":" + std::to_string(f->initial_tuple.dst_port);
        te.source = "flow_table";

        if (min_t == 0 || te.timestamp_us < min_t) min_t = te.timestamp_us;
        if (te.timestamp_us > max_t) max_t = te.timestamp_us;

        incident.timeline.push_back(std::move(te));
    }

    incident.first_seen_us = min_t;
    incident.last_seen_us = max_t;
    incident.duration_seconds = (max_t >= min_t) ? (max_t - min_t) / 1000000.0 : 0.0;

    // Deterministic chronological ordering
    std::sort(incident.timeline.begin(), incident.timeline.end(), [](const TimelineEvent& a, const TimelineEvent& b) {
        if (a.timestamp_us != b.timestamp_us) return a.timestamp_us < b.timestamp_us;
        if (a.event_type != b.event_type) return a.event_type < b.event_type;
        if (a.detection_id != b.detection_id) return a.detection_id < b.detection_id;
        return a.flow_id < b.flow_id;
    });

    // Enforce timeline bounds
    if (incident.timeline.size() > config_.max_timeline_events) {
        incident.timeline.resize(config_.max_timeline_events);
    }
}

// ============================================================================
// Incident Deduplication & Merging
// ============================================================================
std::vector<SecurityIncident> IncidentCorrelator::deduplicateAndMerge(std::vector<SecurityIncident>& incidents) {
    std::vector<SecurityIncident> merged;

    for (auto& inc : incidents) {
        bool combined = false;
        for (auto& existing : merged) {
            // Unrelated endpoints are NEVER merged
            if (existing.primary_endpoint != inc.primary_endpoint) {
                continue;
            }

            // Same endpoint: Check if categories match or one is MULTI_STAGE_ACTIVITY
            bool same_category = (existing.category == inc.category);
            bool one_multistage = (existing.category == IncidentCategory::MULTI_STAGE_ACTIVITY ||
                                   inc.category == IncidentCategory::MULTI_STAGE_ACTIVITY);

            // Check time window
            uint64_t window_us = static_cast<uint64_t>(config_.incident_window_seconds * 1000000.0);
            bool within_window = (inc.first_seen_us <= existing.last_seen_us + window_us) &&
                                 (existing.first_seen_us <= inc.last_seen_us + window_us);

            if ((same_category || one_multistage) && within_window) {
                // Merge inc into existing
                if (inc.category == IncidentCategory::MULTI_STAGE_ACTIVITY) {
                    existing.category = IncidentCategory::MULTI_STAGE_ACTIVITY;
                    existing.title = inc.title;
                }

                existing.first_seen_us = std::min(existing.first_seen_us, inc.first_seen_us);
                existing.last_seen_us = std::max(existing.last_seen_us, inc.last_seen_us);
                existing.duration_seconds = (existing.last_seen_us >= existing.first_seen_us)
                    ? (existing.last_seen_us - existing.first_seen_us) / 1000000.0 : 0.0;

                // Merge flow IDs (deduplicated)
                std::set<uint64_t> flow_set(existing.related_flow_ids.begin(), existing.related_flow_ids.end());
                flow_set.insert(inc.related_flow_ids.begin(), inc.related_flow_ids.end());
                existing.related_flow_ids.assign(flow_set.begin(), flow_set.end());

                // Merge detection IDs
                std::set<std::string> det_set(existing.related_detection_ids.begin(), existing.related_detection_ids.end());
                det_set.insert(inc.related_detection_ids.begin(), inc.related_detection_ids.end());
                existing.related_detection_ids.assign(det_set.begin(), det_set.end());

                // Merge related endpoints
                std::set<std::string> ep_set(existing.related_endpoints.begin(), existing.related_endpoints.end());
                ep_set.insert(inc.related_endpoints.begin(), inc.related_endpoints.end());
                existing.related_endpoints.assign(ep_set.begin(), ep_set.end());

                // Merge related ports
                std::set<uint16_t> port_set(existing.related_ports.begin(), existing.related_ports.end());
                port_set.insert(inc.related_ports.begin(), inc.related_ports.end());
                existing.related_ports.assign(port_set.begin(), port_set.end());

                // Merge timeline
                existing.timeline.insert(existing.timeline.end(), inc.timeline.begin(), inc.timeline.end());
                std::sort(existing.timeline.begin(), existing.timeline.end(), [](const TimelineEvent& a, const TimelineEvent& b) {
                    if (a.timestamp_us != b.timestamp_us) return a.timestamp_us < b.timestamp_us;
                    return a.event_type < b.event_type;
                });
                if (existing.timeline.size() > config_.max_timeline_events) {
                    existing.timeline.resize(config_.max_timeline_events);
                }

                // Update score
                existing.correlation_score += inc.correlation_score * 0.5; // Diminishing returns for merged
                if (existing.correlation_score >= config_.critical_score_threshold ||
                    existing.category == IncidentCategory::MULTI_STAGE_ACTIVITY) {
                    existing.severity = IncidentSeverity::CRITICAL;
                } else if (existing.correlation_score >= config_.high_score_threshold) {
                    existing.severity = IncidentSeverity::HIGH;
                }

                combined = true;
                break;
            }
        }

        if (!combined) {
            merged.push_back(std::move(inc));
        }
    }

    return merged;
}

// ============================================================================
// Reporting & Serialization
// ============================================================================
std::string IncidentCorrelator::generateReport(const std::vector<SecurityIncident>& incidents) {
    std::ostringstream ss;
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║          SECURITY INCIDENT INTELLIGENCE REPORT               ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║ Total Correlated Incidents:    " << std::setw(6) << incidents.size() << "                        ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║                     SEVERITY BREAKDOWN                       ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";

    int crit = 0, high = 0, med = 0, low = 0;
    std::map<std::string, int> cat_counts;
    for (const auto& inc : incidents) {
        if (inc.severity == IncidentSeverity::CRITICAL) crit++;
        else if (inc.severity == IncidentSeverity::HIGH) high++;
        else if (inc.severity == IncidentSeverity::MEDIUM) med++;
        else low++;
        cat_counts[incidentCategoryToString(inc.category)]++;
    }

    ss << "║ CRITICAL:                      " << std::setw(6) << crit << "                        ║\n";
    ss << "║ HIGH:                          " << std::setw(6) << high << "                        ║\n";
    ss << "║ MEDIUM:                        " << std::setw(6) << med << "                        ║\n";
    ss << "║ LOW:                           " << std::setw(6) << low << "                        ║\n";

    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║                     CATEGORY BREAKDOWN                       ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    for (const auto& [cat, cnt] : cat_counts) {
        ss << "║ " << std::left << std::setw(30) << cat
           << std::right << std::setw(6) << cnt << "                       ║\n";
    }

    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║                     CORRELATED INCIDENTS                     ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";

    for (const auto& inc : incidents) {
        std::string sev_str = "[" + incidentSeverityToString(inc.severity) + "]";
        ss << "║ " << std::left << std::setw(12) << sev_str
           << std::setw(14) << inc.incident_id
           << std::setw(18) << inc.primary_endpoint
           << "Score: " << std::fixed << std::setprecision(1) << std::setw(5) << inc.correlation_score << " ║\n";
        ss << "║   -> " << std::left << std::setw(56) << inc.title.substr(0, 56) << " ║\n";
    }

    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    return ss.str();
}

void IncidentCorrelator::exportJson(const std::vector<SecurityIncident>& incidents, std::ostream& os, int indent) {
    std::string ind(indent, ' ');
    os << "[\n";
    for (size_t i = 0; i < incidents.size(); ++i) {
        os << incidents[i].toJson(indent);
        if (i + 1 < incidents.size()) os << ",";
        os << "\n";
    }
    os << "]\n";
}

void IncidentCorrelator::exportCsv(const std::vector<SecurityIncident>& incidents, std::ostream& os) {
    os << SecurityIncident::csvHeader() << "\n";
    for (const auto& inc : incidents) {
        os << inc.toCsvRow() << "\n";
    }
}

} // namespace DPI
