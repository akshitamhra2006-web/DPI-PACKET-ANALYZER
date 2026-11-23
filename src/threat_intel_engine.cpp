#include "threat_intel_engine.h"
#include "threat_intel_validator.h"
#include <iomanip>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <set>

namespace DPI {

static inline std::string formatIP(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

ThreatIntelEngine::ThreatIntelEngine() {
    config_.enable_threat_intel = true;
}

ThreatIntelEngine::ThreatIntelEngine(const ThreatIntelConfig& config)
    : config_(config) {}

std::string ThreatIntelEngine::generateEventId() {
    std::ostringstream ss;
    ss << "TME-" << std::setw(4) << std::setfill('0') << next_event_id_++;
    return ss.str();
}

ThreatMatchEvent ThreatIntelEngine::createMatchEvent(
    const ThreatIOC* ioc,
    ThreatMatchType match_type,
    const std::string& observed_value,
    const FlowRecord& flow,
    const std::string& evidence_prefix,
    uint64_t timestamp_us
) {
    ThreatMatchEvent ev;
    ev.event_id = generateEventId();
    ev.schema_version = "1.0";
    ev.dataset_id = ioc->dataset_id;
    const auto* ds = manager_.getDataset(ioc->dataset_id);
    if (ds) {
        ev.dataset_version = ds->version;
    } else {
        ev.dataset_version = "1.0";
    }

    ev.ioc_id = ioc->ioc_id;
    ev.ioc_type = ioc->type;
    ev.ioc_value = ioc->value;
    ev.observed_value = observed_value;
    ev.match_type = match_type;
    ev.match_timestamp_us = (timestamp_us > 0) ? timestamp_us : flow.start_time_us;

    ev.src_ip = formatIP(flow.initial_tuple.src_ip);
    ev.dst_ip = formatIP(flow.initial_tuple.dst_ip);
    ev.src_port = flow.initial_tuple.src_port;
    ev.dst_port = flow.initial_tuple.dst_port;
    ev.protocol = (flow.initial_tuple.protocol == 6 ? "TCP" : (flow.initial_tuple.protocol == 17 ? "UDP" : "IP"));
    ev.direction = "FORWARD";

    ev.flow_id = flow.flow_id;
    ev.confidence = ioc->confidence;
    ev.severity = ioc->severity;
    ev.tags = ioc->tags;
    ev.category = ioc->category;

    ev.evidence = evidence_prefix + " [IOC: " + ioc->value + " (" + ioc->category + "/" +
                  iocSeverityToString(ioc->severity) + ")]";
    ev.match_explanation = "Observed traffic matched threat intelligence indicator " + ioc->ioc_id +
                           " from dataset " + ioc->dataset_id + ". Defined as " + ioc->description;

    ev.limitations.push_back("IOC match indicates endpoint association; does not verify host compromise.");
    ev.limitations.push_back("Threat intelligence datasets reflect historical observations and may suffer from indicator staleness.");

    ev.recommended_actions.push_back("Correlate with endpoint process execution and host authentication logs.");
    ev.recommended_actions.push_back("Verify whether the destination is a shared hosting or content delivery network IP.");

    return ev;
}

std::vector<ThreatMatchEvent> ThreatIntelEngine::evaluateAll(
    std::vector<FlowRecord>& flows,
    const std::vector<StreamRecordSummary>& streams,
    std::vector<DetectionEvent>* detections,
    std::vector<SignatureEvent>* signatures
) {
    std::vector<ThreatMatchEvent> events;
    if (manager_.totalIOCs() == 0) return events;

    std::set<std::tuple<uint64_t, std::string, ThreatMatchType>> seen_matches;
    std::map<uint64_t, std::vector<const ThreatMatchEvent*>> flow_to_events;

    uint64_t ref_time = config_.reference_time_us;

    for (const auto& flow : flows) {
        if (events.size() >= config_.max_matches) break;

        auto tryAdd = [&](const ThreatIOC* ioc, ThreatMatchType mt, const std::string& obs,
                          const std::string& ev_str, uint64_t ts) {
            if (events.size() >= config_.max_matches) return;
            auto key = std::make_tuple(flow.flow_id, ioc->ioc_id, mt);
            if (seen_matches.count(key)) return;
            seen_matches.insert(key);

            ThreatMatchEvent ev = createMatchEvent(ioc, mt, obs, flow, ev_str, ts);
            events.push_back(ev);
        };

        // 1. Check Source IPv4
        auto src_iocs = manager_.matchIPv4(flow.initial_tuple.src_ip, ref_time, config_.allow_expired_iocs);
        for (const auto* ioc : src_iocs) {
            ThreatMatchType mt = (ioc->type == IOCType::IPV4_CIDR) ? ThreatMatchType::CIDR_IP : ThreatMatchType::EXACT_IP;
            tryAdd(ioc, mt, formatIP(flow.initial_tuple.src_ip),
                   "Source IP matches threat intelligence indicator", flow.start_time_us);
        }

        // 2. Check Destination IPv4
        auto dst_iocs = manager_.matchIPv4(flow.initial_tuple.dst_ip, ref_time, config_.allow_expired_iocs);
        for (const auto* ioc : dst_iocs) {
            ThreatMatchType mt = (ioc->type == IOCType::IPV4_CIDR) ? ThreatMatchType::CIDR_IP : ThreatMatchType::EXACT_IP;
            tryAdd(ioc, mt, formatIP(flow.initial_tuple.dst_ip),
                   "Destination IP matches threat intelligence indicator", flow.start_time_us);
        }

        // 3. Check TLS SNI
        if (!flow.sni.empty()) {
            auto sni_iocs = manager_.matchDomain(flow.sni, ref_time, config_.allow_expired_iocs);
            for (const auto* ioc : sni_iocs) {
                tryAdd(ioc, ThreatMatchType::TLS_SNI, flow.sni,
                       "TLS SNI matches threat intelligence indicator", flow.start_time_us);
            }
        }

        // 4. Check HTTP Host & URI
        if (!flow.http_host.empty()) {
            auto host_iocs = manager_.matchDomain(flow.http_host, ref_time, config_.allow_expired_iocs);
            for (const auto* ioc : host_iocs) {
                tryAdd(ioc, ThreatMatchType::HTTP_HOST, flow.http_host,
                       "HTTP Host header matches threat intelligence indicator", flow.start_time_us);
            }

            if (!flow.http_uri.empty()) {
                auto url_iocs = manager_.matchURL(flow.http_host, flow.http_uri, ref_time, config_.allow_expired_iocs);
                for (const auto* ioc : url_iocs) {
                    tryAdd(ioc, ThreatMatchType::HTTP_URL, flow.http_host + flow.http_uri,
                           "HTTP URL matches threat intelligence indicator", flow.start_time_us);
                }
            }
        }

        // 5. Check DNS Query
        if (!flow.dns_query.empty()) {
            auto dns_iocs = manager_.matchDomain(flow.dns_query, ref_time, config_.allow_expired_iocs);
            for (const auto* ioc : dns_iocs) {
                tryAdd(ioc, ThreatMatchType::DNS_QUERY, flow.dns_query,
                       "DNS Query matches threat intelligence indicator", flow.start_time_us);
            }
        }

        // 6. Check DNS Answers
        for (const auto& ans : flow.dns_answers) {
            uint32_t ans_ip = 0;
            if (ThreatIntelValidator::isValidIPv4(ans, ans_ip)) {
                auto ans_ip_iocs = manager_.matchIPv4(ans_ip, ref_time, config_.allow_expired_iocs);
                for (const auto* ioc : ans_ip_iocs) {
                    tryAdd(ioc, ThreatMatchType::DNS_RESPONSE_IP, ans,
                           "DNS Resolved Answer IP matches threat intelligence indicator", flow.last_time_us);
                }
            } else {
                // Potential CNAME domain
                auto cname_iocs = manager_.matchDomain(ans, ref_time, config_.allow_expired_iocs);
                for (const auto* ioc : cname_iocs) {
                    tryAdd(ioc, ThreatMatchType::DNS_QUERY, ans,
                           "DNS CNAME record matches threat intelligence indicator", flow.last_time_us);
                }
            }
        }
    }

    // Build flow index for matching streams to their parent flows
    std::unordered_map<FiveTuple, const FlowRecord*, FiveTupleHash> flow_map;
    for (const auto& f : flows) {
        flow_map[f.canonical_tuple] = &f;
    }

    // Inspect Stream summaries if available for deeper protocol metadata
    for (const auto& stream : streams) {
        if (events.size() >= config_.max_matches) break;

        FiveTuple canonical = stream.tuple.toCanonical();
        const FlowRecord* matched_flow = nullptr;
        auto fit = flow_map.find(canonical);
        if (fit != flow_map.end()) {
            matched_flow = fit->second;
        }

        FlowRecord fallback_flow;
        fallback_flow.flow_id = 0;
        fallback_flow.initial_tuple = stream.tuple;
        fallback_flow.start_time_us = ref_time;

        const FlowRecord& f_ref = matched_flow ? *matched_flow : fallback_flow;
        uint64_t ts = f_ref.start_time_us;

        // HTTP Messages in stream
        for (const auto& msg : stream.http_messages) {
            if (!msg.host.empty()) {
                auto host_iocs = manager_.matchDomain(msg.host, ref_time, config_.allow_expired_iocs);
                for (const auto* ioc : host_iocs) {
                    auto key = std::make_tuple(f_ref.flow_id, ioc->ioc_id, ThreatMatchType::HTTP_HOST);
                    if (seen_matches.count(key)) continue;
                    seen_matches.insert(key);

                    ThreatMatchEvent ev = createMatchEvent(ioc, ThreatMatchType::HTTP_HOST, msg.host,
                                                           f_ref, "Stream HTTP Host matches threat intelligence", ts);
                    events.push_back(ev);
                }

                if (!msg.uri.empty()) {
                    auto url_iocs = manager_.matchURL(msg.host, msg.uri, ref_time, config_.allow_expired_iocs);
                    for (const auto* ioc : url_iocs) {
                        auto key = std::make_tuple(f_ref.flow_id, ioc->ioc_id, ThreatMatchType::HTTP_URL);
                        if (seen_matches.count(key)) continue;
                        seen_matches.insert(key);

                        ThreatMatchEvent ev = createMatchEvent(ioc, ThreatMatchType::HTTP_URL, msg.host + msg.uri,
                                                               f_ref, "Stream HTTP URL matches threat intelligence", ts);
                        events.push_back(ev);
                    }
                }
            }
        }

        // TLS SNI in stream
        if (!stream.tls_meta.sni.empty()) {
            auto sni_iocs = manager_.matchDomain(stream.tls_meta.sni, ref_time, config_.allow_expired_iocs);
            for (const auto* ioc : sni_iocs) {
                auto key = std::make_tuple(f_ref.flow_id, ioc->ioc_id, ThreatMatchType::TLS_SNI);
                if (seen_matches.count(key)) continue;
                seen_matches.insert(key);

                ThreatMatchEvent ev = createMatchEvent(ioc, ThreatMatchType::TLS_SNI, stream.tls_meta.sni,
                                                       f_ref, "Stream TLS SNI matches threat intelligence", ts);
                events.push_back(ev);
            }
        }
    }

    // Map events by flow_id for enrichment
    for (const auto& ev : events) {
        if (ev.flow_id != 0) {
            flow_to_events[ev.flow_id].push_back(&ev);
        }
    }

    // 1. Enrich Flows
    for (auto& flow : flows) {
        auto it = flow_to_events.find(flow.flow_id);
        if (it != flow_to_events.end()) {
            flow.ioc_match_count = static_cast<uint32_t>(it->second.size());
            std::set<std::string> cats;
            for (const auto* ev : it->second) {
                flow.matched_ioc_ids.push_back(ev->ioc_id);
                flow.matched_ioc_values.push_back(ev->ioc_value);
                cats.insert(ev->category);
            }
            for (const auto& c : cats) {
                flow.threat_categories.push_back(c);
            }
            flow.threat_summary = "Matched " + std::to_string(it->second.size()) + " IOCs";
        }
    }

    // 2. Enrich Behavioral Detections if provided
    if (detections) {
        for (auto& det : *detections) {
            std::vector<std::string> det_matched_iocs;
            for (uint64_t fid : det.related_flow_ids) {
                auto it = flow_to_events.find(fid);
                if (it != flow_to_events.end()) {
                    for (const auto* ev : it->second) {
                        det_matched_iocs.push_back(ev->ioc_id + " (" + ev->ioc_value + ")");
                    }
                }
            }
            if (!det_matched_iocs.empty()) {
                std::string ioc_str;
                for (size_t i = 0; i < det_matched_iocs.size(); ++i) {
                    ioc_str += det_matched_iocs[i] + (i + 1 < det_matched_iocs.size() ? ", " : "");
                }
                det.evidence["threat_intel_iocs"] = ioc_str;
                det.explanation += " [Enriched with Threat Intelligence: " + ioc_str + "]";
            }
        }
    }

    // 3. Enrich Signature Events if provided
    if (signatures) {
        for (auto& sig : *signatures) {
            auto it = flow_to_events.find(sig.flow_id);
            if (it != flow_to_events.end()) {
                std::string ioc_str;
                for (size_t i = 0; i < it->second.size(); ++i) {
                    ioc_str += it->second[i]->ioc_id + " (" + it->second[i]->ioc_value + ")" +
                               (i + 1 < it->second.size() ? ", " : "");
                }
                sig.metadata["threat_intel_iocs"] = ioc_str;
            }
        }
    }

    return events;
}

std::string ThreatIntelEngine::generateReport(const std::vector<ThreatMatchEvent>& events) const {
    std::ostringstream ss;
    ss << "\n";
    ss << "╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║          THREAT INTELLIGENCE & IOC ENRICHMENT REPORT         ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║ Total Datasets Loaded:      " << std::setw(32) << std::right << manager_.totalDatasets() << " ║\n";
    ss << "║ Active Datasets:            " << std::setw(32) << std::right << manager_.activeDatasets() << " ║\n";
    ss << "║ Total Indicators (IOCs):    " << std::setw(32) << std::right << manager_.totalIOCs() << " ║\n";
    ss << "║ Active Indicators (IOCs):   " << std::setw(32) << std::right << manager_.activeIOCs() << " ║\n";
    ss << "║ Total IOC Matches:          " << std::setw(32) << std::right << events.size() << " ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║                     SEVERITY BREAKDOWN                       ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";

    size_t crit = 0, high = 0, med = 0, low = 0, info = 0;
    for (const auto& ev : events) {
        if (ev.severity == IOCSeverity::CRITICAL) crit++;
        else if (ev.severity == IOCSeverity::HIGH) high++;
        else if (ev.severity == IOCSeverity::MEDIUM) med++;
        else if (ev.severity == IOCSeverity::LOW) low++;
        else info++;
    }

    ss << "║ CRITICAL:                   " << std::setw(32) << std::right << crit << " ║\n";
    ss << "║ HIGH:                       " << std::setw(32) << std::right << high << " ║\n";
    ss << "║ MEDIUM:                     " << std::setw(32) << std::right << med << " ║\n";
    ss << "║ LOW:                        " << std::setw(32) << std::right << low << " ║\n";
    ss << "║ INFO:                       " << std::setw(32) << std::right << info << " ║\n";

    if (!events.empty()) {
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║                   DETECTED IOC MATCH EVENTS                  ║\n";
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        for (const auto& ev : events) {
            std::string sev_str = "[" + iocSeverityToString(ev.severity) + "]";
            std::string ioc_info = ev.ioc_id + " (" + iocTypeToString(ev.ioc_type) + ")";
            std::string ep_info = ev.src_ip + " -> " + ev.dst_ip;

            ss << "║ " << std::setw(12) << std::left << sev_str << " "
               << std::setw(22) << std::left << ioc_info << " "
               << std::setw(24) << std::left << ep_info << " ║\n";

            std::string val_str = "   Observed: " + ev.observed_value + " [Cat: " + ev.category + "]";
            if (val_str.size() > 58) val_str = val_str.substr(0, 55) + "...";
            ss << "║ " << std::setw(60) << std::left << val_str << " ║\n";
        }
    }

    // Dataset Provenance Summary
    const auto& dss = manager_.getDatasets();
    if (!dss.empty()) {
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║                      DATASET PROVENANCE                      ║\n";
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        for (const auto& ds : dss) {
            std::string st = ds.enabled ? "ACTIVE" : "DISABLED";
            std::string ds_line = ds.dataset_id + " v" + ds.version + " (" + st + ", " + std::to_string(ds.iocs.size()) + " IOCs)";
            if (ds_line.size() > 58) ds_line = ds_line.substr(0, 55) + "...";
            ss << "║ " << std::setw(60) << std::left << ds_line << " ║\n";
        }
    }

    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    return ss.str();
}

void ThreatIntelEngine::exportJson(const std::vector<ThreatMatchEvent>& events, std::ostream& os, int indent) const {
    std::string ind(indent, ' ');
    os << "[\n";
    for (size_t i = 0; i < events.size(); ++i) {
        os << events[i].toJson(indent) << (i + 1 < events.size() ? ",\n" : "\n");
    }
    os << "]\n";
}

void ThreatIntelEngine::exportCsv(const std::vector<ThreatMatchEvent>& events, std::ostream& os) const {
    os << ThreatMatchEvent::csvHeader() << "\n";
    for (const auto& ev : events) {
        os << ev.toCsvRow() << "\n";
    }
}

} // namespace DPI
