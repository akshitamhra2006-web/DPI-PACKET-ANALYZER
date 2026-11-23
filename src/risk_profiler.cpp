#include "risk_profiler.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>

namespace DPI {

static inline std::string formatIPAddr(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

static inline uint32_t parseIPAddr(const std::string& ip_str) {
    uint32_t result = 0;
    int octet = 0;
    int shift = 0;
    for (char c : ip_str) {
        if (c == '.') {
            result |= (octet << shift);
            shift += 8;
            octet = 0;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
        }
    }
    result |= (octet << shift);
    return result;
}

std::string riskLevelToString(RiskLevel level) {
    switch (level) {
        case RiskLevel::CRITICAL: return "CRITICAL";
        case RiskLevel::HIGH:     return "HIGH";
        case RiskLevel::MEDIUM:   return "MEDIUM";
        case RiskLevel::LOW:      return "LOW";
        case RiskLevel::CLEAN:    return "CLEAN";
        default:                  return "CLEAN";
    }
}

RiskLevel stringToRiskLevel(const std::string& str) {
    if (str == "CRITICAL") return RiskLevel::CRITICAL;
    if (str == "HIGH")     return RiskLevel::HIGH;
    if (str == "MEDIUM")   return RiskLevel::MEDIUM;
    if (str == "LOW")      return RiskLevel::LOW;
    return RiskLevel::CLEAN;
}

std::string RiskFactor::toJson() const {
    std::ostringstream ss;
    ss << "{"
       << "\"name\":\"" << name << "\","
       << "\"weight\":" << std::fixed << std::setprecision(1) << weight << ","
       << "\"explanation\":\"" << explanation << "\","
       << "\"source_reference\":\"" << source_reference << "\""
       << "}";
    return ss.str();
}

std::string EndpointRiskProfile::toJson() const {
    std::ostringstream ss;
    ss << "{"
       << "\"ip\":\"" << ip << "\","
       << "\"is_internal\":" << (is_internal ? "true" : "false") << ","
       << "\"role\":\"" << role << "\","
       << "\"total_flows\":" << total_flows << ","
       << "\"total_packets\":" << total_packets << ","
       << "\"total_bytes\":" << total_bytes << ","
       << "\"bytes_sent\":" << bytes_sent << ","
       << "\"bytes_received\":" << bytes_received << ","
       << "\"first_seen_us\":" << first_seen_us << ","
       << "\"last_seen_us\":" << last_seen_us << ","
       << "\"risk_score\":" << std::fixed << std::setprecision(1) << risk_score << ","
       << "\"risk_level\":\"" << riskLevelToString(risk_level) << "\","
       << "\"associated_ports\":[";
    bool first = true;
    for (auto p : associated_ports) {
        if (!first) ss << ",";
        ss << p;
        first = false;
    }
    ss << "],\"protocols\":[";
    first = true;
    for (const auto& pr : protocols) {
        if (!first) ss << ",";
        ss << "\"" << pr << "\"";
        first = false;
    }
    ss << "],\"behavioral_tags\":[";
    first = true;
    for (const auto& tag : behavioral_tags) {
        if (!first) ss << ",";
        ss << "\"" << tag << "\"";
        first = false;
    }
    ss << "],\"contributing_factors\":[";
    first = true;
    for (const auto& f : contributing_factors) {
        if (!first) ss << ",";
        ss << f.toJson();
        first = false;
    }
    ss << "],\"related_detections\":[";
    first = true;
    for (const auto& d : related_detections) {
        if (!first) ss << ",";
        ss << "\"" << d << "\"";
        first = false;
    }
    ss << "],\"related_incidents\":[";
    first = true;
    for (const auto& inc : related_incidents) {
        if (!first) ss << ",";
        ss << "\"" << inc << "\"";
        first = false;
    }
    ss << "],\"related_signatures\":[";
    first = true;
    for (const auto& s : related_signatures) {
        if (!first) ss << ",";
        ss << "\"" << s << "\"";
        first = false;
    }
    ss << "],\"related_iocs\":[";
    first = true;
    for (const auto& ioc : related_iocs) {
        if (!first) ss << ",";
        ss << "\"" << ioc << "\"";
        first = false;
    }
    ss << "]}";
    return ss.str();
}

std::string FlowRiskProfile::toJson() const {
    std::ostringstream ss;
    ss << "{"
       << "\"flow_id\":" << flow_id << ","
       << "\"src_ip\":\"" << formatIPAddr(tuple.src_ip) << "\","
       << "\"dst_ip\":\"" << formatIPAddr(tuple.dst_ip) << "\","
       << "\"src_port\":" << tuple.src_port << ","
       << "\"dst_port\":" << tuple.dst_port << ","
       << "\"protocol\":\"" << protocol_str << "\","
       << "\"risk_score\":" << std::fixed << std::setprecision(1) << risk_score << ","
       << "\"risk_level\":\"" << riskLevelToString(risk_level) << "\","
       << "\"contributing_factors\":[";
    bool first = true;
    for (const auto& f : contributing_factors) {
        if (!first) ss << ",";
        ss << f.toJson();
        first = false;
    }
    ss << "]}";
    return ss.str();
}

bool RiskProfiler::isRFC1918(uint32_t ip) {
    uint8_t o1 = (ip >> 0) & 0xFF;
    uint8_t o2 = (ip >> 8) & 0xFF;
    if (o1 == 10) return true;                         // 10.0.0.0/8
    if (o1 == 172 && (o2 >= 16 && o2 <= 31)) return true; // 172.16.0.0/12
    if (o1 == 192 && o2 == 168) return true;           // 192.168.0.0/16
    if (o1 == 127) return true;                        // 127.0.0.0/8
    if (o1 == 169 && o2 == 254) return true;           // 169.254.0.0/16 Link-local
    return false;
}

bool RiskProfiler::isRFC1918(const std::string& ip_str) {
    return isRFC1918(parseIPAddr(ip_str));
}

RiskProfiler::RiskProfiler(const RiskProfilerConfig& config)
    : config_(config) {}

void RiskProfiler::profileAll(const std::vector<FlowRecord>& flows,
                             const std::vector<DetectionEvent>& detections,
                             const std::vector<SecurityIncident>& incidents,
                             const std::vector<SignatureEvent>& signatures,
                             const std::vector<ThreatMatchEvent>& threat_matches) {
    endpoint_profiles_.clear();
    flow_profiles_.clear();

    if (!config_.enabled) return;

    // 1. Ingest all flows to establish baseline endpoint inventory
    for (const auto& f : flows) {
        std::string src_ip = formatIPAddr(f.initial_tuple.src_ip);
        std::string dst_ip = formatIPAddr(f.initial_tuple.dst_ip);
        std::string proto = (f.initial_tuple.protocol == 6) ? "TCP" :
                            (f.initial_tuple.protocol == 17) ? "UDP" : "OTHER";
        if (!f.detected_app_name.empty() && f.detected_app_name != "Unknown") {
            proto = f.detected_app_name;
        }

        uint64_t flow_pkts = f.fwd.packet_count + f.rev.packet_count;
        uint64_t flow_b = f.fwd.byte_count + f.rev.byte_count;

        // Source endpoint
        auto& src_ep = endpoint_profiles_[src_ip];
        if (src_ep.ip.empty()) {
            src_ep.ip = src_ip;
            src_ep.ip_int = f.initial_tuple.src_ip;
            src_ep.is_internal = isRFC1918(f.initial_tuple.src_ip);
            src_ep.first_seen_us = f.start_time_us;
        }
        src_ep.total_flows++;
        src_ep.total_packets += flow_pkts;
        src_ep.total_bytes += flow_b;
        src_ep.bytes_sent += f.fwd.byte_count;
        src_ep.bytes_received += f.rev.byte_count;
        src_ep.associated_ports.insert(f.initial_tuple.src_port);
        src_ep.protocols.insert(proto);
        if (f.start_time_us < src_ep.first_seen_us || src_ep.first_seen_us == 0) src_ep.first_seen_us = f.start_time_us;
        if (f.last_time_us > src_ep.last_seen_us) src_ep.last_seen_us = f.last_time_us;

        // Destination endpoint
        auto& dst_ep = endpoint_profiles_[dst_ip];
        if (dst_ep.ip.empty()) {
            dst_ep.ip = dst_ip;
            dst_ep.ip_int = f.initial_tuple.dst_ip;
            dst_ep.is_internal = isRFC1918(f.initial_tuple.dst_ip);
            dst_ep.first_seen_us = f.start_time_us;
        }
        dst_ep.total_flows++;
        dst_ep.total_packets += flow_pkts;
        dst_ep.total_bytes += flow_b;
        dst_ep.bytes_sent += f.rev.byte_count;
        dst_ep.bytes_received += f.fwd.byte_count;
        dst_ep.associated_ports.insert(f.initial_tuple.dst_port);
        dst_ep.protocols.insert(proto);
        if (f.start_time_us < dst_ep.first_seen_us || dst_ep.first_seen_us == 0) dst_ep.first_seen_us = f.start_time_us;
        if (f.last_time_us > dst_ep.last_seen_us) dst_ep.last_seen_us = f.last_time_us;

        // Individual Flow Risk Profile
        FlowRiskProfile fp;
        fp.flow_id = f.flow_id;
        fp.tuple = f.initial_tuple;
        fp.protocol_str = proto;
        fp.risk_score = 0.0;

        if (f.ioc_match_count > 0) {
            RiskFactor rf;
            rf.name = "THREAT_INTEL_MATCH";
            rf.weight = config_.threat_ioc_weight;
            rf.explanation = "Flow matched threat intelligence IOC: " + f.threat_summary;
            rf.source_reference = f.matched_ioc_ids.empty() ? "" : f.matched_ioc_ids[0];
            fp.contributing_factors.push_back(rf);
            fp.risk_score += rf.weight;
        }

        if (f.dns_answers.empty() && !f.dns_query.empty() && f.dns_rcode == 3) {
            RiskFactor rf;
            rf.name = "DNS_NXDOMAIN_FAILURE";
            rf.weight = 15.0;
            rf.explanation = "Flow observed NXDOMAIN resolution failure for " + f.dns_query;
            rf.source_reference = "DNS_INTELLIGENCE";
            fp.contributing_factors.push_back(rf);
            fp.risk_score += rf.weight;
        }

        if (f.rev.byte_count == 0 && f.fwd.byte_count > 50000) {
            RiskFactor rf;
            rf.name = "UNILATERAL_DATA_PUSH";
            rf.weight = config_.exfiltration_weight;
            rf.explanation = "Substantial unidirectional data transmission with zero reverse bytes";
            rf.source_reference = "FLOW_TELEMETRY";
            fp.contributing_factors.push_back(rf);
            fp.risk_score += rf.weight;
        }

        fp.risk_score = std::min(100.0, fp.risk_score);
        if (fp.risk_score >= config_.critical_threshold) fp.risk_level = RiskLevel::CRITICAL;
        else if (fp.risk_score >= config_.high_threshold) fp.risk_level = RiskLevel::HIGH;
        else if (fp.risk_score >= config_.medium_threshold) fp.risk_level = RiskLevel::MEDIUM;
        else if (fp.risk_score >= config_.low_threshold) fp.risk_level = RiskLevel::LOW;
        else fp.risk_level = RiskLevel::CLEAN;

        flow_profiles_.push_back(fp);
    }

    // 2. Map Behavioral Detections to Endpoints
    for (const auto& det : detections) {
        std::string src_ip = det.source_ip_str.empty() ? formatIPAddr(det.source_ip) : det.source_ip_str;
        if (endpoint_profiles_.find(src_ip) != endpoint_profiles_.end()) {
            auto& ep = endpoint_profiles_[src_ip];
            ep.related_detections.push_back(det.detection_id);

            RiskFactor rf;
            rf.name = "BEHAVIORAL_ALERT_" + detectionCategoryToString(det.category);
            rf.weight = (det.severity == DetectionSeverity::CRITICAL) ? 35.0 :
                        (det.severity == DetectionSeverity::HIGH) ? 20.0 :
                        (det.severity == DetectionSeverity::MEDIUM) ? 12.0 : 5.0;
            rf.explanation = det.explanation;
            rf.source_reference = det.detection_id;
            ep.contributing_factors.push_back(rf);

            if (det.category == DetectionCategory::NETWORK_RECONNAISSANCE) ep.behavioral_tags.insert("SCANNER");
            else if (det.category == DetectionCategory::COMMAND_AND_CONTROL) ep.behavioral_tags.insert("BEACONING");
            else if (det.category == DetectionCategory::UNUSUAL_TRAFFIC_VOLUME) ep.behavioral_tags.insert("DATA_EXFIL");
            else if (det.category == DetectionCategory::SUSPICIOUS_DNS) ep.behavioral_tags.insert("DNS_ANOMALOUS");
        }
    }

    // 3. Map Signatures to Endpoints
    for (const auto& sig : signatures) {
        std::string src_ip = sig.src_ip;
        std::string dst_ip = sig.dst_ip;
        for (const auto& ip_str : {src_ip, dst_ip}) {
            if (endpoint_profiles_.find(ip_str) != endpoint_profiles_.end()) {
                auto& ep = endpoint_profiles_[ip_str];
                ep.related_signatures.push_back(sig.rule_id);

                RiskFactor rf;
                rf.name = "SIGNATURE_TRIGGER_" + sig.rule_id;
                rf.weight = (sig.severity == SignatureSeverity::CRITICAL) ? 35.0 :
                            (sig.severity == SignatureSeverity::HIGH) ? 22.0 :
                            (sig.severity == SignatureSeverity::MEDIUM) ? 12.0 : 4.0;
                rf.explanation = sig.rule_name + " (" + signatureCategoryToString(sig.category) + ")";
                rf.source_reference = sig.rule_id;
                ep.contributing_factors.push_back(rf);
                ep.behavioral_tags.insert("SIGNATURE_TRIGGERED");
            }
        }
    }

    // 4. Map Threat Intelligence Matches
    for (const auto& tm : threat_matches) {
        std::string src_ip = tm.src_ip;
        std::string dst_ip = tm.dst_ip;
        for (const auto& ip_str : {src_ip, dst_ip}) {
            if (endpoint_profiles_.find(ip_str) != endpoint_profiles_.end()) {
                auto& ep = endpoint_profiles_[ip_str];
                ep.related_iocs.push_back(tm.ioc_id);

                RiskFactor rf;
                rf.name = "THREAT_INTEL_IOC_" + tm.ioc_id;
                rf.weight = (tm.severity == IOCSeverity::CRITICAL) ? 40.0 :
                            (tm.severity == IOCSeverity::HIGH) ? 25.0 :
                            (tm.severity == IOCSeverity::MEDIUM) ? 15.0 : 5.0;
                rf.explanation = tm.evidence;
                rf.source_reference = tm.ioc_id;
                ep.contributing_factors.push_back(rf);
                ep.behavioral_tags.insert("THREAT_INTEL_FLAGGED");
            }
        }
    }

    // 5. Map Correlated Security Incidents
    for (const auto& inc : incidents) {
        std::string ep_ip = inc.primary_endpoint;
        if (endpoint_profiles_.find(ep_ip) != endpoint_profiles_.end()) {
            auto& ep = endpoint_profiles_[ep_ip];
            ep.related_incidents.push_back(inc.incident_id);

            RiskFactor rf;
            rf.name = "SECURITY_INCIDENT_" + inc.incident_id;
            rf.weight = (inc.severity == IncidentSeverity::CRITICAL) ? config_.incident_critical_weight :
                        (inc.severity == IncidentSeverity::HIGH) ? config_.incident_high_weight :
                        (inc.severity == IncidentSeverity::MEDIUM) ? config_.incident_medium_weight : 8.0;
            rf.explanation = inc.title + " (Score: " + std::to_string(static_cast<int>(inc.correlation_score)) + ")";
            rf.source_reference = inc.incident_id;
            ep.contributing_factors.push_back(rf);
        }
    }

    // 6. Calculate aggregate scores & roles
    calculateEndpointScores();
}

void RiskProfiler::calculateEndpointScores() {
    for (auto& pair : endpoint_profiles_) {
        auto& ep = pair.second;

        // Role inference
        if (!ep.is_internal) {
            ep.role = "EXTERNAL";
        } else if (ep.associated_ports.count(80) || ep.associated_ports.count(443) ||
                   ep.associated_ports.count(8080) || ep.associated_ports.count(53)) {
            if (ep.bytes_sent > ep.bytes_received * 2 && ep.total_flows > 5) {
                ep.role = "SERVER";
            } else {
                ep.role = "MIXED";
            }
        } else {
            ep.role = "CLIENT";
        }

        // Sum contributing factors with soft diminishing returns
        double total_score = 0.0;
        for (const auto& f : ep.contributing_factors) {
            total_score += f.weight;
        }

        // Bound to 0.0 - 100.0
        ep.risk_score = std::min(100.0, total_score);

        if (ep.risk_score >= config_.critical_threshold) {
            ep.risk_level = RiskLevel::CRITICAL;
        } else if (ep.risk_score >= config_.high_threshold) {
            ep.risk_level = RiskLevel::HIGH;
        } else if (ep.risk_score >= config_.medium_threshold) {
            ep.risk_level = RiskLevel::MEDIUM;
        } else if (ep.risk_score >= config_.low_threshold) {
            ep.risk_level = RiskLevel::LOW;
        } else {
            ep.risk_level = RiskLevel::CLEAN;
        }

        assignBehavioralTags(ep);
    }
}

void RiskProfiler::assignBehavioralTags(EndpointRiskProfile& ep) {
    if (ep.total_bytes > 50000000) ep.behavioral_tags.insert("HIGH_BANDWIDTH");
    if (ep.total_flows > 100) ep.behavioral_tags.insert("HIGH_CONNECTION_RATE");
    if (ep.associated_ports.size() > 20) ep.behavioral_tags.insert("MULTI_PORT");
    if (ep.bytes_sent > ep.bytes_received * 10 && ep.bytes_sent > 100000) ep.behavioral_tags.insert("DATA_EXFIL_SUSPECT");
}

std::vector<EndpointRiskProfile> RiskProfiler::getTopRiskEndpoints(size_t limit) const {
    std::vector<EndpointRiskProfile> vec;
    vec.reserve(endpoint_profiles_.size());
    for (const auto& p : endpoint_profiles_) {
        vec.push_back(p.second);
    }
    std::sort(vec.begin(), vec.end(), [](const EndpointRiskProfile& a, const EndpointRiskProfile& b) {
        if (a.risk_score != b.risk_score) return a.risk_score > b.risk_score;
        return a.total_bytes > b.total_bytes;
    });
    if (vec.size() > limit) vec.resize(limit);
    return vec;
}

std::vector<FlowRiskProfile> RiskProfiler::getTopRiskFlows(size_t limit) const {
    std::vector<FlowRiskProfile> vec = flow_profiles_;
    std::sort(vec.begin(), vec.end(), [](const FlowRiskProfile& a, const FlowRiskProfile& b) {
        return a.risk_score > b.risk_score;
    });
    if (vec.size() > limit) vec.resize(limit);
    return vec;
}

std::string RiskProfiler::endpointsToJson() const {
    std::ostringstream ss;
    ss << "[\n";
    bool first = true;
    for (const auto& p : endpoint_profiles_) {
        if (!first) ss << ",\n";
        ss << "  " << p.second.toJson();
        first = false;
    }
    ss << "\n]\n";
    return ss.str();
}

std::string RiskProfiler::flowsToJson() const {
    std::ostringstream ss;
    ss << "[\n";
    bool first = true;
    for (const auto& f : flow_profiles_) {
        if (!first) ss << ",\n";
        ss << "  " << f.toJson();
        first = false;
    }
    ss << "\n]\n";
    return ss.str();
}

std::string RiskProfiler::summaryToJson() const {
    size_t critical_cnt = 0, high_cnt = 0, medium_cnt = 0, low_cnt = 0, clean_cnt = 0;
    for (const auto& p : endpoint_profiles_) {
        switch (p.second.risk_level) {
            case RiskLevel::CRITICAL: critical_cnt++; break;
            case RiskLevel::HIGH:     high_cnt++; break;
            case RiskLevel::MEDIUM:   medium_cnt++; break;
            case RiskLevel::LOW:      low_cnt++; break;
            case RiskLevel::CLEAN:    clean_cnt++; break;
        }
    }

    std::ostringstream ss;
    ss << "{\n"
       << "  \"total_endpoints\": " << endpoint_profiles_.size() << ",\n"
       << "  \"critical_endpoints\": " << critical_cnt << ",\n"
       << "  \"high_risk_endpoints\": " << high_cnt << ",\n"
       << "  \"medium_risk_endpoints\": " << medium_cnt << ",\n"
       << "  \"low_risk_endpoints\": " << low_cnt << ",\n"
       << "  \"clean_endpoints\": " << clean_cnt << ",\n"
       << "  \"top_risk_endpoints\": [\n";

    auto top = getTopRiskEndpoints(5);
    bool first = true;
    for (const auto& ep : top) {
        if (!first) ss << ",\n";
        ss << "    " << ep.toJson();
        first = false;
    }
    ss << "\n  ]\n}";
    return ss.str();
}

std::string RiskProfiler::generateRiskReport() const {
    std::ostringstream ss;
    ss << "\n"
       << "╔══════════════════════════════════════════════════════════════╗\n"
       << "║             NETWORK RISK ASSESSMENT REPORT                   ║\n"
       << "╠══════════════════════════════════════════════════════════════╣\n";

    size_t crit = 0, high = 0, med = 0, low = 0, clean = 0;
    for (const auto& p : endpoint_profiles_) {
        switch (p.second.risk_level) {
            case RiskLevel::CRITICAL: crit++; break;
            case RiskLevel::HIGH:     high++; break;
            case RiskLevel::MEDIUM:   med++; break;
            case RiskLevel::LOW:      low++; break;
            case RiskLevel::CLEAN:    clean++; break;
        }
    }

    ss << "║ Total Endpoints Profiled:    " << std::setw(10) << endpoint_profiles_.size() << "                      ║\n"
       << "║ Critical Risk Endpoints:     " << std::setw(10) << crit << "                      ║\n"
       << "║ High Risk Endpoints:         " << std::setw(10) << high << "                      ║\n"
       << "║ Medium Risk Endpoints:       " << std::setw(10) << med << "                      ║\n"
       << "║ Low Risk Endpoints:          " << std::setw(10) << low << "                      ║\n"
       << "║ Clean / Benign Endpoints:    " << std::setw(10) << clean << "                      ║\n"
       << "╠══════════════════════════════════════════════════════════════╣\n"
       << "║                     TOP RISK ENDPOINTS                       ║\n"
       << "╠══════════════════════════════════════════════════════════════╣\n";

    auto top = getTopRiskEndpoints(8);
    if (top.empty()) {
        ss << "║ (No endpoints profiled)                                      ║\n";
    } else {
        for (const auto& ep : top) {
            std::string level_str = "[" + riskLevelToString(ep.risk_level) + "]";
            ss << "║ " << std::left << std::setw(12) << level_str
               << std::setw(17) << ep.ip
               << " Score: " << std::right << std::setw(4) << std::fixed << std::setprecision(1) << ep.risk_score
               << " (" << std::setw(3) << ep.total_flows << " flows, "
               << std::setw(6) << ep.total_bytes << " B) ║\n";
            if (!ep.behavioral_tags.empty()) {
                std::string tag_str = "   Tags: ";
                for (const auto& t : ep.behavioral_tags) tag_str += t + " ";
                if (tag_str.length() > 58) tag_str = tag_str.substr(0, 55) + "...";
                ss << "║ " << std::left << std::setw(60) << tag_str << " ║\n";
            }
        }
    }
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    return ss.str();
}

} // namespace DPI
