#include "signature_types.h"
#include <algorithm>
#include <cctype>
#include <iostream>

namespace DPI {

static inline std::string escapeJson(const std::string& str) {
    std::string out;
    for (char c : str) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\b') out += "\\b";
        else if (c == '\f') out += "\\f";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 126) {
            std::ostringstream ss;
            ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (static_cast<int>(c) & 0xFF);
            out += ss.str();
        } else {
            out += c;
        }
    }
    return out;
}

static inline std::string toUpper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::toupper(c); });
    return s;
}

static inline std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

// ============================================================================
// String Conversions
// ============================================================================

std::string signatureSeverityToString(SignatureSeverity severity) {
    switch (severity) {
        case SignatureSeverity::LOW:      return "LOW";
        case SignatureSeverity::MEDIUM:   return "MEDIUM";
        case SignatureSeverity::HIGH:     return "HIGH";
        case SignatureSeverity::CRITICAL: return "CRITICAL";
        default:                          return "UNKNOWN";
    }
}

SignatureSeverity stringToSignatureSeverity(const std::string& str) {
    std::string s = toUpper(trim(str));
    if (s == "CRITICAL") return SignatureSeverity::CRITICAL;
    if (s == "HIGH")     return SignatureSeverity::HIGH;
    if (s == "LOW")      return SignatureSeverity::LOW;
    return SignatureSeverity::MEDIUM;
}

std::string signatureCategoryToString(SignatureCategory cat) {
    switch (cat) {
        case SignatureCategory::MALWARE:            return "MALWARE";
        case SignatureCategory::EXPLOIT:            return "EXPLOIT";
        case SignatureCategory::SCANNER:            return "SCANNER";
        case SignatureCategory::POLICY_VIOLATION:   return "POLICY_VIOLATION";
        case SignatureCategory::INFO:               return "INFO";
        case SignatureCategory::SUSPICIOUS_TRAFFIC: return "SUSPICIOUS_TRAFFIC";
        case SignatureCategory::DATA_LEAK:          return "DATA_LEAK";
        case SignatureCategory::DOS:                return "DOS";
        default:                                    return "MALWARE";
    }
}

SignatureCategory stringToSignatureCategory(const std::string& str) {
    std::string s = toUpper(trim(str));
    if (s == "EXPLOIT")            return SignatureCategory::EXPLOIT;
    if (s == "SCANNER")            return SignatureCategory::SCANNER;
    if (s == "POLICY_VIOLATION")   return SignatureCategory::POLICY_VIOLATION;
    if (s == "INFO")               return SignatureCategory::INFO;
    if (s == "SUSPICIOUS_TRAFFIC") return SignatureCategory::SUSPICIOUS_TRAFFIC;
    if (s == "DATA_LEAK")          return SignatureCategory::DATA_LEAK;
    if (s == "DOS")                return SignatureCategory::DOS;
    return SignatureCategory::MALWARE;
}

std::string ruleProtocolToString(RuleProtocol proto) {
    switch (proto) {
        case RuleProtocol::TCP: return "TCP";
        case RuleProtocol::UDP: return "UDP";
        case RuleProtocol::IP:  return "IP";
        case RuleProtocol::ANY: return "ANY";
        default:                return "ANY";
    }
}

RuleProtocol stringToRuleProtocol(const std::string& str) {
    std::string s = toUpper(trim(str));
    if (s == "TCP") return RuleProtocol::TCP;
    if (s == "UDP") return RuleProtocol::UDP;
    if (s == "IP")  return RuleProtocol::IP;
    return RuleProtocol::ANY;
}

std::string ruleDirectionToString(RuleDirection dir) {
    switch (dir) {
        case RuleDirection::FORWARD:       return "FORWARD";
        case RuleDirection::REVERSE:       return "REVERSE";
        case RuleDirection::BIDIRECTIONAL: return "BIDIRECTIONAL";
        default:                           return "BIDIRECTIONAL";
    }
}

RuleDirection stringToRuleDirection(const std::string& str) {
    std::string s = toUpper(trim(str));
    if (s == "FORWARD" || s == "->" || s == "TO") return RuleDirection::FORWARD;
    if (s == "REVERSE" || s == "<-")              return RuleDirection::REVERSE;
    return RuleDirection::BIDIRECTIONAL;
}

std::string flowStateCriteriaToString(FlowStateCriteria state) {
    switch (state) {
        case FlowStateCriteria::NEW:         return "NEW";
        case FlowStateCriteria::ESTABLISHED: return "ESTABLISHED";
        case FlowStateCriteria::CLOSED:      return "CLOSED";
        case FlowStateCriteria::RESET:       return "RESET";
        case FlowStateCriteria::ANY:         return "ANY";
        default:                             return "ANY";
    }
}

FlowStateCriteria stringToFlowStateCriteria(const std::string& str) {
    std::string s = toUpper(trim(str));
    if (s == "NEW")         return FlowStateCriteria::NEW;
    if (s == "ESTABLISHED") return FlowStateCriteria::ESTABLISHED;
    if (s == "CLOSED")      return FlowStateCriteria::CLOSED;
    if (s == "RESET")       return FlowStateCriteria::RESET;
    return FlowStateCriteria::ANY;
}

std::string streamDirectionToString(StreamDirection dir) {
    switch (dir) {
        case StreamDirection::FWD_ONLY: return "FWD_ONLY";
        case StreamDirection::REV_ONLY: return "REV_ONLY";
        case StreamDirection::EITHER:   return "EITHER";
        case StreamDirection::BOTH:     return "BOTH";
        default:                        return "EITHER";
    }
}

StreamDirection stringToStreamDirection(const std::string& str) {
    std::string s = toUpper(trim(str));
    if (s == "FWD_ONLY" || s == "FWD" || s == "REQUEST") return StreamDirection::FWD_ONLY;
    if (s == "REV_ONLY" || s == "REV" || s == "RESPONSE") return StreamDirection::REV_ONLY;
    if (s == "BOTH") return StreamDirection::BOTH;
    return StreamDirection::EITHER;
}

std::string matchScopeToString(MatchScope scope) {
    switch (scope) {
        case MatchScope::PACKET: return "PACKET";
        case MatchScope::FLOW:   return "FLOW";
        case MatchScope::STREAM: return "STREAM";
        case MatchScope::HTTP:   return "HTTP";
        case MatchScope::TLS:    return "TLS";
        case MatchScope::DNS:    return "DNS";
        case MatchScope::MULTI:  return "MULTI";
        default:                 return "FLOW";
    }
}

// ============================================================================
// PortRange Implementation
// ============================================================================

PortRange PortRange::parse(const std::string& str) {
    std::string s = trim(str);
    if (s.empty() || s == "any" || s == "*") {
        return {1, 65535};
    }
    size_t dash = s.find('-');
    if (dash != std::string::npos) {
        try {
            int p1 = std::stoi(s.substr(0, dash));
            int p2 = std::stoi(s.substr(dash + 1));
            p1 = std::max(1, std::min(65535, p1));
            p2 = std::max(1, std::min(65535, p2));
            if (p1 > p2) std::swap(p1, p2);
            return {static_cast<uint16_t>(p1), static_cast<uint16_t>(p2)};
        } catch (...) {
            return {1, 65535};
        }
    }
    try {
        int p = std::stoi(s);
        p = std::max(1, std::min(65535, p));
        return {static_cast<uint16_t>(p), static_cast<uint16_t>(p)};
    } catch (...) {
        return {1, 65535};
    }
}

std::string PortRange::toString() const {
    if (min_port == max_port) return std::to_string(min_port);
    if (min_port == 1 && max_port == 65535) return "any";
    return std::to_string(min_port) + "-" + std::to_string(max_port);
}

// ============================================================================
// IPNet (CIDR) Implementation
// ============================================================================

static inline uint32_t parseIPv4(const std::string& ip_str) {
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

static inline uint32_t toNetworkOrder(uint32_t ip) {
    return ((ip & 0xFF) << 24) |
           (((ip >> 8) & 0xFF) << 16) |
           (((ip >> 16) & 0xFF) << 8) |
           (((ip >> 24) & 0xFF));
}

IPNet IPNet::parse(const std::string& cidr_str) {
    std::string s = trim(cidr_str);
    if (s.empty() || s == "any" || s == "*") {
        return {0, 0};
    }
    size_t slash = s.find('/');
    if (slash != std::string::npos) {
        std::string ip_part = s.substr(0, slash);
        std::string mask_part = s.substr(slash + 1);
        try {
            int p = std::stoi(mask_part);
            p = std::max(0, std::min(32, p));
            return {parseIPv4(ip_part), static_cast<uint8_t>(p)};
        } catch (...) {
            return {parseIPv4(ip_part), 32};
        }
    }
    return {parseIPv4(s), 32};
}

bool IPNet::matches(uint32_t candidate_ip) const {
    if (prefix_len == 0) return true;
    uint32_t cand_net = toNetworkOrder(candidate_ip);
    uint32_t base_net = toNetworkOrder(ip);
    uint32_t mask = (prefix_len == 32) ? 0xFFFFFFFFU : (~0U << (32 - prefix_len));
    return (cand_net & mask) == (base_net & mask);
}

std::string IPNet::toString() const {
    if (prefix_len == 0) return "any";
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    if (prefix_len < 32) {
        ss << "/" << static_cast<int>(prefix_len);
    }
    return ss.str();
}

// ============================================================================
// PatternCondition Implementation
// ============================================================================

bool PatternCondition::decodeHex() {
    std::string s = trim(pattern);
    if (s.rfind("hex:", 0) == 0) {
        s = s.substr(4);
    }
    if (!s.empty() && s.front() == '|' && s.back() == '|') {
        s = s.substr(1, s.size() - 2);
    }
    
    bytes.clear();
    std::string hex_digits;
    for (char c : s) {
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            hex_digits += c;
        } else if (!std::isspace(static_cast<unsigned char>(c))) {
            // Invalid hex character
            return false;
        }
    }
    if (hex_digits.empty() || hex_digits.size() % 2 != 0) {
        return false;
    }
    for (size_t i = 0; i < hex_digits.size(); i += 2) {
        std::string byte_str = hex_digits.substr(i, 2);
        try {
            uint8_t b = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
            bytes.push_back(b);
        } catch (...) {
            return false;
        }
    }
    is_hex = true;
    return true;
}

// ============================================================================
// SignatureRule Serialization
// ============================================================================

std::string SignatureRule::toJson() const {
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"id\": \"" << escapeJson(rule_id) << "\",\n";
    ss << "  \"schema_version\": \"" << escapeJson(schema_version) << "\",\n";
    ss << "  \"name\": \"" << escapeJson(name) << "\",\n";
    ss << "  \"revision\": " << revision << ",\n";
    ss << "  \"category\": \"" << signatureCategoryToString(category) << "\",\n";
    ss << "  \"severity\": \"" << signatureSeverityToString(severity) << "\",\n";
    ss << "  \"description\": \"" << escapeJson(description) << "\",\n";
    ss << "  \"enabled\": " << (enabled ? "true" : "false") << ",\n";
    if (match_limit > 0) {
        ss << "  \"match_limit\": " << match_limit << ",\n";
    }
    
    // Tags
    ss << "  \"tags\": [";
    for (size_t i = 0; i < tags.size(); ++i) {
        ss << "\"" << escapeJson(tags[i]) << "\"" << (i + 1 < tags.size() ? ", " : "");
    }
    ss << "],\n";

    // References
    ss << "  \"references\": [";
    for (size_t i = 0; i < references.size(); ++i) {
        ss << "\"" << escapeJson(references[i]) << "\"" << (i + 1 < references.size() ? ", " : "");
    }
    ss << "],\n";

    // Network
    ss << "  \"network\": {\n";
    ss << "    \"protocol\": \"" << ruleProtocolToString(network.protocol) << "\",\n";
    ss << "    \"direction\": \"" << ruleDirectionToString(network.direction) << "\"";
    if (!network.src_ips.empty()) {
        ss << ",\n    \"src_ips\": [";
        for (size_t i = 0; i < network.src_ips.size(); ++i) {
            ss << "\"" << network.src_ips[i].toString() << "\"" << (i + 1 < network.src_ips.size() ? ", " : "");
        }
        ss << "]";
    }
    if (!network.dst_ips.empty()) {
        ss << ",\n    \"dst_ips\": [";
        for (size_t i = 0; i < network.dst_ips.size(); ++i) {
            ss << "\"" << network.dst_ips[i].toString() << "\"" << (i + 1 < network.dst_ips.size() ? ", " : "");
        }
        ss << "]";
    }
    if (!network.src_ports.empty()) {
        ss << ",\n    \"src_ports\": [";
        for (size_t i = 0; i < network.src_ports.size(); ++i) {
            ss << "\"" << network.src_ports[i].toString() << "\"" << (i + 1 < network.src_ports.size() ? ", " : "");
        }
        ss << "]";
    }
    if (!network.dst_ports.empty()) {
        ss << ",\n    \"dst_ports\": [";
        for (size_t i = 0; i < network.dst_ports.size(); ++i) {
            ss << "\"" << network.dst_ports[i].toString() << "\"" << (i + 1 < network.dst_ports.size() ? ", " : "");
        }
        ss << "]";
    }
    ss << "\n  }";

    // Stream Content
    if (!stream_content.patterns.empty()) {
        ss << ",\n  \"stream_content\": [\n";
        for (size_t i = 0; i < stream_content.patterns.size(); ++i) {
            const auto& p = stream_content.patterns[i];
            ss << "    {\n";
            ss << "      \"pattern\": \"" << escapeJson(p.pattern) << "\",\n";
            ss << "      \"is_hex\": " << (p.is_hex ? "true" : "false") << ",\n";
            ss << "      \"nocase\": " << (p.nocase ? "true" : "false") << ",\n";
            ss << "      \"offset\": " << p.offset << ",\n";
            ss << "      \"depth\": " << p.depth << ",\n";
            ss << "      \"relative_distance\": " << p.relative_distance << ",\n";
            ss << "      \"relative_within\": " << p.relative_within << ",\n";
            ss << "      \"negated\": " << (p.negated ? "true" : "false") << "\n";
            ss << "    }" << (i + 1 < stream_content.patterns.size() ? "," : "") << "\n";
        }
        ss << "  ]";
    }

    // HTTP
    if (http.has_criteria()) {
        ss << ",\n  \"http\": {\n";
        bool first = true;
        if (!http.method.empty()) {
            ss << "    \"method\": \"" << escapeJson(http.method) << "\"";
            first = false;
        }
        if (!http.host.empty()) {
            if (!first) ss << ",\n";
            ss << "    \"host\": \"" << escapeJson(http.host) << "\"";
            first = false;
        }
        if (!http.uri.empty()) {
            if (!first) ss << ",\n";
            ss << "    \"uri\": \"" << escapeJson(http.uri) << "\"";
            first = false;
        }
        if (!http.user_agent.empty()) {
            if (!first) ss << ",\n";
            ss << "    \"user_agent\": \"" << escapeJson(http.user_agent) << "\"";
            first = false;
        }
        if (http.status_code != 0) {
            if (!first) ss << ",\n";
            ss << "    \"status_code\": " << http.status_code;
            first = false;
        }
        ss << "\n  }";
    }

    // TLS
    if (tls.has_criteria()) {
        ss << ",\n  \"tls\": {\n";
        bool first = true;
        if (!tls.sni.empty()) {
            ss << "    \"sni\": \"" << escapeJson(tls.sni) << "\"";
            first = false;
        }
        if (!tls.alpn.empty()) {
            if (!first) ss << ",\n";
            ss << "    \"alpn\": \"" << escapeJson(tls.alpn) << "\"";
            first = false;
        }
        if (!tls.version.empty()) {
            if (!first) ss << ",\n";
            ss << "    \"version\": \"" << escapeJson(tls.version) << "\"";
            first = false;
        }
        ss << "\n  }";
    }

    // DNS
    if (dns.has_criteria()) {
        ss << ",\n  \"dns\": {\n";
        bool first = true;
        if (!dns.query_name.empty()) {
            ss << "    \"query_name\": \"" << escapeJson(dns.query_name) << "\"";
            first = false;
        }
        if (dns.query_type != 0) {
            if (!first) ss << ",\n";
            ss << "    \"query_type\": " << dns.query_type;
            first = false;
        }
        if (dns.rcode != -1) {
            if (!first) ss << ",\n";
            ss << "    \"rcode\": " << dns.rcode;
            first = false;
        }
        if (dns.is_nxdomain.has_value()) {
            if (!first) ss << ",\n";
            ss << "    \"is_nxdomain\": " << (dns.is_nxdomain.value() ? "true" : "false");
            first = false;
        }
        ss << "\n  }";
    }

    ss << "\n}";
    return ss.str();
}

// ============================================================================
// SignatureEvent Serialization
// ============================================================================

std::string SignatureEvent::toJson(int indent) const {
    std::string pad(indent, ' ');
    std::ostringstream ss;
    ss << pad << "{\n";
    ss << pad << "  \"event_id\": \"" << escapeJson(event_id) << "\",\n";
    ss << pad << "  \"schema_version\": \"" << escapeJson(schema_version) << "\",\n";
    ss << pad << "  \"rule_id\": \"" << escapeJson(rule_id) << "\",\n";
    ss << pad << "  \"rule_name\": \"" << escapeJson(rule_name) << "\",\n";
    ss << pad << "  \"rule_revision\": " << rule_revision << ",\n";
    ss << pad << "  \"category\": \"" << signatureCategoryToString(category) << "\",\n";
    ss << pad << "  \"severity\": \"" << signatureSeverityToString(severity) << "\",\n";
    ss << pad << "  \"timestamp_us\": " << timestamp_us << ",\n";
    ss << pad << "  \"src_ip\": \"" << escapeJson(src_ip) << "\",\n";
    ss << pad << "  \"dst_ip\": \"" << escapeJson(dst_ip) << "\",\n";
    ss << pad << "  \"src_port\": " << src_port << ",\n";
    ss << pad << "  \"dst_port\": " << dst_port << ",\n";
    ss << pad << "  \"protocol\": \"" << escapeJson(protocol) << "\",\n";
    ss << pad << "  \"direction\": \"" << escapeJson(direction) << "\",\n";
    ss << pad << "  \"flow_id\": " << flow_id << ",\n";
    ss << pad << "  \"incident_id\": \"" << escapeJson(incident_id) << "\",\n";
    ss << pad << "  \"match_scope\": \"" << matchScopeToString(match_scope) << "\",\n";
    ss << pad << "  \"match_details\": \"" << escapeJson(match_details) << "\",\n";
    ss << pad << "  \"matched_pattern\": \"" << escapeJson(matched_pattern) << "\",\n";
    ss << pad << "  \"match_offset\": " << match_offset << ",\n";
    ss << pad << "  \"evidence\": \"" << escapeJson(evidence) << "\",\n";
    ss << pad << "  \"confidence\": \"" << escapeJson(confidence) << "\"\n";
    ss << pad << "}";
    return ss.str();
}

std::string SignatureEvent::csvHeader() {
    return "event_id,schema_version,rule_id,rule_name,category,severity,timestamp_us,"
           "src_ip,dst_ip,src_port,dst_port,protocol,direction,flow_id,incident_id,"
           "match_scope,match_offset,confidence,evidence";
}

std::string SignatureEvent::toCsvRow() const {
    std::ostringstream ss;
    ss << "\"" << escapeJson(event_id) << "\","
       << "\"" << escapeJson(schema_version) << "\","
       << "\"" << escapeJson(rule_id) << "\","
       << "\"" << escapeJson(rule_name) << "\","
       << "\"" << signatureCategoryToString(category) << "\","
       << "\"" << signatureSeverityToString(severity) << "\","
       << timestamp_us << ","
       << "\"" << escapeJson(src_ip) << "\","
       << "\"" << escapeJson(dst_ip) << "\","
       << src_port << ","
       << dst_port << ","
       << "\"" << escapeJson(protocol) << "\","
       << "\"" << escapeJson(direction) << "\","
       << flow_id << ","
       << "\"" << escapeJson(incident_id) << "\","
       << "\"" << matchScopeToString(match_scope) << "\","
       << match_offset << ","
       << "\"" << escapeJson(confidence) << "\","
       << "\"" << escapeJson(evidence) << "\"";
    return ss.str();
}

} // namespace DPI
