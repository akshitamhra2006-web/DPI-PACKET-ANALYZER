#include "threat_intel_types.h"
#include <algorithm>
#include <cctype>
#include <iostream>
#include <sstream>
#include <iomanip>

namespace DPI {

// ============================================================================
// Internal Helpers
// ============================================================================

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

static inline std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

static inline std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

// Convert little-endian/host IP to big-endian network order for prefix comparisons
static inline uint32_t toNetworkOrder(uint32_t ip) {
    return ((ip & 0xFF) << 24) |
           (((ip >> 8) & 0xFF) << 16) |
           (((ip >> 16) & 0xFF) << 8) |
           (((ip >> 24) & 0xFF));
}

// ============================================================================
// String Conversions
// ============================================================================

std::string iocTypeToString(IOCType type) {
    switch (type) {
        case IOCType::IPV4:        return "IPV4";
        case IOCType::IPV4_CIDR:   return "IPV4_CIDR";
        case IOCType::DOMAIN_NAME: return "DOMAIN";
        case IOCType::DNS_NAME:    return "DNS_NAME";
        case IOCType::TLS_SNI:     return "TLS_SNI";
        case IOCType::URL:         return "URL";
        case IOCType::FILE_HASH:   return "FILE_HASH";
        default:                   return "UNKNOWN";
    }
}

IOCType stringToIOCType(const std::string& str) {
    std::string s = toUpper(trim(str));
    if (s == "IPV4" || s == "IP")          return IOCType::IPV4;
    if (s == "IPV4_CIDR" || s == "CIDR")   return IOCType::IPV4_CIDR;
    if (s == "DOMAIN" || s == "DOMAIN_NAME") return IOCType::DOMAIN_NAME;
    if (s == "DNS" || s == "DNS_NAME")     return IOCType::DNS_NAME;
    if (s == "TLS_SNI" || s == "SNI")      return IOCType::TLS_SNI;
    if (s == "URL")                        return IOCType::URL;
    if (s == "FILE_HASH" || s == "HASH")   return IOCType::FILE_HASH;
    return IOCType::UNKNOWN;
}

std::string iocConfidenceToString(IOCConfidence conf) {
    switch (conf) {
        case IOCConfidence::LOW:    return "LOW";
        case IOCConfidence::MEDIUM: return "MEDIUM";
        case IOCConfidence::HIGH:   return "HIGH";
        default:                    return "MEDIUM";
    }
}

IOCConfidence stringToIOCConfidence(const std::string& str) {
    std::string s = toUpper(trim(str));
    if (s == "HIGH")   return IOCConfidence::HIGH;
    if (s == "LOW")    return IOCConfidence::LOW;
    return IOCConfidence::MEDIUM;
}

std::string iocSeverityToString(IOCSeverity sev) {
    switch (sev) {
        case IOCSeverity::INFO:     return "INFO";
        case IOCSeverity::LOW:      return "LOW";
        case IOCSeverity::MEDIUM:   return "MEDIUM";
        case IOCSeverity::HIGH:     return "HIGH";
        case IOCSeverity::CRITICAL: return "CRITICAL";
        default:                    return "MEDIUM";
    }
}

IOCSeverity stringToIOCSeverity(const std::string& str) {
    std::string s = toUpper(trim(str));
    if (s == "CRITICAL") return IOCSeverity::CRITICAL;
    if (s == "HIGH")     return IOCSeverity::HIGH;
    if (s == "LOW")      return IOCSeverity::LOW;
    if (s == "INFO")     return IOCSeverity::INFO;
    return IOCSeverity::MEDIUM;
}

std::string threatMatchTypeToString(ThreatMatchType match_type) {
    switch (match_type) {
        case ThreatMatchType::EXACT_IP:        return "EXACT_IP";
        case ThreatMatchType::CIDR_IP:         return "CIDR_IP";
        case ThreatMatchType::EXACT_DOMAIN:    return "EXACT_DOMAIN";
        case ThreatMatchType::SUBDOMAIN:       return "SUBDOMAIN";
        case ThreatMatchType::DNS_QUERY:       return "DNS_QUERY";
        case ThreatMatchType::DNS_RESPONSE_IP: return "DNS_RESPONSE_IP";
        case ThreatMatchType::TLS_SNI:         return "TLS_SNI";
        case ThreatMatchType::HTTP_HOST:       return "HTTP_HOST";
        case ThreatMatchType::HTTP_URI:        return "HTTP_URI";
        case ThreatMatchType::HTTP_URL:        return "HTTP_URL";
        default:                               return "UNKNOWN";
    }
}

ThreatMatchType stringToThreatMatchType(const std::string& str) {
    std::string s = toUpper(trim(str));
    if (s == "EXACT_IP")        return ThreatMatchType::EXACT_IP;
    if (s == "CIDR_IP")         return ThreatMatchType::CIDR_IP;
    if (s == "EXACT_DOMAIN")    return ThreatMatchType::EXACT_DOMAIN;
    if (s == "SUBDOMAIN")       return ThreatMatchType::SUBDOMAIN;
    if (s == "DNS_QUERY")       return ThreatMatchType::DNS_QUERY;
    if (s == "DNS_RESPONSE_IP") return ThreatMatchType::DNS_RESPONSE_IP;
    if (s == "TLS_SNI")         return ThreatMatchType::TLS_SNI;
    if (s == "HTTP_HOST")       return ThreatMatchType::HTTP_HOST;
    if (s == "HTTP_URI")        return ThreatMatchType::HTTP_URI;
    if (s == "HTTP_URL")        return ThreatMatchType::HTTP_URL;
    return ThreatMatchType::UNKNOWN;
}

// ============================================================================
// ThreatIOC Implementation
// ============================================================================

bool ThreatIOC::isExpired(uint64_t current_time_us) const {
    if (expiration_timestamp == 0) return false;
    if (current_time_us == 0) return false;
    // expiration_timestamp may be in seconds or microseconds
    uint64_t exp_us = (expiration_timestamp < 10000000000ULL)
                          ? (expiration_timestamp * 1000000ULL)
                          : expiration_timestamp;
    return current_time_us > exp_us;
}

bool ThreatIOC::matchesIPv4(uint32_t candidate_ip) const {
    if (type == IOCType::IPV4) {
        return candidate_ip == parsed_ip;
    }
    if (type == IOCType::IPV4_CIDR) {
        if (prefix_len == 0) return true;
        uint32_t cand_net = toNetworkOrder(candidate_ip);
        uint32_t base_net = toNetworkOrder(parsed_ip);
        return (cand_net & net_mask) == (base_net & net_mask);
    }
    return false;
}

bool ThreatIOC::matchesDomain(const std::string& candidate_domain_raw) const {
    if (type != IOCType::DOMAIN_NAME && type != IOCType::DNS_NAME && type != IOCType::TLS_SNI) {
        return false;
    }
    std::string cand = toLower(trim(candidate_domain_raw));
    if (!cand.empty() && cand.back() == '.') cand.pop_back();
    if (cand.empty()) return false;

    const std::string& target = normalized_domain;
    if (target.empty()) return false;

    // Exact match
    if (cand == target) return true;

    // Subdomain boundary match: cand must end with "." + target
    if (cand.size() > target.size() + 1) {
        size_t offset = cand.size() - target.size();
        if (cand[offset - 1] == '.' && cand.compare(offset, target.size(), target) == 0) {
            return true;
        }
    }
    return false;
}

bool ThreatIOC::matchesURL(const std::string& host_raw, const std::string& uri_raw) const {
    if (type != IOCType::URL) return false;
    std::string h = toLower(trim(host_raw));
    if (!h.empty() && h.back() == '.') h.pop_back();

    // If IOC has url_host specified, verify host
    if (!url_host.empty() && h != url_host) {
        // Also check if h is a subdomain of url_host
        if (h.size() <= url_host.size() + 1 ||
            h[h.size() - url_host.size() - 1] != '.' ||
            h.compare(h.size() - url_host.size(), url_host.size(), url_host) != 0) {
            return false;
        }
    }

    // Verify URL path prefix/substring
    if (!url_path.empty()) {
        std::string u = uri_raw;
        // Search path within uri
        if (u.find(url_path) == std::string::npos) {
            return false;
        }
    }

    return true;
}

std::string ThreatIOC::toJson(int indent) const {
    std::string ind(indent, ' ');
    std::ostringstream ss;
    ss << ind << "{\n";
    ss << ind << "  \"ioc_id\": \"" << escapeJson(ioc_id) << "\",\n";
    ss << ind << "  \"dataset_id\": \"" << escapeJson(dataset_id) << "\",\n";
    ss << ind << "  \"type\": \"" << iocTypeToString(type) << "\",\n";
    ss << ind << "  \"value\": \"" << escapeJson(value) << "\",\n";
    ss << ind << "  \"raw_value\": \"" << escapeJson(raw_value) << "\",\n";
    ss << ind << "  \"confidence\": \"" << iocConfidenceToString(confidence) << "\",\n";
    ss << ind << "  \"severity\": \"" << iocSeverityToString(severity) << "\",\n";
    ss << ind << "  \"category\": \"" << escapeJson(category) << "\",\n";
    ss << ind << "  \"description\": \"" << escapeJson(description) << "\",\n";
    ss << ind << "  \"enabled\": " << (enabled ? "true" : "false") << ",\n";
    ss << ind << "  \"tags\": [";
    for (size_t i = 0; i < tags.size(); ++i) {
        ss << "\"" << escapeJson(tags[i]) << "\"" << (i + 1 < tags.size() ? ", " : "");
    }
    ss << "],\n";
    ss << ind << "  \"references\": [";
    for (size_t i = 0; i < reference_metadata.size(); ++i) {
        ss << "\"" << escapeJson(reference_metadata[i]) << "\"" << (i + 1 < reference_metadata.size() ? ", " : "");
    }
    ss << "],\n";
    ss << ind << "  \"first_seen_timestamp\": " << first_seen_timestamp << ",\n";
    ss << ind << "  \"last_seen_timestamp\": " << last_seen_timestamp << ",\n";
    ss << ind << "  \"expiration_timestamp\": " << expiration_timestamp << ",\n";
    ss << ind << "  \"analyst_notes\": \"" << escapeJson(analyst_notes) << "\"\n";
    ss << ind << "}";
    return ss.str();
}

// ============================================================================
// ThreatDataset Implementation
// ============================================================================

bool ThreatDataset::isExpired(uint64_t current_time_us) const {
    if (expiration_timestamp == 0) return false;
    if (current_time_us == 0) return false;
    uint64_t exp_us = (expiration_timestamp < 10000000000ULL)
                          ? (expiration_timestamp * 1000000ULL)
                          : expiration_timestamp;
    return current_time_us > exp_us;
}

size_t ThreatDataset::activeIOCCount() const {
    size_t count = 0;
    for (const auto& ioc : iocs) {
        if (ioc.enabled) count++;
    }
    return count;
}

std::string ThreatDataset::toJson(int indent) const {
    std::string ind(indent, ' ');
    std::ostringstream ss;
    ss << ind << "{\n";
    ss << ind << "  \"dataset_id\": \"" << escapeJson(dataset_id) << "\",\n";
    ss << ind << "  \"name\": \"" << escapeJson(name) << "\",\n";
    ss << ind << "  \"version\": \"" << escapeJson(version) << "\",\n";
    ss << ind << "  \"schema_version\": \"" << escapeJson(schema_version) << "\",\n";
    ss << ind << "  \"source_description\": \"" << escapeJson(source_description) << "\",\n";
    ss << ind << "  \"source_url\": \"" << escapeJson(source_url) << "\",\n";
    ss << ind << "  \"created_timestamp\": " << created_timestamp << ",\n";
    ss << ind << "  \"expiration_timestamp\": " << expiration_timestamp << ",\n";
    ss << ind << "  \"enabled\": " << (enabled ? "true" : "false") << ",\n";
    ss << ind << "  \"ioc_count\": " << iocs.size() << ",\n";
    ss << ind << "  \"active_ioc_count\": " << activeIOCCount() << ",\n";
    ss << ind << "  \"iocs\": [\n";
    for (size_t i = 0; i < iocs.size(); ++i) {
        ss << iocs[i].toJson(indent + 4) << (i + 1 < iocs.size() ? ",\n" : "\n");
    }
    ss << ind << "  ]\n";
    ss << ind << "}";
    return ss.str();
}

// ============================================================================
// ThreatMatchEvent Implementation
// ============================================================================

std::string ThreatMatchEvent::toJson(int indent) const {
    std::string ind(indent, ' ');
    std::ostringstream ss;
    ss << ind << "{\n";
    ss << ind << "  \"event_id\": \"" << escapeJson(event_id) << "\",\n";
    ss << ind << "  \"schema_version\": \"" << escapeJson(schema_version) << "\",\n";
    ss << ind << "  \"dataset_id\": \"" << escapeJson(dataset_id) << "\",\n";
    ss << ind << "  \"dataset_version\": \"" << escapeJson(dataset_version) << "\",\n";
    ss << ind << "  \"ioc_id\": \"" << escapeJson(ioc_id) << "\",\n";
    ss << ind << "  \"ioc_type\": \"" << iocTypeToString(ioc_type) << "\",\n";
    ss << ind << "  \"ioc_value\": \"" << escapeJson(ioc_value) << "\",\n";
    ss << ind << "  \"observed_value\": \"" << escapeJson(observed_value) << "\",\n";
    ss << ind << "  \"match_type\": \"" << threatMatchTypeToString(match_type) << "\",\n";
    ss << ind << "  \"match_timestamp_us\": " << match_timestamp_us << ",\n";
    ss << ind << "  \"src_ip\": \"" << escapeJson(src_ip) << "\",\n";
    ss << ind << "  \"dst_ip\": \"" << escapeJson(dst_ip) << "\",\n";
    ss << ind << "  \"src_port\": " << src_port << ",\n";
    ss << ind << "  \"dst_port\": " << dst_port << ",\n";
    ss << ind << "  \"protocol\": \"" << escapeJson(protocol) << "\",\n";
    ss << ind << "  \"direction\": \"" << escapeJson(direction) << "\",\n";
    ss << ind << "  \"flow_id\": " << flow_id << ",\n";
    ss << ind << "  \"related_incident_id\": \"" << escapeJson(related_incident_id) << "\",\n";
    ss << ind << "  \"confidence\": \"" << iocConfidenceToString(confidence) << "\",\n";
    ss << ind << "  \"severity\": \"" << iocSeverityToString(severity) << "\",\n";
    ss << ind << "  \"category\": \"" << escapeJson(category) << "\",\n";
    ss << ind << "  \"evidence\": \"" << escapeJson(evidence) << "\",\n";
    ss << ind << "  \"match_explanation\": \"" << escapeJson(match_explanation) << "\",\n";
    ss << ind << "  \"tags\": [";
    for (size_t i = 0; i < tags.size(); ++i) {
        ss << "\"" << escapeJson(tags[i]) << "\"" << (i + 1 < tags.size() ? ", " : "");
    }
    ss << "],\n";
    ss << ind << "  \"related_detection_ids\": [";
    for (size_t i = 0; i < related_detection_ids.size(); ++i) {
        ss << "\"" << escapeJson(related_detection_ids[i]) << "\"" << (i + 1 < related_detection_ids.size() ? ", " : "");
    }
    ss << "],\n";
    ss << ind << "  \"related_signature_ids\": [";
    for (size_t i = 0; i < related_signature_ids.size(); ++i) {
        ss << "\"" << escapeJson(related_signature_ids[i]) << "\"" << (i + 1 < related_signature_ids.size() ? ", " : "");
    }
    ss << "],\n";
    ss << ind << "  \"limitations\": [";
    for (size_t i = 0; i < limitations.size(); ++i) {
        ss << "\"" << escapeJson(limitations[i]) << "\"" << (i + 1 < limitations.size() ? ", " : "");
    }
    ss << "],\n";
    ss << ind << "  \"recommended_actions\": [";
    for (size_t i = 0; i < recommended_actions.size(); ++i) {
        ss << "\"" << escapeJson(recommended_actions[i]) << "\"" << (i + 1 < recommended_actions.size() ? ", " : "");
    }
    ss << "]\n";
    ss << ind << "}";
    return ss.str();
}

std::string ThreatMatchEvent::csvHeader() {
    return "event_id,schema_version,dataset_id,dataset_version,ioc_id,ioc_type,ioc_value,observed_value,"
           "match_type,match_timestamp_us,src_ip,dst_ip,src_port,dst_port,protocol,direction,flow_id,"
           "related_incident_id,confidence,severity,category,evidence,match_explanation";
}

static inline std::string escapeCsv(const std::string& field) {
    std::string out = "\"";
    for (char c : field) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += "\"";
    return out;
}

std::string ThreatMatchEvent::toCsvRow() const {
    std::ostringstream ss;
    ss << escapeCsv(event_id) << ","
       << escapeCsv(schema_version) << ","
       << escapeCsv(dataset_id) << ","
       << escapeCsv(dataset_version) << ","
       << escapeCsv(ioc_id) << ","
       << escapeCsv(iocTypeToString(ioc_type)) << ","
       << escapeCsv(ioc_value) << ","
       << escapeCsv(observed_value) << ","
       << escapeCsv(threatMatchTypeToString(match_type)) << ","
       << match_timestamp_us << ","
       << escapeCsv(src_ip) << ","
       << escapeCsv(dst_ip) << ","
       << src_port << ","
       << dst_port << ","
       << escapeCsv(protocol) << ","
       << escapeCsv(direction) << ","
       << flow_id << ","
       << escapeCsv(related_incident_id) << ","
       << escapeCsv(iocConfidenceToString(confidence)) << ","
       << escapeCsv(iocSeverityToString(severity)) << ","
       << escapeCsv(category) << ","
       << escapeCsv(evidence) << ","
       << escapeCsv(match_explanation);
    return ss.str();
}

} // namespace DPI
