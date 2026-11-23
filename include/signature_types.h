#ifndef DPI_SIGNATURE_TYPES_H
#define DPI_SIGNATURE_TYPES_H

#include "types.h"
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <cstdint>
#include <sstream>
#include <iomanip>

namespace DPI {

// ============================================================================
// Enums
// ============================================================================

enum class SignatureSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

std::string signatureSeverityToString(SignatureSeverity severity);
SignatureSeverity stringToSignatureSeverity(const std::string& str);

enum class SignatureCategory {
    MALWARE,
    EXPLOIT,
    SCANNER,
    POLICY_VIOLATION,
    INFO,
    SUSPICIOUS_TRAFFIC,
    DATA_LEAK,
    DOS
};

std::string signatureCategoryToString(SignatureCategory cat);
SignatureCategory stringToSignatureCategory(const std::string& str);

enum class RuleProtocol {
    ANY,
    TCP,
    UDP,
    IP
};

std::string ruleProtocolToString(RuleProtocol proto);
RuleProtocol stringToRuleProtocol(const std::string& str);

enum class RuleDirection {
    FORWARD,      // Source -> Destination
    REVERSE,      // Destination -> Source
    BIDIRECTIONAL // Either direction
};

std::string ruleDirectionToString(RuleDirection dir);
RuleDirection stringToRuleDirection(const std::string& str);

enum class FlowStateCriteria {
    ANY,
    NEW,
    ESTABLISHED,
    CLOSED,
    RESET
};

std::string flowStateCriteriaToString(FlowStateCriteria state);
FlowStateCriteria stringToFlowStateCriteria(const std::string& str);

enum class StreamDirection {
    FWD_ONLY,
    REV_ONLY,
    EITHER,
    BOTH
};

std::string streamDirectionToString(StreamDirection dir);
StreamDirection stringToStreamDirection(const std::string& str);

enum class MatchScope {
    PACKET,
    FLOW,
    STREAM,
    HTTP,
    TLS,
    DNS,
    MULTI
};

std::string matchScopeToString(MatchScope scope);

// ============================================================================
// Network Criteria Support: PortRange and IPNet (CIDR)
// ============================================================================

struct PortRange {
    uint16_t min_port = 1;
    uint16_t max_port = 65535;

    bool matches(uint16_t port) const {
        return port >= min_port && port <= max_port;
    }

    static PortRange single(uint16_t port) {
        return {port, port};
    }

    static PortRange any() {
        return {1, 65535};
    }

    static PortRange parse(const std::string& str);
    std::string toString() const;
};

struct IPNet {
    uint32_t ip = 0;          // Little-endian representation consistent with FiveTuple
    uint8_t prefix_len = 32;  // 0 to 32

    bool matches(uint32_t candidate_ip) const;
    static IPNet parse(const std::string& cidr_str);
    std::string toString() const;
};

// ============================================================================
// Stream Pattern Condition
// ============================================================================

struct PatternCondition {
    std::string pattern;             // Original string / pattern spec
    bool is_hex = false;             // If true, decoded from hex
    std::vector<uint8_t> bytes;      // Raw byte needle to search
    bool nocase = false;             // Case-insensitive ASCII search
    int32_t offset = -1;             // Start search offset (-1 = anywhere)
    int32_t depth = 0;               // Search depth limit (0 = unlimited)
    int32_t relative_distance = -1;  // Distance from previous pattern match end
    int32_t relative_within = 0;     // Must match within N bytes of previous match
    bool negated = false;            // Condition satisfied if NOT found
    StreamDirection direction = StreamDirection::EITHER;

    bool decodeHex();
};

// ============================================================================
// Condition Blocks
// ============================================================================

struct NetworkCriteria {
    RuleProtocol protocol = RuleProtocol::ANY;
    std::vector<IPNet> src_ips;
    std::vector<IPNet> dst_ips;
    std::vector<PortRange> src_ports;
    std::vector<PortRange> dst_ports;
    RuleDirection direction = RuleDirection::BIDIRECTIONAL;
    uint8_t tcp_flags_mask = 0;
    uint8_t tcp_flags_value = 0;
    uint32_t packet_size_min = 0;
    uint32_t packet_size_max = 0;

    bool has_criteria() const {
        return protocol != RuleProtocol::ANY || !src_ips.empty() || !dst_ips.empty() ||
               !src_ports.empty() || !dst_ports.empty() || tcp_flags_mask != 0 ||
               packet_size_min > 0 || packet_size_max > 0;
    }
};

struct FlowCriteria {
    FlowStateCriteria flow_state = FlowStateCriteria::ANY;
    uint64_t min_bytes = 0;
    uint64_t max_bytes = 0;
    uint64_t min_packets = 0;
    uint64_t max_packets = 0;
    double min_duration_sec = 0.0;
    double max_duration_sec = 0.0;
    double min_asymmetry_ratio = 0.0;

    bool has_criteria() const {
        return flow_state != FlowStateCriteria::ANY || min_bytes > 0 || max_bytes > 0 ||
               min_packets > 0 || max_packets > 0 || min_duration_sec > 0.0 ||
               max_duration_sec > 0.0 || min_asymmetry_ratio > 0.0;
    }
};

struct StreamContentCriteria {
    std::vector<PatternCondition> patterns;

    bool has_criteria() const {
        return !patterns.empty();
    }
};

struct HTTPCriteria {
    std::string method;
    std::string host;
    std::string uri;
    std::string user_agent;
    std::map<std::string, std::string> headers;
    int status_code = 0;

    bool has_criteria() const {
        return !method.empty() || !host.empty() || !uri.empty() ||
               !user_agent.empty() || !headers.empty() || status_code != 0;
    }
};

struct TLSCriteria {
    std::string sni;
    std::string alpn;
    std::string version;
    uint16_t cipher_suite = 0;

    bool has_criteria() const {
        return !sni.empty() || !alpn.empty() || !version.empty() || cipher_suite != 0;
    }
};

struct DNSCriteria {
    std::string query_name;
    uint16_t query_type = 0;
    int rcode = -1;
    std::optional<bool> is_nxdomain;
    double min_entropy = 0.0;

    bool has_criteria() const {
        return !query_name.empty() || query_type != 0 || rcode != -1 ||
               is_nxdomain.has_value() || min_entropy > 0.0;
    }
};

// ============================================================================
// Signature Rule Schema v1.0
// ============================================================================

struct SignatureRule {
    std::string rule_id;
    std::string schema_version = "1.0";
    std::string name;
    uint32_t revision = 1;
    SignatureCategory category = SignatureCategory::MALWARE;
    SignatureSeverity severity = SignatureSeverity::MEDIUM;
    std::string description;
    bool enabled = true;
    uint32_t match_limit = 0; // 0 = unlimited

    std::vector<std::string> tags;
    std::vector<std::string> references;
    std::map<std::string, std::string> metadata;

    NetworkCriteria network;
    FlowCriteria flow;
    StreamContentCriteria stream_content;
    HTTPCriteria http;
    TLSCriteria tls;
    DNSCriteria dns;

    bool hasCriteria() const {
        return network.has_criteria() || flow.has_criteria() ||
               stream_content.has_criteria() || http.has_criteria() ||
               tls.has_criteria() || dns.has_criteria();
    }

    std::string toJson() const;
};

// ============================================================================
// Signature Event Schema v1.0
// ============================================================================

struct SignatureEvent {
    std::string event_id;
    std::string schema_version = "1.0";
    std::string rule_id;
    std::string rule_name;
    uint32_t rule_revision = 1;
    SignatureCategory category = SignatureCategory::MALWARE;
    SignatureSeverity severity = SignatureSeverity::MEDIUM;
    
    uint64_t timestamp_us = 0;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::string protocol;       // "TCP", "UDP"
    std::string direction = "FORWARD";
    
    uint64_t flow_id = 0;
    std::string incident_id;    // Associated Phase 3.3 incident ID if correlated
    
    MatchScope match_scope = MatchScope::FLOW;
    std::string match_details;
    std::string matched_pattern;
    int64_t match_offset = -1;
    std::string evidence;
    std::string confidence = "HIGH";
    
    std::map<std::string, std::string> metadata;
    std::vector<std::string> limitations;

    std::string toJson(int indent = 2) const;
    std::string toCsvRow() const;
    static std::string csvHeader();
};

// ============================================================================
// Rule Match Result
// ============================================================================

struct RuleMatchResult {
    bool matched = false;
    MatchScope scope = MatchScope::FLOW;
    std::string details;
    std::string pattern;
    int64_t offset = -1;
    std::string evidence;
    std::string direction = "FORWARD";
};

} // namespace DPI

#endif // DPI_SIGNATURE_TYPES_H
