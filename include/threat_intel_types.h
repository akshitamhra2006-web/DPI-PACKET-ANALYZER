#ifndef DPI_THREAT_INTEL_TYPES_H
#define DPI_THREAT_INTEL_TYPES_H

#include "types.h"
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <optional>

namespace DPI {

#ifdef DOMAIN
#undef DOMAIN
#endif

// ============================================================================
// IOC Types
// ============================================================================
enum class IOCType {
    IPV4,
    IPV4_CIDR,
    DOMAIN_NAME,
    DNS_NAME,
    TLS_SNI,
    URL,
    FILE_HASH, // Documented limitation: validated & tracked, but packet fragments are not hashed
    UNKNOWN
};

std::string iocTypeToString(IOCType type);
IOCType stringToIOCType(const std::string& str);

// ============================================================================
// IOC Confidence Levels
// ============================================================================
enum class IOCConfidence {
    LOW,
    MEDIUM,
    HIGH
};

std::string iocConfidenceToString(IOCConfidence conf);
IOCConfidence stringToIOCConfidence(const std::string& str);

// ============================================================================
// IOC Severity Levels
// ============================================================================
enum class IOCSeverity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

std::string iocSeverityToString(IOCSeverity sev);
IOCSeverity stringToIOCSeverity(const std::string& str);

// ============================================================================
// Threat Match Types
// ============================================================================
enum class ThreatMatchType {
    EXACT_IP,
    CIDR_IP,
    EXACT_DOMAIN,
    SUBDOMAIN,
    DNS_QUERY,
    DNS_RESPONSE_IP,
    TLS_SNI,
    HTTP_HOST,
    HTTP_URI,
    HTTP_URL,
    UNKNOWN
};

std::string threatMatchTypeToString(ThreatMatchType match_type);
ThreatMatchType stringToThreatMatchType(const std::string& str);

// ============================================================================
// Threat IOC Record (Within a Dataset)
// ============================================================================
struct ThreatIOC {
    std::string ioc_id;
    std::string dataset_id;
    IOCType type = IOCType::UNKNOWN;
    std::string value;               // Normalized value
    std::string raw_value;           // Original value as supplied in dataset
    IOCConfidence confidence = IOCConfidence::MEDIUM;
    IOCSeverity severity = IOCSeverity::MEDIUM;
    std::vector<std::string> tags;
    std::string category = "SUSPICIOUS"; // C2, PHISHING, SCANNER, MALWARE, EXFIL, etc.
    std::string description;
    std::vector<std::string> reference_metadata;
    uint64_t first_seen_timestamp = 0;
    uint64_t last_seen_timestamp = 0;
    uint64_t expiration_timestamp = 0; // 0 = no expiration
    bool enabled = true;
    std::string analyst_notes;

    // Compiled / Parsed Fields for Fast Lookups
    uint32_t parsed_ip = 0;          // Host-byte order or consistent representation
    uint8_t prefix_len = 32;         // For IPV4_CIDR
    uint32_t net_mask = 0xFFFFFFFFU; // For IPV4_CIDR
    std::string normalized_domain;   // Lowercase, trailing dot stripped
    bool is_wildcard_domain = false; // True if specified as *.domain.com
    std::string url_host;            // Extracted host for URL IOC
    std::string url_path;            // Extracted path for URL IOC

    // Matching Helpers
    bool isExpired(uint64_t current_time_us = 0) const;
    bool matchesIPv4(uint32_t ip) const;
    bool matchesDomain(const std::string& candidate_domain) const;
    bool matchesURL(const std::string& host, const std::string& uri) const;

    std::string toJson(int indent = 4) const;
};

// ============================================================================
// Threat Intelligence Dataset
// ============================================================================
struct ThreatDataset {
    std::string dataset_id;
    std::string name;
    std::string version = "1.0";
    std::string schema_version = "1.0";
    std::string source_description;
    std::string source_url; // Metadata only
    uint64_t created_timestamp = 0;
    uint64_t expiration_timestamp = 0; // 0 = no expiration
    bool enabled = true;
    std::string filepath;

    std::vector<ThreatIOC> iocs;

    bool isExpired(uint64_t current_time_us = 0) const;
    size_t activeIOCCount() const;
    std::string toJson(int indent = 2) const;
};

// ============================================================================
// Threat Match Event Schema v1.0
// ============================================================================
struct ThreatMatchEvent {
    std::string event_id;
    std::string schema_version = "1.0";
    std::string dataset_id;
    std::string dataset_version;
    std::string ioc_id;
    IOCType ioc_type = IOCType::UNKNOWN;
    std::string ioc_value;
    std::string observed_value;
    ThreatMatchType match_type = ThreatMatchType::UNKNOWN;
    uint64_t match_timestamp_us = 0;

    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::string protocol;       // "TCP", "UDP"
    std::string direction = "FORWARD";

    uint64_t flow_id = 0;
    std::vector<std::string> related_detection_ids;
    std::vector<std::string> related_signature_ids;
    std::string related_incident_id;

    IOCConfidence confidence = IOCConfidence::MEDIUM;
    IOCSeverity severity = IOCSeverity::MEDIUM;
    std::vector<std::string> tags;
    std::string category;
    std::string evidence;
    std::string match_explanation;
    std::vector<std::string> limitations;
    std::vector<std::string> recommended_actions;

    std::string toJson(int indent = 2) const;
    std::string toCsvRow() const;
    static std::string csvHeader();
};

// ============================================================================
// Threat Intelligence Engine Configuration
// ============================================================================
struct ThreatIntelConfig {
    bool enable_threat_intel = false;
    std::string dataset_file;
    std::string dataset_dir;
    bool show_stats = false;
    std::string export_json_file;
    std::string export_csv_file;
    uint32_t max_matches = 10000;
    uint64_t reference_time_us = 0; // For expiration checking (0 = disabled/current)
    bool allow_expired_iocs = false; // If true, matches expired IOCs with warning
};

} // namespace DPI

#endif // DPI_THREAT_INTEL_TYPES_H
