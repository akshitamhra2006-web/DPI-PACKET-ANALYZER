#ifndef DPI_INCIDENT_TYPES_H
#define DPI_INCIDENT_TYPES_H

#include "types.h"
#include "detection_types.h"
#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <sstream>

namespace DPI {

// ============================================================================
// Incident Category
// ============================================================================
enum class IncidentCategory {
    RECONNAISSANCE,
    DNS_SUSPICIOUS_ACTIVITY,
    SUSPICIOUS_OUTBOUND_COMMUNICATION,
    POTENTIAL_DATA_EXFILTRATION,
    MULTI_STAGE_ACTIVITY,
    TCP_ANOMALY_CLUSTER,
    OTHER
};

std::string incidentCategoryToString(IncidentCategory category);
IncidentCategory stringToIncidentCategory(const std::string& str);

// ============================================================================
// Incident Severity
// ============================================================================
enum class IncidentSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

std::string incidentSeverityToString(IncidentSeverity severity);
IncidentSeverity stringToIncidentSeverity(const std::string& str);

// ============================================================================
// Incident Confidence
// ============================================================================
enum class IncidentConfidence {
    LOW,
    MEDIUM,
    HIGH
};

std::string incidentConfidenceToString(IncidentConfidence confidence);
IncidentConfidence stringToIncidentConfidence(const std::string& str);

// ============================================================================
// Incident Status (Analytical only)
// ============================================================================
enum class IncidentStatus {
    NEW,
    OBSERVED,
    REVIEW_REQUIRED
};

std::string incidentStatusToString(IncidentStatus status);
IncidentStatus stringToIncidentStatus(const std::string& str);

// ============================================================================
// Timeline Event
// ============================================================================
struct TimelineEvent {
    uint64_t timestamp_us = 0;
    std::string timestamp_iso;
    std::string event_type; // DETECTION, FLOW_START, FLOW_END, STAGE_TRANSITION, PROTOCOL_METADATA
    std::string endpoint;
    uint64_t flow_id = 0;
    std::string detection_id;
    std::string description;
    std::map<std::string, std::string> observed_values;
    std::string source; // e.g. "detector:port_scan", "flow_table", "dns_correlator"

    std::string toJson(int indent = 4) const;
};

// ============================================================================
// Security Incident Record
// ============================================================================
struct SecurityIncident {
    std::string schema_version = "1.0";
    std::string incident_id; // e.g. "INC-0001"
    IncidentCategory category = IncidentCategory::OTHER;
    std::string title;
    IncidentSeverity severity = IncidentSeverity::LOW;
    IncidentConfidence confidence = IncidentConfidence::LOW;
    std::string confidence_explanation;

    // Numerical correlation score
    double correlation_score = 0.0;

    // Timing
    uint64_t first_seen_us = 0;
    uint64_t last_seen_us = 0;
    std::string first_seen_iso;
    std::string last_seen_iso;
    double duration_seconds = 0.0;

    // Endpoints & Scope
    std::string primary_endpoint;
    std::vector<std::string> related_endpoints;
    std::vector<uint16_t> related_ports;

    // Correlated Identifiers
    std::vector<uint64_t> related_flow_ids;
    std::vector<std::string> related_detection_ids;
    std::vector<std::string> related_signature_ids;
    std::vector<std::string> related_ioc_ids;

    // Chronological Evidence Timeline
    std::vector<TimelineEvent> timeline;

    // Structured Evidence & Metrics
    std::vector<std::string> evidence_descriptions;
    std::vector<std::string> threat_intel_summaries;
    std::map<std::string, std::string> observed_metrics;

    // Rule & Provenance
    std::vector<std::string> correlation_rules_triggered;
    std::string rule_version = "1.0";

    // Investigative Guidance & Operational Limitations
    std::vector<std::string> limitations;
    std::vector<std::string> recommended_investigation_steps;

    // Analytical Status
    IncidentStatus status = IncidentStatus::NEW;

    // Serialization
    std::string toJson(int indent = 2) const;
    std::string toCsvRow() const;
    static std::string csvHeader();
};

} // namespace DPI

#endif // DPI_INCIDENT_TYPES_H
