#include "incident_types.h"
#include <iomanip>
#include <sstream>

namespace DPI {

// ============================================================================
// String Conversion Helpers
// ============================================================================

std::string incidentCategoryToString(IncidentCategory category) {
    switch (category) {
        case IncidentCategory::RECONNAISSANCE:
            return "RECONNAISSANCE";
        case IncidentCategory::DNS_SUSPICIOUS_ACTIVITY:
            return "DNS_SUSPICIOUS_ACTIVITY";
        case IncidentCategory::SUSPICIOUS_OUTBOUND_COMMUNICATION:
            return "SUSPICIOUS_OUTBOUND_COMMUNICATION";
        case IncidentCategory::POTENTIAL_DATA_EXFILTRATION:
            return "POTENTIAL_DATA_EXFILTRATION";
        case IncidentCategory::MULTI_STAGE_ACTIVITY:
            return "MULTI_STAGE_ACTIVITY";
        case IncidentCategory::TCP_ANOMALY_CLUSTER:
            return "TCP_ANOMALY_CLUSTER";
        case IncidentCategory::OTHER:
        default:
            return "OTHER";
    }
}

IncidentCategory stringToIncidentCategory(const std::string& str) {
    if (str == "RECONNAISSANCE") return IncidentCategory::RECONNAISSANCE;
    if (str == "DNS_SUSPICIOUS_ACTIVITY") return IncidentCategory::DNS_SUSPICIOUS_ACTIVITY;
    if (str == "SUSPICIOUS_OUTBOUND_COMMUNICATION") return IncidentCategory::SUSPICIOUS_OUTBOUND_COMMUNICATION;
    if (str == "POTENTIAL_DATA_EXFILTRATION") return IncidentCategory::POTENTIAL_DATA_EXFILTRATION;
    if (str == "MULTI_STAGE_ACTIVITY") return IncidentCategory::MULTI_STAGE_ACTIVITY;
    if (str == "TCP_ANOMALY_CLUSTER") return IncidentCategory::TCP_ANOMALY_CLUSTER;
    return IncidentCategory::OTHER;
}

std::string incidentSeverityToString(IncidentSeverity severity) {
    switch (severity) {
        case IncidentSeverity::CRITICAL: return "CRITICAL";
        case IncidentSeverity::HIGH: return "HIGH";
        case IncidentSeverity::MEDIUM: return "MEDIUM";
        case IncidentSeverity::LOW:
        default:
            return "LOW";
    }
}

IncidentSeverity stringToIncidentSeverity(const std::string& str) {
    if (str == "CRITICAL") return IncidentSeverity::CRITICAL;
    if (str == "HIGH") return IncidentSeverity::HIGH;
    if (str == "MEDIUM") return IncidentSeverity::MEDIUM;
    return IncidentSeverity::LOW;
}

std::string incidentConfidenceToString(IncidentConfidence confidence) {
    switch (confidence) {
        case IncidentConfidence::HIGH: return "HIGH";
        case IncidentConfidence::MEDIUM: return "MEDIUM";
        case IncidentConfidence::LOW:
        default:
            return "LOW";
    }
}

IncidentConfidence stringToIncidentConfidence(const std::string& str) {
    if (str == "HIGH") return IncidentConfidence::HIGH;
    if (str == "MEDIUM") return IncidentConfidence::MEDIUM;
    return IncidentConfidence::LOW;
}

std::string incidentStatusToString(IncidentStatus status) {
    switch (status) {
        case IncidentStatus::OBSERVED: return "OBSERVED";
        case IncidentStatus::REVIEW_REQUIRED: return "REVIEW_REQUIRED";
        case IncidentStatus::NEW:
        default:
            return "NEW";
    }
}

IncidentStatus stringToIncidentStatus(const std::string& str) {
    if (str == "OBSERVED") return IncidentStatus::OBSERVED;
    if (str == "REVIEW_REQUIRED") return IncidentStatus::REVIEW_REQUIRED;
    return IncidentStatus::NEW;
}

static std::string escapeJson(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        if (c == '"') o << "\\\"";
        else if (c == '\\') o << "\\\\";
        else if (c == '\b') o << "\\b";
        else if (c == '\f') o << "\\f";
        else if (c == '\n') o << "\\n";
        else if (c == '\r') o << "\\r";
        else if (c == '\t') o << "\\t";
        else if (static_cast<unsigned char>(c) <= 0x1f) {
            o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
        } else {
            o << c;
        }
    }
    return o.str();
}

// ============================================================================
// TimelineEvent Serialization
// ============================================================================

std::string TimelineEvent::toJson(int indent) const {
    std::string ind(indent, ' ');
    std::ostringstream ss;
    ss << ind << "{\n";
    ss << ind << "  \"timestamp_us\": " << timestamp_us << ",\n";
    ss << ind << "  \"timestamp_iso\": \"" << escapeJson(timestamp_iso) << "\",\n";
    ss << ind << "  \"event_type\": \"" << escapeJson(event_type) << "\",\n";
    ss << ind << "  \"endpoint\": \"" << escapeJson(endpoint) << "\",\n";
    ss << ind << "  \"flow_id\": " << flow_id << ",\n";
    ss << ind << "  \"detection_id\": \"" << escapeJson(detection_id) << "\",\n";
    ss << ind << "  \"description\": \"" << escapeJson(description) << "\",\n";
    ss << ind << "  \"source\": \"" << escapeJson(source) << "\",\n";
    ss << ind << "  \"observed_values\": {";
    bool first = true;
    for (const auto& [k, v] : observed_values) {
        if (!first) ss << ", ";
        first = false;
        ss << "\"" << escapeJson(k) << "\": \"" << escapeJson(v) << "\"";
    }
    ss << "}\n";
    ss << ind << "}";
    return ss.str();
}

// ============================================================================
// SecurityIncident Serialization
// ============================================================================

std::string SecurityIncident::toJson(int indent) const {
    std::string ind(indent, ' ');
    std::ostringstream ss;
    ss << ind << "{\n";
    ss << ind << "  \"schema_version\": \"" << schema_version << "\",\n";
    ss << ind << "  \"incident_id\": \"" << escapeJson(incident_id) << "\",\n";
    ss << ind << "  \"category\": \"" << incidentCategoryToString(category) << "\",\n";
    ss << ind << "  \"title\": \"" << escapeJson(title) << "\",\n";
    ss << ind << "  \"severity\": \"" << incidentSeverityToString(severity) << "\",\n";
    ss << ind << "  \"confidence\": \"" << incidentConfidenceToString(confidence) << "\",\n";
    ss << ind << "  \"confidence_explanation\": \"" << escapeJson(confidence_explanation) << "\",\n";
    ss << ind << "  \"correlation_score\": " << std::fixed << std::setprecision(2) << correlation_score << ",\n";
    ss << ind << "  \"first_seen_us\": " << first_seen_us << ",\n";
    ss << ind << "  \"last_seen_us\": " << last_seen_us << ",\n";
    ss << ind << "  \"first_seen_iso\": \"" << escapeJson(first_seen_iso) << "\",\n";
    ss << ind << "  \"last_seen_iso\": \"" << escapeJson(last_seen_iso) << "\",\n";
    ss << ind << "  \"duration_seconds\": " << std::fixed << std::setprecision(4) << duration_seconds << ",\n";
    ss << ind << "  \"primary_endpoint\": \"" << escapeJson(primary_endpoint) << "\",\n";

    // Related endpoints
    ss << ind << "  \"related_endpoints\": [";
    for (size_t i = 0; i < related_endpoints.size(); ++i) {
        ss << "\"" << escapeJson(related_endpoints[i]) << "\"" << (i + 1 < related_endpoints.size() ? ", " : "");
    }
    ss << "],\n";

    // Related ports
    ss << ind << "  \"related_ports\": [";
    for (size_t i = 0; i < related_ports.size(); ++i) {
        ss << related_ports[i] << (i + 1 < related_ports.size() ? ", " : "");
    }
    ss << "],\n";

    // Related flow ids
    ss << ind << "  \"related_flow_ids\": [";
    for (size_t i = 0; i < related_flow_ids.size(); ++i) {
        ss << related_flow_ids[i] << (i + 1 < related_flow_ids.size() ? ", " : "");
    }
    ss << "],\n";

    // Related detection ids
    ss << ind << "  \"related_detection_ids\": [";
    for (size_t i = 0; i < related_detection_ids.size(); ++i) {
        ss << "\"" << escapeJson(related_detection_ids[i]) << "\"" << (i + 1 < related_detection_ids.size() ? ", " : "");
    }
    ss << "],\n";

    // Related signature ids
    ss << ind << "  \"related_signature_ids\": [";
    for (size_t i = 0; i < related_signature_ids.size(); ++i) {
        ss << "\"" << escapeJson(related_signature_ids[i]) << "\"" << (i + 1 < related_signature_ids.size() ? ", " : "");
    }
    ss << "],\n";

    // Related IOC ids
    ss << ind << "  \"related_ioc_ids\": [";
    for (size_t i = 0; i < related_ioc_ids.size(); ++i) {
        ss << "\"" << escapeJson(related_ioc_ids[i]) << "\"" << (i + 1 < related_ioc_ids.size() ? ", " : "");
    }
    ss << "],\n";

    // Evidence descriptions
    ss << ind << "  \"evidence_descriptions\": [\n";
    for (size_t i = 0; i < evidence_descriptions.size(); ++i) {
        ss << ind << "    \"" << escapeJson(evidence_descriptions[i]) << "\"" << (i + 1 < evidence_descriptions.size() ? ",\n" : "\n");
    }
    ss << ind << "  ],\n";

    // Threat intelligence summaries
    ss << ind << "  \"threat_intel_summaries\": [\n";
    for (size_t i = 0; i < threat_intel_summaries.size(); ++i) {
        ss << ind << "    \"" << escapeJson(threat_intel_summaries[i]) << "\"" << (i + 1 < threat_intel_summaries.size() ? ",\n" : "\n");
    }
    ss << ind << "  ],\n";

    // Observed metrics
    ss << ind << "  \"observed_metrics\": {";
    bool first_m = true;
    for (const auto& [k, v] : observed_metrics) {
        if (!first_m) ss << ", ";
        first_m = false;
        ss << "\"" << escapeJson(k) << "\": \"" << escapeJson(v) << "\"";
    }
    ss << "},\n";

    // Correlation rules triggered
    ss << ind << "  \"correlation_rules_triggered\": [";
    for (size_t i = 0; i < correlation_rules_triggered.size(); ++i) {
        ss << "\"" << escapeJson(correlation_rules_triggered[i]) << "\"" << (i + 1 < correlation_rules_triggered.size() ? ", " : "");
    }
    ss << "],\n";
    ss << ind << "  \"rule_version\": \"" << rule_version << "\",\n";

    // Limitations
    ss << ind << "  \"limitations\": [\n";
    for (size_t i = 0; i < limitations.size(); ++i) {
        ss << ind << "    \"" << escapeJson(limitations[i]) << "\"" << (i + 1 < limitations.size() ? ",\n" : "\n");
    }
    ss << ind << "  ],\n";

    // Recommended investigation steps
    ss << ind << "  \"recommended_investigation_steps\": [\n";
    for (size_t i = 0; i < recommended_investigation_steps.size(); ++i) {
        ss << ind << "    \"" << escapeJson(recommended_investigation_steps[i]) << "\"" << (i + 1 < recommended_investigation_steps.size() ? ",\n" : "\n");
    }
    ss << ind << "  ],\n";

    // Status
    ss << ind << "  \"status\": \"" << incidentStatusToString(status) << "\",\n";

    // Timeline
    ss << ind << "  \"timeline\": [\n";
    for (size_t i = 0; i < timeline.size(); ++i) {
        ss << timeline[i].toJson(indent + 4) << (i + 1 < timeline.size() ? ",\n" : "\n");
    }
    ss << ind << "  ]\n";

    ss << ind << "}";
    return ss.str();
}

std::string SecurityIncident::csvHeader() {
    return "incident_id,category,severity,confidence,score,first_seen,last_seen,duration_sec,primary_endpoint,related_endpoints_count,related_flows_count,related_detections_count,title,status";
}

std::string SecurityIncident::toCsvRow() const {
    std::ostringstream ss;
    ss << "\"" << incident_id << "\","
       << "\"" << incidentCategoryToString(category) << "\","
       << "\"" << incidentSeverityToString(severity) << "\","
       << "\"" << incidentConfidenceToString(confidence) << "\","
       << std::fixed << std::setprecision(2) << correlation_score << ","
       << first_seen_us << ","
       << last_seen_us << ","
       << std::fixed << std::setprecision(4) << duration_seconds << ","
       << "\"" << primary_endpoint << "\","
       << related_endpoints.size() << ","
       << related_flow_ids.size() << ","
       << related_detection_ids.size() << ","
       << "\"" << escapeJson(title) << "\","
       << "\"" << incidentStatusToString(status) << "\"";
    return ss.str();
}

} // namespace DPI
