#include "detection_types.h"
#include <iomanip>
#include <algorithm>

namespace DPI {

std::string detectionSeverityToString(DetectionSeverity severity) {
    switch (severity) {
        case DetectionSeverity::INFO:     return "INFO";
        case DetectionSeverity::LOW:      return "LOW";
        case DetectionSeverity::MEDIUM:   return "MEDIUM";
        case DetectionSeverity::HIGH:     return "HIGH";
        case DetectionSeverity::CRITICAL: return "CRITICAL";
        default:                          return "UNKNOWN";
    }
}

DetectionSeverity stringToDetectionSeverity(const std::string& str) {
    std::string s = str;
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);
    if (s == "INFO") return DetectionSeverity::INFO;
    if (s == "LOW") return DetectionSeverity::LOW;
    if (s == "MEDIUM") return DetectionSeverity::MEDIUM;
    if (s == "HIGH") return DetectionSeverity::HIGH;
    if (s == "CRITICAL") return DetectionSeverity::CRITICAL;
    return DetectionSeverity::INFO;
}

std::string detectionCategoryToString(DetectionCategory category) {
    switch (category) {
        case DetectionCategory::NETWORK_RECONNAISSANCE:        return "NETWORK_RECONNAISSANCE";
        case DetectionCategory::CONNECTION_ANOMALY:            return "CONNECTION_ANOMALY";
        case DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT: return "SUSPICIOUS_CONNECTION_ATTEMPT";
        case DetectionCategory::SUSPICIOUS_DNS:                return "SUSPICIOUS_DNS";
        case DetectionCategory::UNUSUAL_TRAFFIC_VOLUME:        return "UNUSUAL_TRAFFIC_VOLUME";
        case DetectionCategory::COMMAND_AND_CONTROL:           return "COMMAND_AND_CONTROL";
        case DetectionCategory::PROTOCOL_ANOMALY:              return "PROTOCOL_ANOMALY";
        default:                                               return "GENERAL_ANOMALY";
    }
}

DetectionCategory stringToDetectionCategory(const std::string& str) {
    std::string s = str;
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);
    if (s == "NETWORK_RECONNAISSANCE") return DetectionCategory::NETWORK_RECONNAISSANCE;
    if (s == "CONNECTION_ANOMALY") return DetectionCategory::CONNECTION_ANOMALY;
    if (s == "SUSPICIOUS_CONNECTION_ATTEMPT") return DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT;
    if (s == "SUSPICIOUS_DNS") return DetectionCategory::SUSPICIOUS_DNS;
    if (s == "UNUSUAL_TRAFFIC_VOLUME") return DetectionCategory::UNUSUAL_TRAFFIC_VOLUME;
    if (s == "COMMAND_AND_CONTROL") return DetectionCategory::COMMAND_AND_CONTROL;
    if (s == "PROTOCOL_ANOMALY") return DetectionCategory::PROTOCOL_ANOMALY;
    return DetectionCategory::CONNECTION_ANOMALY;
}

static std::string escapeJsonString(const std::string& str) {
    std::string res;
    for (char c : str) {
        if (c == '"') res += "\\\"";
        else if (c == '\\') res += "\\\\";
        else if (c == '\n') res += "\\n";
        else if (c == '\r') res += "\\r";
        else if (c == '\t') res += "\\t";
        else res += c;
    }
    return res;
}

std::string DetectionEvent::toJson(int indent) const {
    std::string ind(indent, ' ');
    std::string ind2(indent + 2, ' ');
    std::string ind3(indent + 4, ' ');
    std::ostringstream ss;

    ss << ind << "{\n";
    ss << ind2 << "\"schema_version\": \"" << schema_version << "\",\n";
    ss << ind2 << "\"detection_id\": \"" << detection_id << "\",\n";
    ss << ind2 << "\"detector\": \"" << detector_name << "\",\n";
    ss << ind2 << "\"category\": \"" << detectionCategoryToString(category) << "\",\n";
    ss << ind2 << "\"severity\": \"" << detectionSeverityToString(severity) << "\",\n";
    ss << ind2 << "\"timestamp_us\": " << timestamp_us << ",\n";
    ss << ind2 << "\"timestamp_iso\": \"" << timestamp_iso << "\",\n";
    ss << ind2 << "\"source_ip\": \"" << source_ip_str << "\",\n";
    ss << ind2 << "\"destination_ip\": \"" << destination_ip_str << "\",\n";
    ss << ind2 << "\"protocol\": \"" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "Mixed") << "\",\n";

    // Relevant ports
    ss << ind2 << "\"relevant_ports\": [";
    for (size_t i = 0; i < relevant_ports.size(); ++i) {
        ss << relevant_ports[i];
        if (i + 1 < relevant_ports.size()) ss << ", ";
    }
    ss << "],\n";

    // Related flow IDs
    ss << ind2 << "\"related_flow_ids\": [";
    for (size_t i = 0; i < related_flow_ids.size(); ++i) {
        ss << related_flow_ids[i];
        if (i + 1 < related_flow_ids.size()) ss << ", ";
    }
    ss << "],\n";

    // Evidence dictionary
    ss << ind2 << "\"evidence\": {\n";
    size_t ev_idx = 0;
    for (const auto& kv : evidence) {
        ss << ind3 << "\"" << escapeJsonString(kv.first) << "\": \"" 
           << escapeJsonString(kv.second) << "\"";
        if (++ev_idx < evidence.size()) ss << ",";
        ss << "\n";
    }
    ss << ind2 << "},\n";

    // Explanation
    ss << ind2 << "\"explanation\": \"" << escapeJsonString(explanation) << "\",\n";

    // Limitations array
    ss << ind2 << "\"limitations\": [\n";
    for (size_t i = 0; i < limitations.size(); ++i) {
        ss << ind3 << "\"" << escapeJsonString(limitations[i]) << "\"";
        if (i + 1 < limitations.size()) ss << ",";
        ss << "\n";
    }
    ss << ind2 << "],\n";

    // Recommended Actions array
    ss << ind2 << "\"recommended_actions\": [\n";
    for (size_t i = 0; i < recommended_actions.size(); ++i) {
        ss << ind3 << "\"" << escapeJsonString(recommended_actions[i]) << "\"";
        if (i + 1 < recommended_actions.size()) ss << ",";
        ss << "\n";
    }
    ss << ind2 << "],\n";

    // Detection method
    ss << ind2 << "\"detection_method\": \"" << detection_method << "\"\n";
    ss << ind << "}";

    return ss.str();
}

std::string DetectionEvent::csvHeader() {
    return "detection_id,detector,category,severity,timestamp_us,source_ip,destination_ip,"
           "protocol,flow_count,primary_metric,explanation";
}

std::string DetectionEvent::toCsvRow() const {
    std::ostringstream ss;
    ss << detection_id << ","
       << detector_name << ","
       << detectionCategoryToString(category) << ","
       << detectionSeverityToString(severity) << ","
       << timestamp_us << ","
       << source_ip_str << ","
       << destination_ip_str << ","
       << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "Mixed") << ","
       << related_flow_ids.size() << ",";

    // Extract primary metric from evidence if present
    std::string primary_metric;
    if (evidence.count("observed_metric")) {
        primary_metric = evidence.at("observed_metric");
    } else if (!evidence.empty()) {
        primary_metric = evidence.begin()->first + "=" + evidence.begin()->second;
    }
    // CSV escape quotes
    std::string escaped_metric = primary_metric;
    std::replace(escaped_metric.begin(), escaped_metric.end(), ',', ';');
    ss << "\"" << escaped_metric << "\",";

    std::string escaped_explanation = explanation;
    std::replace(escaped_explanation.begin(), escaped_explanation.end(), ',', ';');
    std::replace(escaped_explanation.begin(), escaped_explanation.end(), '"', '\'');
    ss << "\"" << escaped_explanation << "\"";

    return ss.str();
}

} // namespace DPI
