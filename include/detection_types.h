#ifndef DPI_DETECTION_TYPES_H
#define DPI_DETECTION_TYPES_H

#include "types.h"
#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <sstream>

namespace DPI {

// ============================================================================
// Detection Severity Levels
// ============================================================================
enum class DetectionSeverity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

std::string detectionSeverityToString(DetectionSeverity severity);
DetectionSeverity stringToDetectionSeverity(const std::string& str);

// ============================================================================
// Detection Categories
// ============================================================================
enum class DetectionCategory {
    NETWORK_RECONNAISSANCE,
    CONNECTION_ANOMALY,
    SUSPICIOUS_CONNECTION_ATTEMPT,
    SUSPICIOUS_DNS,
    UNUSUAL_TRAFFIC_VOLUME,
    COMMAND_AND_CONTROL,
    PROTOCOL_ANOMALY
};

std::string detectionCategoryToString(DetectionCategory category);
DetectionCategory stringToDetectionCategory(const std::string& str);

// ============================================================================
// Structured Behavioral Detection Event
// ============================================================================
struct DetectionEvent {
    std::string schema_version = "1.0";
    std::string detection_id;
    std::string detector_name;
    DetectionCategory category = DetectionCategory::CONNECTION_ANOMALY;
    DetectionSeverity severity = DetectionSeverity::INFO;

    // Timing (microsecond precision and human-readable timestamp)
    uint64_t timestamp_us = 0;
    std::string timestamp_iso;

    // Network context
    uint32_t source_ip = 0;
    uint32_t destination_ip = 0; // 0 if multiple destinations
    std::string source_ip_str;
    std::string destination_ip_str;
    uint8_t protocol = 0;        // 6=TCP, 17=UDP, 0=Mixed/Any
    std::vector<uint16_t> relevant_ports;

    // Associated flows
    std::vector<uint64_t> related_flow_ids;

    // Structured evidence and threshold comparison
    std::map<std::string, std::string> evidence;

    // Explainability and actionable guidance
    std::string explanation;
    std::vector<std::string> limitations;
    std::vector<std::string> recommended_actions;

    // Detection metadata
    std::string detection_method = "deterministic_behavioral_rule";

    // Serialization
    std::string toJson(int indent = 2) const;
    std::string toCsvRow() const;
    static std::string csvHeader();
};

} // namespace DPI

#endif // DPI_DETECTION_TYPES_H
