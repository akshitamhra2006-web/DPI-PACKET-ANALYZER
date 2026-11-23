#ifndef DPI_RISK_PROFILER_H
#define DPI_RISK_PROFILER_H

#include "flow_record.h"
#include "stream_types.h"
#include "detection_types.h"
#include "incident_types.h"
#include "signature_types.h"
#include "threat_intel_types.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <set>
#include <cstdint>

namespace DPI {

// ============================================================================
// RISK LEVEL ENUMS
// ============================================================================
enum class RiskLevel {
    CLEAN,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

std::string riskLevelToString(RiskLevel level);
RiskLevel stringToRiskLevel(const std::string& str);

// ============================================================================
// RISK FACTOR (TRACEABLE EVIDENCE)
// ============================================================================
struct RiskFactor {
    std::string name;
    double weight = 0.0;
    std::string explanation;
    std::string source_reference;

    std::string toJson() const;
};

// ============================================================================
// ENDPOINT RISK PROFILE
// ============================================================================
struct EndpointRiskProfile {
    std::string ip;
    uint32_t ip_int = 0;
    bool is_internal = false;
    std::string role = "CLIENT"; // CLIENT, SERVER, MIXED, ROUTER_GATEWAY, EXTERNAL

    std::set<uint16_t> associated_ports;
    std::set<std::string> protocols;

    uint32_t total_flows = 0;
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;

    uint64_t first_seen_us = 0;
    uint64_t last_seen_us = 0;

    double risk_score = 0.0; // 0.0 - 100.0
    RiskLevel risk_level = RiskLevel::CLEAN;
    std::vector<RiskFactor> contributing_factors;

    std::vector<std::string> related_detections;
    std::vector<std::string> related_incidents;
    std::vector<std::string> related_signatures;
    std::vector<std::string> related_iocs;
    std::set<std::string> behavioral_tags;

    std::string toJson() const;
};

// ============================================================================
// FLOW RISK PROFILE
// ============================================================================
struct FlowRiskProfile {
    uint64_t flow_id = 0;
    FiveTuple tuple;
    std::string protocol_str;
    double risk_score = 0.0;
    RiskLevel risk_level = RiskLevel::CLEAN;
    std::vector<RiskFactor> contributing_factors;

    std::string toJson() const;
};

// ============================================================================
// RISK PROFILER CONFIGURATION
// ============================================================================
struct RiskProfilerConfig {
    bool enabled = true;
    double critical_threshold = 85.0;
    double high_threshold = 70.0;
    double medium_threshold = 45.0;
    double low_threshold = 20.0;

    // Weight factors
    double incident_critical_weight = 40.0;
    double incident_high_weight = 25.0;
    double incident_medium_weight = 15.0;
    double threat_ioc_weight = 30.0;
    double signature_match_weight = 20.0;
    double behavioral_alert_weight = 15.0;
    double scan_activity_weight = 20.0;
    double beacon_activity_weight = 25.0;
    double exfiltration_weight = 30.0;
    double dns_tunnel_weight = 25.0;
    double high_entropy_weight = 15.0;
};

// ============================================================================
// RISK PROFILER ENGINE
// ============================================================================
class RiskProfiler {
public:
    explicit RiskProfiler(const RiskProfilerConfig& config = RiskProfilerConfig());

    // Profile all network entities based on complete analysis state
    void profileAll(const std::vector<FlowRecord>& flows,
                    const std::vector<DetectionEvent>& detections,
                    const std::vector<SecurityIncident>& incidents,
                    const std::vector<SignatureEvent>& signatures,
                    const std::vector<ThreatMatchEvent>& threat_matches);

    // Get profiles
    const std::unordered_map<std::string, EndpointRiskProfile>& getEndpointProfiles() const {
        return endpoint_profiles_;
    }
    const std::vector<FlowRiskProfile>& getFlowProfiles() const {
        return flow_profiles_;
    }

    // Summary queries
    std::vector<EndpointRiskProfile> getTopRiskEndpoints(size_t limit = 10) const;
    std::vector<FlowRiskProfile> getTopRiskFlows(size_t limit = 10) const;

    // JSON export
    std::string endpointsToJson() const;
    std::string flowsToJson() const;
    std::string summaryToJson() const;

    // Formatted ASCII Report
    std::string generateRiskReport() const;

    static bool isRFC1918(uint32_t ip);
    static bool isRFC1918(const std::string& ip_str);

private:
    RiskProfilerConfig config_;
    std::unordered_map<std::string, EndpointRiskProfile> endpoint_profiles_;
    std::vector<FlowRiskProfile> flow_profiles_;

    void calculateEndpointScores();
    void assignBehavioralTags(EndpointRiskProfile& ep);
};

} // namespace DPI

#endif // DPI_RISK_PROFILER_H
