#ifndef DPI_INCIDENT_CORRELATOR_H
#define DPI_INCIDENT_CORRELATOR_H

#include "incident_types.h"
#include "incident_config.h"
#include "detection_types.h"
#include "flow_record.h"
#include "stream_types.h"
#include "signature_types.h"
#include "threat_intel_types.h"
#include <vector>
#include <string>
#include <memory>
#include <map>
#include <set>
#include <iostream>

namespace DPI {

class IncidentCorrelator {
public:
    IncidentCorrelator();
    explicit IncidentCorrelator(const IncidentConfig& config);
    ~IncidentCorrelator() = default;

    // Configuration accessors
    IncidentConfig& getConfig() { return config_; }
    const IncidentConfig& getConfig() const { return config_; }
    void setConfig(const IncidentConfig& config) { config_ = config; }

    // Primary Correlation Entrypoint
    std::vector<SecurityIncident> correlate(
        const std::vector<DetectionEvent>& detections,
        const std::vector<FlowRecord>& flows,
        const std::vector<StreamRecordSummary>& streams = {},
        const std::vector<SignatureEvent>& signatures = {},
        const std::vector<ThreatMatchEvent>& threat_matches = {}
    );

    // Reporting & Serialization
    static std::string generateReport(const std::vector<SecurityIncident>& incidents);
    static void exportJson(const std::vector<SecurityIncident>& incidents, std::ostream& os, int indent = 2);
    static void exportCsv(const std::vector<SecurityIncident>& incidents, std::ostream& os);

private:
    IncidentConfig config_;
    uint64_t next_incident_id_ = 1;

    std::string generateIncidentId();

    // Internal Correlation Rules
    void evaluateReconnaissance(
        const std::string& endpoint,
        const std::vector<const DetectionEvent*>& ep_detections,
        const std::vector<const FlowRecord*>& ep_flows,
        std::vector<SecurityIncident>& out_incidents
    );

    void evaluateDNSSuspicious(
        const std::string& endpoint,
        const std::vector<const DetectionEvent*>& ep_detections,
        const std::vector<const FlowRecord*>& ep_flows,
        std::vector<SecurityIncident>& out_incidents
    );

    void evaluateSuspiciousOutbound(
        const std::string& endpoint,
        const std::vector<const DetectionEvent*>& ep_detections,
        const std::vector<const FlowRecord*>& ep_flows,
        const std::vector<StreamRecordSummary>& streams,
        std::vector<SecurityIncident>& out_incidents
    );

    void evaluateDataExfiltration(
        const std::string& endpoint,
        const std::vector<const DetectionEvent*>& ep_detections,
        const std::vector<const FlowRecord*>& ep_flows,
        std::vector<SecurityIncident>& out_incidents
    );

    void evaluateMultiStage(
        const std::string& endpoint,
        const std::vector<const DetectionEvent*>& ep_detections,
        const std::vector<const FlowRecord*>& ep_flows,
        std::vector<SecurityIncident>& out_incidents
    );

    void evaluateTCPAnomalyCluster(
        const std::string& endpoint,
        const std::vector<const DetectionEvent*>& ep_detections,
        const std::vector<const FlowRecord*>& ep_flows,
        std::vector<SecurityIncident>& out_incidents
    );

    // Scoring & Severity Calculation
    void calculateScoringAndSeverity(SecurityIncident& incident, const std::vector<const FlowRecord*>& ep_flows);

    // Timeline Construction & Sorting
    void buildTimeline(
        SecurityIncident& incident,
        const std::vector<const DetectionEvent*>& related_dets,
        const std::vector<const FlowRecord*>& related_fls
    );

    // Deduplication & Merging
    std::vector<SecurityIncident> deduplicateAndMerge(std::vector<SecurityIncident>& incidents);
};

} // namespace DPI

#endif // DPI_INCIDENT_CORRELATOR_H
