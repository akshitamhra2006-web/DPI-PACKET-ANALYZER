#ifndef DPI_THREAT_INTEL_ENGINE_H
#define DPI_THREAT_INTEL_ENGINE_H

#include "threat_intel_types.h"
#include "threat_intel_manager.h"
#include "flow_record.h"
#include "stream_types.h"
#include "detection_types.h"
#include "signature_types.h"
#include <string>
#include <vector>
#include <set>
#include <memory>
#include <iostream>

namespace DPI {

class ThreatIntelEngine {
public:
    ThreatIntelEngine();
    explicit ThreatIntelEngine(const ThreatIntelConfig& config);
    ~ThreatIntelEngine() = default;

    ThreatIntelConfig& getConfig() { return config_; }
    const ThreatIntelConfig& getConfig() const { return config_; }
    void setConfig(const ThreatIntelConfig& config) { config_ = config; }

    ThreatIntelManager& getManager() { return manager_; }
    const ThreatIntelManager& getManager() const { return manager_; }

    // Primary Evaluation & Enrichment Entrypoint
    std::vector<ThreatMatchEvent> evaluateAll(
        std::vector<FlowRecord>& flows,
        const std::vector<StreamRecordSummary>& streams = {},
        std::vector<DetectionEvent>* detections = nullptr,
        std::vector<SignatureEvent>* signatures = nullptr
    );

    // Reporting & Serialization
    std::string generateReport(const std::vector<ThreatMatchEvent>& events) const;
    void exportJson(const std::vector<ThreatMatchEvent>& events, std::ostream& os, int indent = 2) const;
    void exportCsv(const std::vector<ThreatMatchEvent>& events, std::ostream& os) const;

private:
    ThreatIntelConfig config_;
    ThreatIntelManager manager_;
    uint64_t next_event_id_ = 1;

    std::string generateEventId();

    ThreatMatchEvent createMatchEvent(
        const ThreatIOC* ioc,
        ThreatMatchType match_type,
        const std::string& observed_value,
        const FlowRecord& flow,
        const std::string& evidence_prefix,
        uint64_t timestamp_us
    );
};

} // namespace DPI

#endif // DPI_THREAT_INTEL_ENGINE_H
