#ifndef DPI_SIGNATURE_ENGINE_H
#define DPI_SIGNATURE_ENGINE_H

#include "signature_types.h"
#include "signature_manager.h"
#include "signature_matcher.h"
#include "flow_record.h"
#include "stream_types.h"
#include <string>
#include <vector>
#include <set>
#include <iostream>

namespace DPI {

struct SignatureEngineConfig {
    bool enabled = true;
    uint32_t max_matches = 10000;
    size_t max_stream_inspection_bytes = 65536; // 64 KB bounded search buffer
    bool suppress_duplicate_matches = true;

    bool validate() const {
        return max_matches > 0 && max_stream_inspection_bytes > 0;
    }
};

class SignatureEngine {
public:
    SignatureEngine();
    explicit SignatureEngine(const SignatureEngineConfig& config);
    ~SignatureEngine() = default;

    // Configuration accessors
    const SignatureEngineConfig& getConfig() const { return config_; }
    void setConfig(const SignatureEngineConfig& config) { config_ = config; }

    // Rule manager accessor
    SignatureManager& getRuleManager() { return rule_manager_; }
    const SignatureManager& getRuleManager() const { return rule_manager_; }

    // Evaluation entrypoints
    std::vector<SignatureEvent> evaluatePacket(const PacketJob& job);
    std::vector<SignatureEvent> evaluateFlow(const FlowRecord& flow);
    std::vector<SignatureEvent> evaluateStream(const StreamRecordSummary& stream,
                                               const FlowRecord* flow = nullptr);

    // Primary batch evaluation across all finalized flows and streams
    std::vector<SignatureEvent> evaluateAll(const std::vector<FlowRecord>& flows,
                                           const std::vector<StreamRecordSummary>& streams);

    // Reporting and Serialization
    std::string generateReport(const std::vector<SignatureEvent>& events) const;
    void exportJson(const std::vector<SignatureEvent>& events, std::ostream& os, int indent = 2) const;
    void exportCsv(const std::vector<SignatureEvent>& events, std::ostream& os) const;

    // Reset event sequence counter
    void reset();

private:
    SignatureEngineConfig config_;
    SignatureManager rule_manager_;
    uint64_t next_event_id_ = 1;

    std::string generateEventId();

    // Deduplication tracking: (rule_id + ":" + flow_id)
    std::set<std::string> seen_matches_;
};

} // namespace DPI

#endif // DPI_SIGNATURE_ENGINE_H
