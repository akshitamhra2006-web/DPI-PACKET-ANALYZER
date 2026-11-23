#ifndef DPI_FLOW_TABLE_H
#define DPI_FLOW_TABLE_H

#include "flow_record.h"
#include "stream_types.h"
#include <unordered_map>
#include <vector>
#include <list>
#include <memory>
#include <iostream>

namespace DPI {

class FlowTable {
public:
    FlowTable(int fp_id, size_t max_active_flows = 50000, uint64_t idle_timeout_us = 60000000ULL);

    // Process incoming packet: retrieves or creates flow, updates stats, returns pointer to FlowRecord
    FlowRecord* processPacket(const PacketJob& job);

    // Get active flow by tuple (returns nullptr if not present)
    FlowRecord* getFlow(const FiveTuple& tuple);

    // Update application and L7 metadata for an active flow
    void updateClassification(const FiveTuple& tuple, AppType app, 
                              const std::string& sni, 
                              const std::string& host = "", 
                              const std::string& dns = "");

    // Phase 3.2 Protocol Intelligence & Stream Updates
    void updateStreamMetrics(const FiveTuple& tuple, const StreamDirectionStats& fwd,
                             const StreamDirectionStats& rev, bool is_complete);
    void updateHTTPMetadata(const FiveTuple& tuple, const HTTPMessage& msg);
    void updateTLSMetadata(const FiveTuple& tuple, const TLSStreamMetadata& meta);
    void updateDNSMetadata(const FiveTuple& tuple, const DNSMessage& msg);

    // Mark flow as blocked
    void markBlocked(const FiveTuple& tuple, const std::string& reason);

    // Scan for and finalize flows exceeding idle timeout
    size_t cleanupIdleFlows(uint64_t current_time_us);

    // Finalize a specific flow and archive it
    void finalizeFlow(const FiveTuple& tuple, FlowTerminationReason reason);

    // Finalize all remaining active flows (called upon PCAP EOF or engine shutdown)
    void finalizeAll(FlowTerminationReason reason = FlowTerminationReason::END_OF_FILE);

    // Accessors
    size_t getActiveFlowCount() const { return active_flows_.size(); }
    size_t getFinalizedFlowCount() const { return finalized_flows_.size(); }
    size_t getTotalFlowsSeen() const { return total_flows_seen_; }
    const std::vector<FlowRecord>& getFinalizedFlows() const { return finalized_flows_; }

    // Export utilities
    void exportJson(std::ostream& os) const;
    void exportCsv(std::ostream& os) const;

private:
    int fp_id_;
    size_t max_active_flows_;
    uint64_t idle_timeout_us_;
    uint32_t flow_sequence_ = 0;
    size_t total_flows_seen_ = 0;

    // Node storing the FlowRecord and its LRU iterator
    struct FlowNode {
        FlowRecord record;
        std::list<FiveTuple>::iterator lru_it;
    };

    // Active flows indexed by symmetrical canonical tuple
    std::unordered_map<FiveTuple, FlowNode, FiveTupleHash> active_flows_;
    std::list<FiveTuple> lru_list_;

    // Archive of finalized flow records
    std::vector<FlowRecord> finalized_flows_;

    // Evict oldest flow when capacity limit is reached
    void evictOldest();
};

} // namespace DPI

#endif // DPI_FLOW_TABLE_H
