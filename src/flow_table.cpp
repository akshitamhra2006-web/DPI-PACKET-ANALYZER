#include "flow_table.h"
#include <iostream>

namespace DPI {

FlowTable::FlowTable(int fp_id, size_t max_active_flows, uint64_t idle_timeout_us)
    : fp_id_(fp_id), max_active_flows_(max_active_flows), idle_timeout_us_(idle_timeout_us) {
}

FlowRecord* FlowTable::processPacket(const PacketJob& job) {
    FiveTuple canonical = job.tuple.toCanonical();
    auto it = active_flows_.find(canonical);

    if (it != active_flows_.end()) {
        // Move to front of LRU list (O(1))
        lru_list_.splice(lru_list_.begin(), lru_list_, it->second.lru_it);
        it->second.record.update(job);
        return &it->second.record;
    }

    // Check capacity before creating new flow
    if (active_flows_.size() >= max_active_flows_) {
        evictOldest();
    }

    // Create a new flow record
    FlowRecord rec;
    rec.flow_id = (static_cast<uint64_t>(fp_id_) << 32) | (++flow_sequence_);
    rec.initial_tuple = job.tuple; // First observed packet defines FORWARD direction
    rec.canonical_tuple = canonical;
    rec.update(job);

    lru_list_.push_front(canonical);
    auto res = active_flows_.emplace(canonical, FlowNode{std::move(rec), lru_list_.begin()});
    total_flows_seen_++;

    return &res.first->second.record;
}

FlowRecord* FlowTable::getFlow(const FiveTuple& tuple) {
    FiveTuple canonical = tuple.toCanonical();
    auto it = active_flows_.find(canonical);
    if (it != active_flows_.end()) {
        lru_list_.splice(lru_list_.begin(), lru_list_, it->second.lru_it);
        return &it->second.record;
    }
    return nullptr;
}

void FlowTable::updateClassification(const FiveTuple& tuple, AppType app, 
                                    const std::string& sni, 
                                    const std::string& host, 
                                    const std::string& dns) {
    FlowRecord* flow = getFlow(tuple);
    if (!flow) return;

    if (app != AppType::UNKNOWN) {
        flow->app_type = app;
        flow->detected_app_name = appTypeToString(app);
    }
    if (!sni.empty()) flow->sni = sni;
    if (!host.empty()) flow->http_host = host;
    if (!dns.empty()) flow->dns_query = dns;
}

void FlowTable::updateStreamMetrics(const FiveTuple& tuple, const StreamDirectionStats& fwd,
                                   const StreamDirectionStats& rev, bool is_complete) {
    FlowRecord* flow = getFlow(tuple);
    if (!flow) return;

    flow->tcp_fwd_bytes_reassembled = fwd.bytes_reassembled;
    flow->tcp_rev_bytes_reassembled = rev.bytes_reassembled;
    flow->tcp_out_of_order_count = fwd.out_of_order_count + rev.out_of_order_count;
    flow->tcp_retrans_count = fwd.retrans_count + rev.retrans_count;
    flow->tcp_overlap_count = fwd.overlap_count + rev.overlap_count;
    flow->tcp_gap_count = fwd.gap_count + rev.gap_count;
    flow->tcp_stream_complete = is_complete;
}

void FlowTable::updateHTTPMetadata(const FiveTuple& tuple, const HTTPMessage& msg) {
    FlowRecord* flow = getFlow(tuple);
    if (!flow) return;

    if (msg.is_request) {
        flow->http_method = msg.method;
        flow->http_uri = msg.uri;
        if (!msg.host.empty()) flow->http_host = msg.host;
        if (!msg.user_agent.empty()) flow->http_user_agent = msg.user_agent;
    } else {
        flow->http_status_code = msg.status_code;
    }
    if (msg.content_length >= 0) {
        flow->http_content_length = msg.content_length;
    }
}

void FlowTable::updateTLSMetadata(const FiveTuple& tuple, const TLSStreamMetadata& meta) {
    FlowRecord* flow = getFlow(tuple);
    if (!flow) return;

    if (!meta.sni.empty()) flow->sni = meta.sni;
    if (!meta.alpn.empty()) flow->tls_alpn = meta.alpn;
    if (!meta.supported_versions.empty()) {
        flow->tls_supported_version = meta.supported_versions.front();
    }
    flow->tls_encrypted_bytes = meta.encrypted_bytes_count;
}

void FlowTable::updateDNSMetadata(const FiveTuple& tuple, const DNSMessage& msg) {
    FlowRecord* flow = getFlow(tuple);
    if (!flow) return;

    flow->dns_tx_id = msg.tx_id;
    flow->dns_rcode = msg.rcode;
    flow->dns_rcode_name = msg.rcode_name;
    flow->dns_latency_us = msg.latency_us;
    if (!msg.queries.empty() && flow->dns_query.empty()) {
        flow->dns_query = msg.queries.front().name;
    }
    for (const auto& a : msg.answers) {
        if (!a.rdata_string.empty()) {
            flow->dns_answers.push_back(a.rdata_string);
        }
    }
}

void FlowTable::markBlocked(const FiveTuple& tuple, const std::string& reason) {
    FlowRecord* flow = getFlow(tuple);
    if (!flow) return;

    flow->is_blocked = true;
    flow->block_reason = reason;
}

void FlowTable::evictOldest() {
    if (lru_list_.empty()) return;

    FiveTuple oldest = lru_list_.back();
    auto it = active_flows_.find(oldest);
    if (it != active_flows_.end()) {
        it->second.record.termination_reason = FlowTerminationReason::CAPACITY_EVICTION;
        it->second.record.state = FlowLifecycleState::CLOSED;
        finalized_flows_.push_back(std::move(it->second.record));
        active_flows_.erase(it);
    }
    lru_list_.pop_back();
}

size_t FlowTable::cleanupIdleFlows(uint64_t current_time_us) {
    size_t expired_count = 0;

    for (auto it = active_flows_.begin(); it != active_flows_.end(); ) {
        if (current_time_us > it->second.record.last_time_us &&
            (current_time_us - it->second.record.last_time_us) >= idle_timeout_us_) {
            
            it->second.record.termination_reason = FlowTerminationReason::IDLE_TIMEOUT;
            it->second.record.state = FlowLifecycleState::TIMED_OUT;
            finalized_flows_.push_back(std::move(it->second.record));
            lru_list_.erase(it->second.lru_it);
            it = active_flows_.erase(it);
            expired_count++;
        } else {
            ++it;
        }
    }

    return expired_count;
}

void FlowTable::finalizeFlow(const FiveTuple& tuple, FlowTerminationReason reason) {
    FiveTuple canonical = tuple.toCanonical();
    auto it = active_flows_.find(canonical);
    if (it != active_flows_.end()) {
        it->second.record.termination_reason = reason;
        it->second.record.state = FlowLifecycleState::CLOSED;
        finalized_flows_.push_back(std::move(it->second.record));
        lru_list_.erase(it->second.lru_it);
        active_flows_.erase(it);
    }
}

void FlowTable::finalizeAll(FlowTerminationReason reason) {
    for (auto& [tuple, node] : active_flows_) {
        if (node.record.termination_reason == FlowTerminationReason::ACTIVE) {
            node.record.termination_reason = reason;
        }
        node.record.state = FlowLifecycleState::CLOSED;
        finalized_flows_.push_back(std::move(node.record));
    }
    active_flows_.clear();
    lru_list_.clear();
}

void FlowTable::exportJson(std::ostream& os) const {
    os << "[\n";
    for (size_t i = 0; i < finalized_flows_.size(); i++) {
        os << finalized_flows_[i].toJson();
        if (i + 1 < finalized_flows_.size()) {
            os << ",\n";
        } else {
            os << "\n";
        }
    }
    os << "]\n";
}

void FlowTable::exportCsv(std::ostream& os) const {
    os << FlowRecord::csvHeader() << "\n";
    for (const auto& flow : finalized_flows_) {
        os << flow.toCsvRow() << "\n";
    }
}

} // namespace DPI
