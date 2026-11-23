#include "fast_path.h"
#include "logger.h"
#include <iostream>
#include <sstream>
#include <iomanip>

namespace DPI {

// ============================================================================
// FastPathProcessor Implementation
// ============================================================================

FastPathProcessor::FastPathProcessor(int fp_id,
                                     RuleManager* rule_manager,
                                     PacketOutputCallback output_callback,
                                     const StreamReassemblyConfig& reassembly_config,
                                     bool enable_stream_reassembly)
    : fp_id_(fp_id),
      input_queue_(10000),
      conn_tracker_(fp_id),
      flow_table_(fp_id),
      reassembly_config_(reassembly_config),
      enable_stream_reassembly_(enable_stream_reassembly),
      stream_manager_(reassembly_config),
      rule_manager_(rule_manager),
      output_callback_(std::move(output_callback)) {
}

FastPathProcessor::~FastPathProcessor() {
    stop();
}

void FastPathProcessor::start() {
    if (running_) return;
    
    running_ = true;
    thread_ = std::thread(&FastPathProcessor::run, this);
    
    std::cout << "[FP" << fp_id_ << "] Started\n";
}

void FastPathProcessor::stop() {
    if (!running_) return;
    
    running_ = false;
    input_queue_.shutdown();
    
    if (thread_.joinable()) {
        thread_.join();
    }

    // Finalize all remaining active flows
    flow_table_.finalizeAll(FlowTerminationReason::END_OF_FILE);
    if (enable_stream_reassembly_) {
        stream_manager_.finalizeAll();
    }
    
    std::cout << "[FP" << fp_id_ << "] Stopped (processed " 
              << packets_processed_ << " packets)\n";
}

void FastPathProcessor::run() {
    while (running_) {
        // Get packet from input queue
        auto job_opt = input_queue_.popWithTimeout(std::chrono::milliseconds(100));
        
        if (!job_opt) {
            // Periodically cleanup stale connections and idle flows
            conn_tracker_.cleanupStale(std::chrono::seconds(300));
            uint64_t now_us = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            flow_table_.cleanupIdleFlows(now_us);
            if (enable_stream_reassembly_) {
                stream_manager_.cleanupInactive(now_us);
            }
            continue;
        }
        
        packets_processed_++;
        
        // Process the packet
        PacketAction action = processPacket(*job_opt);
        job_opt->action = action;
        
        // Call output callback
        if (output_callback_) {
            output_callback_(*job_opt, action);
        }
        
        // Update stats
        if (action == PacketAction::DROP) {
            packets_dropped_++;
        } else {
            packets_forwarded_++;
        }
    }
}

PacketAction FastPathProcessor::processPacket(PacketJob& job) {
    // Flow table telemetry and feature extraction update (Phase 3.0)
    flow_table_.processPacket(job);

    uint64_t pkt_time_us = static_cast<uint64_t>(job.ts_sec) * 1000000ULL + job.ts_usec;

    // TCP Stream Reassembly & Protocol Extraction (Phase 3.2)
    if (enable_stream_reassembly_ && job.tuple.protocol == 6) {
        TCPConnectionStream* stream = stream_manager_.processPacket(job);
        if (stream) {
            // HTTP/1.x stream inspection
            if (reassembly_config_.enable_http_parsing && (job.tuple.dst_port == 80 || job.tuple.src_port == 80)) {
                const auto& fwd_data = stream->getForwardStream().getReassembledData();
                if (!fwd_data.empty()) {
                    auto msgs = HTTPStreamParser::parseStream(fwd_data.data(), fwd_data.size());
                    for (const auto& m : msgs) {
                        flow_table_.updateHTTPMetadata(job.tuple, m);
                        if (!m.host.empty()) {
                            AppType app = sniToAppType(m.host, AppType::HTTP);
                            flow_table_.updateClassification(job.tuple, app, "", m.host, "");
                        }
                    }
                }
                const auto& rev_data = stream->getReverseStream().getReassembledData();
                if (!rev_data.empty()) {
                    auto resp_msgs = HTTPStreamParser::parseStream(rev_data.data(), rev_data.size());
                    for (const auto& m : resp_msgs) {
                        flow_table_.updateHTTPMetadata(job.tuple, m);
                    }
                }
            }

            // TLS stream inspection
            if (reassembly_config_.enable_tls_parsing && (job.tuple.dst_port == 443 || job.tuple.src_port == 443)) {
                const auto& fwd_data = stream->getForwardStream().getReassembledData();
                if (!fwd_data.empty()) {
                    auto tls_meta = TLSStreamParser::parseStream(fwd_data.data(), fwd_data.size());
                    flow_table_.updateTLSMetadata(job.tuple, tls_meta);
                    if (!tls_meta.sni.empty()) {
                        AppType app = sniToAppType(tls_meta.sni, AppType::HTTPS);
                        flow_table_.updateClassification(job.tuple, app, tls_meta.sni, "", "");
                    }
                }
            }

            // TCP DNS stream inspection
            if (reassembly_config_.enable_dns_parsing && (job.tuple.dst_port == 53 || job.tuple.src_port == 53)) {
                const auto& fwd_data = stream->getForwardStream().getReassembledData();
                if (!fwd_data.empty()) {
                    auto dns_msgs = DNSParser::parseTCPStream(fwd_data.data(), fwd_data.size(), pkt_time_us);
                    for (auto& m : dns_msgs) {
                        dns_correlator_.processDNSMessage(job.tuple, m);
                        flow_table_.updateDNSMetadata(job.tuple, m);
                    }
                }
                const auto& rev_data = stream->getReverseStream().getReassembledData();
                if (!rev_data.empty()) {
                    auto dns_msgs = DNSParser::parseTCPStream(rev_data.data(), rev_data.size(), pkt_time_us);
                    for (auto& m : dns_msgs) {
                        dns_correlator_.processDNSMessage(job.tuple, m);
                        flow_table_.updateDNSMetadata(job.tuple, m);
                    }
                }
            }

            flow_table_.updateStreamMetrics(job.tuple, stream->getForwardStream().getStats(),
                                            stream->getReverseStream().getStats(), stream->isComplete());
        }
    }

    // UDP DNS inspection & correlation
    if (reassembly_config_.enable_dns_parsing && job.tuple.protocol == 17 &&
        (job.tuple.dst_port == 53 || job.tuple.src_port == 53)) {
        if (job.payload_offset < job.data.size() && job.payload_length >= 12) {
            auto dns_msg = DNSParser::parseUDP(job.data.data() + job.payload_offset,
                                               job.payload_length, pkt_time_us);
            if (dns_msg) {
                dns_correlator_.processDNSMessage(job.tuple, *dns_msg);
                flow_table_.updateDNSMetadata(job.tuple, *dns_msg);
                if (!dns_msg->queries.empty()) {
                    flow_table_.updateClassification(job.tuple, AppType::DNS, "", "", dns_msg->queries.front().name);
                }
            }
        }
    }

    // Get or create connection
    Connection* conn = conn_tracker_.getOrCreateConnection(job.tuple);
    if (!conn) {
        // Should not happen, but handle gracefully
        return PacketAction::FORWARD;
    }
    
    // Update connection stats (directional tracking relative to canonical flow tuple)
    bool is_outbound = (job.tuple.src_ip == conn->tuple.src_ip && job.tuple.src_port == conn->tuple.src_port);
    conn_tracker_.updateConnection(conn, job.data.size(), is_outbound);
    
    // Update TCP state if applicable
    if (job.tuple.protocol == 6) {  // TCP
        updateTCPState(conn, job.tcp_flags);
    }
    
    // If connection is already blocked, drop immediately
    if (conn->state == ConnectionState::BLOCKED) {
        flow_table_.markBlocked(job.tuple, "Connection already blocked");
        return PacketAction::DROP;
    }
    
    // If connection not yet classified, try to inspect payload
    if (conn->state != ConnectionState::CLASSIFIED && job.payload_length > 0) {
        inspectPayload(job, conn);
    }
    
    // Check rules (even for classified connections, as rules might change)
    return checkRules(job, conn);
}

void FastPathProcessor::inspectPayload(PacketJob& job, Connection* conn) {
    if (job.payload_length == 0 || job.payload_offset >= job.data.size()) {
        return;
    }
    
    const uint8_t* payload = job.data.data() + job.payload_offset;
    
    // Try TLS SNI extraction first (most common for HTTPS)
    if (tryExtractSNI(job, conn)) {
        return;
    }
    
    // Try HTTP Host header extraction
    if (tryExtractHTTPHost(job, conn)) {
        return;
    }
    
    // Check for DNS (port 53)
    if (job.tuple.dst_port == 53 || job.tuple.src_port == 53) {
        auto domain = DNSExtractor::extractQuery(payload, job.payload_length);
        if (domain) {
            conn_tracker_.classifyConnection(conn, AppType::DNS, *domain);
            flow_table_.updateClassification(job.tuple, AppType::DNS, "", "", *domain);
            return;
        }
    }
    
    // Basic port-based classification as fallback
    if (job.tuple.dst_port == 80) {
        conn_tracker_.classifyConnection(conn, AppType::HTTP, "");
        flow_table_.updateClassification(job.tuple, AppType::HTTP, "", "", "");
    } else if (job.tuple.dst_port == 443) {
        conn_tracker_.classifyConnection(conn, AppType::HTTPS, "");
        flow_table_.updateClassification(job.tuple, AppType::HTTPS, "", "", "");
    }
}

bool FastPathProcessor::tryExtractSNI(const PacketJob& job, Connection* conn) {
    // Only for port 443 (HTTPS) or if it looks like TLS
    if (job.tuple.dst_port != 443 && job.payload_length < 50) {
        return false;
    }
    
    if (job.payload_offset >= job.data.size() || job.payload_length == 0) {
        return false;
    }
    
    const uint8_t* payload = job.data.data() + job.payload_offset;
    auto sni = SNIExtractor::extract(payload, job.payload_length);
    if (sni) {
        sni_extractions_++;
        
        // Map SNI to app type
        AppType app = sniToAppType(*sni, AppType::HTTPS);
        conn_tracker_.classifyConnection(conn, app, *sni);
        flow_table_.updateClassification(job.tuple, app, *sni, "", "");
        
        if (app != AppType::UNKNOWN && app != AppType::HTTPS) {
            classification_hits_++;
        }
        
        return true;
    }
    
    return false;
}

bool FastPathProcessor::tryExtractHTTPHost(const PacketJob& job, Connection* conn) {
    // Only for port 80 (HTTP)
    if (job.tuple.dst_port != 80) {
        return false;
    }
    
    if (job.payload_offset >= job.data.size() || job.payload_length == 0) {
        return false;
    }
    
    const uint8_t* payload = job.data.data() + job.payload_offset;
    auto host = HTTPHostExtractor::extract(payload, job.payload_length);
    if (host) {
        AppType app = sniToAppType(*host, AppType::HTTP);
        conn_tracker_.classifyConnection(conn, app, *host);
        flow_table_.updateClassification(job.tuple, app, "", *host, "");
        
        if (app != AppType::UNKNOWN && app != AppType::HTTP) {
            classification_hits_++;
        }
        
        return true;
    }
    
    return false;
}

PacketAction FastPathProcessor::checkRules(const PacketJob& job, Connection* conn) {
    if (!rule_manager_) {
        return PacketAction::FORWARD;
    }
    
    // Parse source IP from tuple
    uint32_t src_ip = job.tuple.src_ip;
    
    // Check blocking rules
    auto block_reason = rule_manager_->shouldBlock(
        src_ip,
        job.tuple.dst_port,
        conn->app_type,
        conn->sni
    );
    
    if (block_reason) {
        // Log the block
        std::ostringstream ss;
        ss << "[FP" << fp_id_ << "] BLOCKED packet: ";
        std::string block_desc;
        
        switch (block_reason->type) {
            case RuleManager::BlockReason::IP:
                ss << "IP " << block_reason->detail;
                block_desc = "IP: " + block_reason->detail;
                break;
            case RuleManager::BlockReason::APP:
                ss << "App " << block_reason->detail;
                block_desc = "App: " + block_reason->detail;
                break;
            case RuleManager::BlockReason::DOMAIN_NAME:
                ss << "Domain " << block_reason->detail;
                block_desc = "Domain: " + block_reason->detail;
                break;
            case RuleManager::BlockReason::PORT:
                ss << "Port " << block_reason->detail;
                block_desc = "Port: " + block_reason->detail;
                break;
        }
        
        Logger::log(ss.str());
        
        // Mark connection as blocked
        conn_tracker_.blockConnection(conn);
        flow_table_.markBlocked(job.tuple, block_desc);
        
        return PacketAction::DROP;
    }
    
    return PacketAction::FORWARD;
}

void FastPathProcessor::updateTCPState(Connection* conn, uint8_t tcp_flags) {
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t RST = 0x04;
    
    if (tcp_flags & SYN) {
        if (tcp_flags & ACK) {
            conn->syn_ack_seen = true;
        } else {
            conn->syn_seen = true;
        }
    }
    
    if (conn->syn_seen && conn->syn_ack_seen && (tcp_flags & ACK)) {
        if (conn->state == ConnectionState::NEW) {
            conn->state = ConnectionState::ESTABLISHED;
        }
    }
    
    if (tcp_flags & FIN) {
        conn->fin_seen = true;
    }
    
    if (tcp_flags & RST) {
        conn->state = ConnectionState::CLOSED;
        flow_table_.finalizeFlow(conn->tuple, FlowTerminationReason::NATURAL_FIN_RST);
        return;
    }
    
    if (conn->fin_seen && (tcp_flags & ACK)) {
        conn->state = ConnectionState::CLOSED;
        flow_table_.finalizeFlow(conn->tuple, FlowTerminationReason::NATURAL_FIN_RST);
    }
}

FastPathProcessor::FPStats FastPathProcessor::getStats() const {
    FPStats stats;
    stats.packets_processed = packets_processed_.load();
    stats.packets_forwarded = packets_forwarded_.load();
    stats.packets_dropped = packets_dropped_.load();
    stats.connections_tracked = conn_tracker_.getActiveCount();
    stats.sni_extractions = sni_extractions_.load();
    stats.classification_hits = classification_hits_.load();
    return stats;
}

// ============================================================================
// FPManager Implementation
// ============================================================================

FPManager::FPManager(int num_fps,
                     RuleManager* rule_manager,
                     PacketOutputCallback output_callback,
                     const StreamReassemblyConfig& reassembly_config,
                     bool enable_stream_reassembly) {
    
    // Create FP processors (each has its own input queue)
    for (int i = 0; i < num_fps; i++) {
        auto fp = std::make_unique<FastPathProcessor>(
            i, rule_manager, output_callback, reassembly_config, enable_stream_reassembly
        );
        fps_.push_back(std::move(fp));
    }
    
    std::cout << "[FPManager] Created " << num_fps << " fast path processors\n";
}

FPManager::~FPManager() {
    stopAll();
}

void FPManager::startAll() {
    for (auto& fp : fps_) {
        fp->start();
    }
}

void FPManager::stopAll() {
    // Stop all FPs (they'll shutdown their own queues)
    for (auto& fp : fps_) {
        fp->stop();
    }
}

FPManager::AggregatedStats FPManager::getAggregatedStats() const {
    AggregatedStats stats = {0, 0, 0, 0};
    
    for (const auto& fp : fps_) {
        auto fp_stats = fp->getStats();
        stats.total_processed += fp_stats.packets_processed;
        stats.total_forwarded += fp_stats.packets_forwarded;
        stats.total_dropped += fp_stats.packets_dropped;
        stats.total_connections += fp_stats.connections_tracked;
    }
    
    return stats;
}

std::string FPManager::generateClassificationReport() const {
    // Aggregate app distribution across all FPs
    std::unordered_map<AppType, size_t> app_counts;
    std::unordered_map<std::string, size_t> domain_counts;
    size_t total_classified = 0;
    size_t total_unknown = 0;
    
    for (const auto& fp : fps_) {
        fp->getConnectionTracker().forEach([&](const Connection& conn) {
            app_counts[conn.app_type]++;
            
            if (conn.app_type == AppType::UNKNOWN) {
                total_unknown++;
            } else {
                total_classified++;
            }
            
            if (!conn.sni.empty()) {
                domain_counts[conn.sni]++;
            }
        });
    }
    
    std::ostringstream ss;
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║                 APPLICATION CLASSIFICATION REPORT             ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    size_t total = total_classified + total_unknown;
    double classified_pct = total > 0 ? (100.0 * total_classified / total) : 0;
    double unknown_pct = total > 0 ? (100.0 * total_unknown / total) : 0;
    
    ss << "║ Total Connections:    " << std::setw(10) << total << "                           ║\n";
    ss << "║ Classified:           " << std::setw(10) << total_classified 
       << " (" << std::fixed << std::setprecision(1) << classified_pct << "%)                  ║\n";
    ss << "║ Unidentified:         " << std::setw(10) << total_unknown
       << " (" << std::fixed << std::setprecision(1) << unknown_pct << "%)                  ║\n";
    
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║                    APPLICATION DISTRIBUTION                   ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    // Sort apps by count
    std::vector<std::pair<AppType, size_t>> sorted_apps(
        app_counts.begin(), app_counts.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (const auto& pair : sorted_apps) {
        double pct = total > 0 ? (100.0 * pair.second / total) : 0;
        
        // Create a simple bar graph
        int bar_len = static_cast<int>(pct / 5);  // 20 chars max
        std::string bar(bar_len, '#');
        
        ss << "║ " << std::setw(15) << std::left << appTypeToString(pair.first)
           << std::setw(8) << std::right << pair.second
           << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "% "
           << std::setw(20) << std::left << bar << "   ║\n";
    }
    
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return ss.str();
}

std::vector<FlowRecord> FPManager::getAllFinalizedFlows() const {
    std::vector<FlowRecord> all_flows;
    for (const auto& fp : fps_) {
        const auto& flows = fp->getFlowTable().getFinalizedFlows();
        all_flows.insert(all_flows.end(), flows.begin(), flows.end());
    }
    return all_flows;
}

void FPManager::exportAllFlowsJson(std::ostream& os) const {
    auto flows = getAllFinalizedFlows();
    os << "[\n";
    for (size_t i = 0; i < flows.size(); ++i) {
        os << flows[i].toJson();
        if (i + 1 < flows.size()) {
            os << ",";
        }
        os << "\n";
    }
    os << "]\n";
}

void FPManager::exportAllFlowsCsv(std::ostream& os) const {
    os << FlowRecord::csvHeader() << "\n";
    for (const auto& fp : fps_) {
        for (const auto& flow : fp->getFlowTable().getFinalizedFlows()) {
            os << flow.toCsvRow() << "\n";
        }
    }
}

std::string FPManager::generateFlowIntelligenceReport() const {
    auto flows = getAllFinalizedFlows();
    
    size_t total_flows = flows.size();
    size_t tcp_flows = 0;
    size_t udp_flows = 0;
    size_t other_flows = 0;
    size_t blocked_flows = 0;
    
    std::unordered_map<FlowTerminationReason, size_t> term_counts;
    std::unordered_map<AppType, size_t> app_counts;
    
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    double total_duration_s = 0.0;
    
    for (const auto& f : flows) {
        if (f.canonical_tuple.protocol == 6) tcp_flows++;
        else if (f.canonical_tuple.protocol == 17) udp_flows++;
        else other_flows++;
        
        if (f.is_blocked) blocked_flows++;
        
        term_counts[f.termination_reason]++;
        app_counts[f.app_type]++;
        
        total_packets += f.total_packets();
        total_bytes += f.total_bytes();
        total_duration_s += f.duration_seconds();
    }
    
    double mean_duration = total_flows > 0 ? (total_duration_s / total_flows) : 0.0;
    
    std::ostringstream ss;
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║              NETWORK FLOW INTELLIGENCE REPORT                ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║ Total Flows Tracked:  " << std::setw(10) << total_flows << "                           ║\n";
    ss << "║ Total Flow Packets:   " << std::setw(10) << total_packets << "                           ║\n";
    ss << "║ Total Flow Volume:    " << std::setw(10) << total_bytes << " bytes                     ║\n";
    ss << "║ Mean Flow Duration:   " << std::setw(10) << std::fixed << std::setprecision(3) << mean_duration << " s                         ║\n";
    ss << "║ Blocked Flows:        " << std::setw(10) << blocked_flows << "                           ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║                    PROTOCOL DISTRIBUTION                     ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║ TCP:                  " << std::setw(10) << tcp_flows 
       << " (" << std::fixed << std::setprecision(1) << (total_flows > 0 ? (100.0 * tcp_flows / total_flows) : 0.0) << "%)                  ║\n";
    ss << "║ UDP:                  " << std::setw(10) << udp_flows 
       << " (" << std::fixed << std::setprecision(1) << (total_flows > 0 ? (100.0 * udp_flows / total_flows) : 0.0) << "%)                  ║\n";
    ss << "║ Other:                " << std::setw(10) << other_flows 
       << " (" << std::fixed << std::setprecision(1) << (total_flows > 0 ? (100.0 * other_flows / total_flows) : 0.0) << "%)                  ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║                  FLOW TERMINATION REASONS                    ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    for (const auto& pair : term_counts) {
        std::string reason_name = flowTerminationReasonToString(pair.first);
        double pct = total_flows > 0 ? (100.0 * pair.second / total_flows) : 0.0;
        ss << "║ " << std::setw(20) << std::left << reason_name
           << std::setw(8) << std::right << pair.second
           << " (" << std::setw(5) << std::fixed << std::setprecision(1) << pct << "%)                ║\n";
    }
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    return ss.str();
}

std::vector<StreamRecordSummary> FPManager::getAllFinalizedStreams() const {
    std::vector<StreamRecordSummary> all_streams;
    for (const auto& fp : fps_) {
        const auto& streams = fp->getStreamManager().getFinalizedSummaries();
        all_streams.insert(all_streams.end(), streams.begin(), streams.end());
    }
    return all_streams;
}

void FPManager::exportAllStreamsJson(std::ostream& os) const {
    auto streams = getAllFinalizedStreams();
    os << "[\n";
    for (size_t i = 0; i < streams.size(); ++i) {
        os << streams[i].toJson();
        if (i + 1 < streams.size()) {
            os << ",";
        }
        os << "\n";
    }
    os << "]\n";
}

void FPManager::exportAllStreamsCsv(std::ostream& os) const {
    os << StreamRecordSummary::csvHeader() << "\n";
    for (const auto& fp : fps_) {
        for (const auto& stream : fp->getStreamManager().getFinalizedSummaries()) {
            os << stream.toCsvRow() << "\n";
        }
    }
}

std::string FPManager::generateStreamStatsReport() const {
    auto streams = getAllFinalizedStreams();
    size_t total_streams = streams.size();
    uint64_t total_fwd_bytes = 0;
    uint64_t total_rev_bytes = 0;
    uint32_t total_ooo = 0;
    uint32_t total_retrans = 0;
    uint32_t total_overlaps = 0;
    uint32_t total_gaps = 0;

    for (const auto& s : streams) {
        total_fwd_bytes += s.fwd.bytes_reassembled;
        total_rev_bytes += s.rev.bytes_reassembled;
        total_ooo += (s.fwd.out_of_order_count + s.rev.out_of_order_count);
        total_retrans += (s.fwd.retrans_count + s.rev.retrans_count);
        total_overlaps += (s.fwd.overlap_count + s.rev.overlap_count);
        total_gaps += (s.fwd.gap_count + s.rev.gap_count);
    }

    std::ostringstream ss;
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║              TCP STREAM REASSEMBLY REPORT                    ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║ Total Streams Tracked:        " << std::setw(10) << total_streams << "                     ║\n";
    ss << "║ Total Reassembled Fwd Bytes:  " << std::setw(10) << total_fwd_bytes << "                     ║\n";
    ss << "║ Total Reassembled Rev Bytes:  " << std::setw(10) << total_rev_bytes << "                     ║\n";
    ss << "║ Total Out-of-Order Segments:  " << std::setw(10) << total_ooo << "                     ║\n";
    ss << "║ Total Retransmissions:        " << std::setw(10) << total_retrans << "                     ║\n";
    ss << "║ Total Overlaps Detected:      " << std::setw(10) << total_overlaps << "                     ║\n";
    ss << "║ Total Gaps Detected:          " << std::setw(10) << total_gaps << "                     ║\n";
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    return ss.str();
}

DNSCorrelator::Stats FPManager::getAggregatedDNSStats() const {
    DNSCorrelator::Stats agg;
    for (const auto& fp : fps_) {
        const auto& s = fp->getDNSCorrelator().getStats();
        agg.total_queries += s.total_queries;
        agg.total_responses += s.total_responses;
        agg.noerror_count += s.noerror_count;
        agg.nxdomain_count += s.nxdomain_count;
        agg.servfail_count += s.servfail_count;
        agg.refused_count += s.refused_count;
        agg.correlated_count += s.correlated_count;
        agg.total_latency_us += s.total_latency_us;
    }
    return agg;
}

} // namespace DPI
