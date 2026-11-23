#include "flow_record.h"
#include "packet_parser.h"
#include "rule_manager.h"
#include <iomanip>
#include <sstream>

namespace DPI {

std::string flowDirectionToString(FlowDirection dir) {
    switch (dir) {
        case FlowDirection::FORWARD: return "FORWARD";
        case FlowDirection::REVERSE: return "REVERSE";
        default: return "UNKNOWN";
    }
}

std::string flowLifecycleStateToString(FlowLifecycleState state) {
    switch (state) {
        case FlowLifecycleState::NEW: return "NEW";
        case FlowLifecycleState::ESTABLISHED: return "ESTABLISHED";
        case FlowLifecycleState::FIN_WAIT: return "FIN_WAIT";
        case FlowLifecycleState::CLOSED: return "CLOSED";
        case FlowLifecycleState::TIMED_OUT: return "TIMED_OUT";
        default: return "UNKNOWN";
    }
}

std::string flowTerminationReasonToString(FlowTerminationReason reason) {
    switch (reason) {
        case FlowTerminationReason::ACTIVE: return "ACTIVE";
        case FlowTerminationReason::NATURAL_FIN_RST: return "NATURAL_FIN_RST";
        case FlowTerminationReason::IDLE_TIMEOUT: return "IDLE_TIMEOUT";
        case FlowTerminationReason::ACTIVE_TIMEOUT: return "ACTIVE_TIMEOUT";
        case FlowTerminationReason::CAPACITY_EVICTION: return "CAPACITY_EVICTION";
        case FlowTerminationReason::END_OF_FILE: return "END_OF_FILE";
        default: return "UNKNOWN";
    }
}

void DirectionalStats::update(size_t packet_size, uint64_t pkt_time_us, uint8_t tcp_flags) {
    packet_count++;
    byte_count += packet_size;
    packet_size_stats.update(static_cast<double>(packet_size));

    if (last_packet_time_us > 0 && pkt_time_us >= last_packet_time_us) {
        iat_stats.update(static_cast<double>(pkt_time_us - last_packet_time_us));
    }
    last_packet_time_us = pkt_time_us;

    if (tcp_flags & 0x02) syn_count++;
    if (tcp_flags & 0x10) ack_count++;
    if (tcp_flags & 0x01) fin_count++;
    if (tcp_flags & 0x04) rst_count++;
    if (tcp_flags & 0x08) psh_count++;
    if (tcp_flags & 0x20) urg_count++;
}

FlowDirection FlowRecord::determineDirection(const FiveTuple& pkt_tuple) const {
    if (pkt_tuple.src_ip == initial_tuple.src_ip && pkt_tuple.src_port == initial_tuple.src_port) {
        return FlowDirection::FORWARD;
    }
    return FlowDirection::REVERSE;
}

void FlowRecord::update(const PacketJob& job) {
    uint64_t pkt_time_us = static_cast<uint64_t>(job.ts_sec) * 1000000ULL + job.ts_usec;
    if (start_time_us == 0) {
        start_time_us = pkt_time_us;
    }
    last_time_us = pkt_time_us;

    total_packet_size_stats.update(static_cast<double>(job.data.size()));
    if (last_total_time_us > 0 && pkt_time_us >= last_total_time_us) {
        total_iat_stats.update(static_cast<double>(pkt_time_us - last_total_time_us));
    }
    last_total_time_us = pkt_time_us;

    FlowDirection dir = determineDirection(job.tuple);
    if (dir == FlowDirection::FORWARD) {
        fwd.update(job.data.size(), pkt_time_us, job.tcp_flags);
    } else {
        rev.update(job.data.size(), pkt_time_us, job.tcp_flags);
    }

    // TCP state transitions
    if (job.tuple.protocol == 6) {
        if (job.tcp_flags & 0x04) { // RST
            state = FlowLifecycleState::CLOSED;
            termination_reason = FlowTerminationReason::NATURAL_FIN_RST;
        } else if (job.tcp_flags & 0x01) { // FIN
            if (state == FlowLifecycleState::FIN_WAIT) {
                state = FlowLifecycleState::CLOSED;
                termination_reason = FlowTerminationReason::NATURAL_FIN_RST;
            } else {
                state = FlowLifecycleState::FIN_WAIT;
            }
        } else if (state == FlowLifecycleState::NEW) {
            if (job.tcp_flags & 0x10) { // ACK
                state = FlowLifecycleState::ESTABLISHED;
            }
        }
    } else {
        // UDP connectionless state
        state = FlowLifecycleState::ESTABLISHED;
    }
}

std::string FlowRecord::toJson() const {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(4);

    ss << "{\n";
    ss << "  \"flow_id\": " << flow_id << ",\n";
    ss << "  \"protocol\": " << (initial_tuple.protocol == 6 ? "\"TCP\"" : (initial_tuple.protocol == 17 ? "\"UDP\"" : "\"OTHER\"")) << ",\n";
    ss << "  \"source_ip\": \"" << RuleManager::ipToString(initial_tuple.src_ip) << "\",\n";
    ss << "  \"destination_ip\": \"" << RuleManager::ipToString(initial_tuple.dst_ip) << "\",\n";
    ss << "  \"source_port\": " << initial_tuple.src_port << ",\n";
    ss << "  \"destination_port\": " << initial_tuple.dst_port << ",\n";
    ss << "  \"state\": \"" << flowLifecycleStateToString(state) << "\",\n";
    ss << "  \"termination_reason\": \"" << flowTerminationReasonToString(termination_reason) << "\",\n";
    ss << "  \"start_time_us\": " << start_time_us << ",\n";
    ss << "  \"last_time_us\": " << last_time_us << ",\n";
    ss << "  \"duration_seconds\": " << duration_seconds() << ",\n";
    
    // Overall Counts and Rates
    ss << "  \"total_packets\": " << total_packets() << ",\n";
    ss << "  \"total_bytes\": " << total_bytes() << ",\n";
    ss << "  \"packets_per_second\": " << packets_per_second() << ",\n";
    ss << "  \"bytes_per_second\": " << bytes_per_second() << ",\n";
    ss << "  \"has_rate_metrics\": " << (has_rate_metrics() ? "true" : "false") << ",\n";
    ss << "  \"byte_asymmetry_ratio\": " << byte_asymmetry_ratio() << ",\n";
    ss << "  \"packet_asymmetry_ratio\": " << packet_asymmetry_ratio() << ",\n";

    // Packet Size Metrics
    ss << "  \"packet_size\": {\n";
    ss << "    \"min\": " << total_packet_size_stats.min() << ",\n";
    ss << "    \"max\": " << total_packet_size_stats.max() << ",\n";
    ss << "    \"mean\": " << total_packet_size_stats.mean() << ",\n";
    ss << "    \"variance\": " << total_packet_size_stats.variance() << ",\n";
    ss << "    \"stddev\": " << total_packet_size_stats.stddev() << "\n";
    ss << "  },\n";

    // Inter-Arrival Time Metrics
    ss << "  \"iat_microseconds\": {\n";
    ss << "    \"min\": " << total_iat_stats.min() << ",\n";
    ss << "    \"max\": " << total_iat_stats.max() << ",\n";
    ss << "    \"mean\": " << total_iat_stats.mean() << ",\n";
    ss << "    \"variance\": " << total_iat_stats.variance() << ",\n";
    ss << "    \"stddev\": " << total_iat_stats.stddev() << "\n";
    ss << "  },\n";

    // Forward Direction Telemetry
    ss << "  \"forward\": {\n";
    ss << "    \"packets\": " << fwd.packet_count << ",\n";
    ss << "    \"bytes\": " << fwd.byte_count << ",\n";
    ss << "    \"size_mean\": " << fwd.packet_size_stats.mean() << ",\n";
    ss << "    \"size_variance\": " << fwd.packet_size_stats.variance() << ",\n";
    ss << "    \"iat_mean\": " << fwd.iat_stats.mean() << ",\n";
    ss << "    \"iat_variance\": " << fwd.iat_stats.variance() << ",\n";
    ss << "    \"syn\": " << fwd.syn_count << ",\n";
    ss << "    \"ack\": " << fwd.ack_count << ",\n";
    ss << "    \"fin\": " << fwd.fin_count << ",\n";
    ss << "    \"rst\": " << fwd.rst_count << ",\n";
    ss << "    \"psh\": " << fwd.psh_count << "\n";
    ss << "  },\n";

    // Reverse Direction Telemetry
    ss << "  \"reverse\": {\n";
    ss << "    \"packets\": " << rev.packet_count << ",\n";
    ss << "    \"bytes\": " << rev.byte_count << ",\n";
    ss << "    \"size_mean\": " << rev.packet_size_stats.mean() << ",\n";
    ss << "    \"size_variance\": " << rev.packet_size_stats.variance() << ",\n";
    ss << "    \"iat_mean\": " << rev.iat_stats.mean() << ",\n";
    ss << "    \"iat_variance\": " << rev.iat_stats.variance() << ",\n";
    ss << "    \"syn\": " << rev.syn_count << ",\n";
    ss << "    \"ack\": " << rev.ack_count << ",\n";
    ss << "    \"fin\": " << rev.fin_count << ",\n";
    ss << "    \"rst\": " << rev.rst_count << ",\n";
    ss << "    \"psh\": " << rev.psh_count << "\n";
    ss << "  },\n";

    // Application Metadata & Enforcement
    ss << "  \"app_type\": \"" << appTypeToString(app_type) << "\",\n";
    ss << "  \"sni\": \"" << sni << "\",\n";
    ss << "  \"http_host\": \"" << http_host << "\",\n";
    ss << "  \"dns_query\": \"" << dns_query << "\",\n";
    ss << "  \"is_blocked\": " << (is_blocked ? "true" : "false") << ",\n";
    ss << "  \"block_reason\": \"" << block_reason << "\",\n";

    // Phase 3.2 Protocol Intelligence & Reassembly Metadata
    ss << "  \"tcp_stream\": {\n";
    ss << "    \"fwd_bytes_reassembled\": " << tcp_fwd_bytes_reassembled << ",\n";
    ss << "    \"rev_bytes_reassembled\": " << tcp_rev_bytes_reassembled << ",\n";
    ss << "    \"out_of_order_count\": " << tcp_out_of_order_count << ",\n";
    ss << "    \"retrans_count\": " << tcp_retrans_count << ",\n";
    ss << "    \"overlap_count\": " << tcp_overlap_count << ",\n";
    ss << "    \"gap_count\": " << tcp_gap_count << ",\n";
    ss << "    \"is_complete\": " << (tcp_stream_complete ? "true" : "false") << "\n";
    ss << "  },\n";
    ss << "  \"http\": {\n";
    ss << "    \"method\": \"" << http_method << "\",\n";
    ss << "    \"uri\": \"" << http_uri << "\",\n";
    ss << "    \"status_code\": " << http_status_code << ",\n";
    ss << "    \"user_agent\": \"" << http_user_agent << "\",\n";
    ss << "    \"content_length\": " << http_content_length << "\n";
    ss << "  },\n";
    ss << "  \"tls\": {\n";
    ss << "    \"alpn\": \"" << tls_alpn << "\",\n";
    ss << "    \"supported_version\": \"" << tls_supported_version << "\",\n";
    ss << "    \"encrypted_bytes\": " << tls_encrypted_bytes << "\n";
    ss << "  },\n";
    ss << "  \"dns\": {\n";
    ss << "    \"tx_id\": " << dns_tx_id << ",\n";
    ss << "    \"rcode\": " << static_cast<int>(dns_rcode) << ",\n";
    ss << "    \"rcode_name\": \"" << dns_rcode_name << "\",\n";
    ss << "    \"latency_us\": " << dns_latency_us << "\n";
    ss << "  },\n";
    ss << "  \"threat_intel\": {\n";
    ss << "    \"ioc_match_count\": " << ioc_match_count << ",\n";
    ss << "    \"threat_summary\": \"" << threat_summary << "\",\n";
    ss << "    \"matched_ioc_ids\": [";
    for (size_t i = 0; i < matched_ioc_ids.size(); ++i) {
        ss << "\"" << matched_ioc_ids[i] << "\"" << (i + 1 < matched_ioc_ids.size() ? ", " : "");
    }
    ss << "],\n";
    ss << "    \"threat_categories\": [";
    for (size_t i = 0; i < threat_categories.size(); ++i) {
        ss << "\"" << threat_categories[i] << "\"" << (i + 1 < threat_categories.size() ? ", " : "");
    }
    ss << "]\n";
    ss << "  }\n";
    ss << "}";

    return ss.str();
}

std::string FlowRecord::csvHeader() {
    return "flow_id,protocol,src_ip,dst_ip,src_port,dst_port,state,termination_reason,"
           "duration_sec,total_packets,total_bytes,packets_per_sec,bytes_per_sec,"
           "fwd_packets,fwd_bytes,rev_packets,rev_bytes,"
           "pkt_size_mean,pkt_size_variance,iat_mean_us,iat_variance_us,"
           "fwd_syn,fwd_ack,fwd_fin,fwd_rst,rev_syn,rev_ack,rev_fin,rev_rst,"
           "app_type,sni,is_blocked";
}

std::string FlowRecord::toCsvRow() const {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(4);

    ss << flow_id << ","
       << (initial_tuple.protocol == 6 ? "TCP" : "UDP") << ","
       << RuleManager::ipToString(initial_tuple.src_ip) << ","
       << RuleManager::ipToString(initial_tuple.dst_ip) << ","
       << initial_tuple.src_port << ","
       << initial_tuple.dst_port << ","
       << flowLifecycleStateToString(state) << ","
       << flowTerminationReasonToString(termination_reason) << ","
       << duration_seconds() << ","
       << total_packets() << ","
       << total_bytes() << ","
       << packets_per_second() << ","
       << bytes_per_second() << ","
       << fwd.packet_count << ","
       << fwd.byte_count << ","
       << rev.packet_count << ","
       << rev.byte_count << ","
       << total_packet_size_stats.mean() << ","
       << total_packet_size_stats.variance() << ","
       << total_iat_stats.mean() << ","
       << total_iat_stats.variance() << ","
       << fwd.syn_count << ","
       << fwd.ack_count << ","
       << fwd.fin_count << ","
       << fwd.rst_count << ","
       << rev.syn_count << ","
       << rev.ack_count << ","
       << rev.fin_count << ","
       << rev.rst_count << ","
       << appTypeToString(app_type) << ","
       << "\"" << sni << "\","
       << (is_blocked ? "1" : "0");

    return ss.str();
}

} // namespace DPI
