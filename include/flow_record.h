#ifndef DPI_FLOW_RECORD_H
#define DPI_FLOW_RECORD_H

#include "types.h"
#include <string>
#include <vector>
#include <cmath>
#include <cstdint>
#include <limits>
#include <sstream>
#include <iomanip>

namespace DPI {

// ============================================================================
// Flow Direction (Established by the first observed packet)
// ============================================================================
enum class FlowDirection {
    FORWARD, // Originating direction (same as initial packet)
    REVERSE  // Responding direction (opposite of initial packet)
};

std::string flowDirectionToString(FlowDirection dir);

// ============================================================================
// Flow Lifecycle & Termination State
// ============================================================================
enum class FlowLifecycleState {
    NEW,
    ESTABLISHED,
    FIN_WAIT,
    CLOSED,
    TIMED_OUT
};

std::string flowLifecycleStateToString(FlowLifecycleState state);

enum class FlowTerminationReason {
    ACTIVE,             // Flow is still currently active
    NATURAL_FIN_RST,    // Completed via TCP FIN or RST
    IDLE_TIMEOUT,       // Inactivity exceeded timeout threshold
    ACTIVE_TIMEOUT,     // Flow duration exceeded maximum active threshold
    CAPACITY_EVICTION,  // Evicted due to flow table capacity limits
    END_OF_FILE         // Reached end of PCAP capture
};

std::string flowTerminationReasonToString(FlowTerminationReason reason);

// ============================================================================
// Numerically Stable Statistical Accumulator (Welford's Algorithm)
// ============================================================================
struct StatisticalAccumulator {
    uint64_t count = 0;
    double min_val = std::numeric_limits<double>::max();
    double max_val = std::numeric_limits<double>::lowest();
    double sum = 0.0;
    double mean_val = 0.0;
    double m2 = 0.0; // Sum of squares of differences from the mean

    void update(double x) {
        count++;
        sum += x;
        if (x < min_val) min_val = x;
        if (x > max_val) max_val = x;

        double delta = x - mean_val;
        mean_val += delta / count;
        double delta2 = x - mean_val;
        m2 += delta * delta2;
    }

    double min() const { return count > 0 ? min_val : 0.0; }
    double max() const { return count > 0 ? max_val : 0.0; }
    double mean() const { return count > 0 ? mean_val : 0.0; }
    
    // Sample variance: s^2 = m2 / (count - 1)
    double variance() const {
        return (count > 1) ? (m2 / (count - 1)) : 0.0;
    }

    double stddev() const {
        double v = variance();
        return v > 0.0 ? std::sqrt(v) : 0.0;
    }
};

// ============================================================================
// Directional Flow Telemetry & Statistics
// ============================================================================
struct DirectionalStats {
    uint64_t packet_count = 0;
    uint64_t byte_count = 0;

    // Packet length metrics (bytes)
    StatisticalAccumulator packet_size_stats;

    // Inter-Arrival Time metrics (microseconds)
    StatisticalAccumulator iat_stats;
    uint64_t last_packet_time_us = 0;

    // TCP Flag occurrences
    uint32_t syn_count = 0;
    uint32_t ack_count = 0;
    uint32_t fin_count = 0;
    uint32_t rst_count = 0;
    uint32_t psh_count = 0;
    uint32_t urg_count = 0;

    void update(size_t packet_size, uint64_t pkt_time_us, uint8_t tcp_flags);
};

// ============================================================================
// Comprehensive Flow Record
// ============================================================================
struct FlowRecord {
    uint64_t flow_id = 0;

    // Five-Tuple Identifiers
    FiveTuple initial_tuple;   // First-observed packet tuple (defines FORWARD direction)
    FiveTuple canonical_tuple; // Symmetrical canonical representation for table indexing

    // Flow Timing (microsecond precision)
    uint64_t start_time_us = 0;
    uint64_t last_time_us = 0;

    // Lifecycle
    FlowLifecycleState state = FlowLifecycleState::NEW;
    FlowTerminationReason termination_reason = FlowTerminationReason::ACTIVE;

    // Directional telemetry
    DirectionalStats fwd;
    DirectionalStats rev;

    // Combined packet size and IAT metrics
    StatisticalAccumulator total_packet_size_stats;
    StatisticalAccumulator total_iat_stats;
    uint64_t last_total_time_us = 0;

    // Protocol & Threat Metadata
    AppType app_type = AppType::UNKNOWN;
    std::string detected_app_name = "Unknown";
    std::string sni;
    std::string http_host;
    std::string dns_query;

    bool is_blocked = false;
    std::string block_reason;

    // Phase 3.2 Protocol Intelligence & Reassembly Metadata
    uint64_t tcp_fwd_bytes_reassembled = 0;
    uint64_t tcp_rev_bytes_reassembled = 0;
    uint32_t tcp_out_of_order_count = 0;
    uint32_t tcp_retrans_count = 0;
    uint32_t tcp_overlap_count = 0;
    uint32_t tcp_gap_count = 0;
    bool tcp_stream_complete = false;

    // HTTP L7 Metadata
    std::string http_method;
    std::string http_uri;
    int http_status_code = 0;
    std::string http_user_agent;
    int64_t http_content_length = -1;

    // TLS L7 Metadata
    std::string tls_alpn;
    std::string tls_supported_version;
    uint64_t tls_encrypted_bytes = 0;

    // DNS L7 Metadata
    uint16_t dns_tx_id = 0;
    uint8_t dns_rcode = 0;
    std::string dns_rcode_name;
    uint64_t dns_latency_us = 0;
    std::vector<std::string> dns_answers;

    // Phase 3.5 Threat Intelligence Metadata
    uint32_t ioc_match_count = 0;
    std::vector<std::string> matched_ioc_ids;
    std::vector<std::string> matched_ioc_values;
    std::vector<std::string> threat_categories;
    std::string threat_summary;

    // Helpers
    FlowDirection determineDirection(const FiveTuple& pkt_tuple) const;
    void update(const PacketJob& job);
    
    double duration_seconds() const {
        return (last_time_us >= start_time_us) ? (last_time_us - start_time_us) / 1000000.0 : 0.0;
    }

    uint64_t duration_microseconds() const {
        return (last_time_us >= start_time_us) ? (last_time_us - start_time_us) : 0;
    }

    uint64_t total_packets() const {
        return fwd.packet_count + rev.packet_count;
    }

    uint64_t total_bytes() const {
        return fwd.byte_count + rev.byte_count;
    }

    bool has_rate_metrics() const {
        return duration_seconds() > 0.0 && total_packets() > 1;
    }

    double packets_per_second() const {
        double d = duration_seconds();
        return (d > 0.0) ? (total_packets() / d) : 0.0;
    }

    double bytes_per_second() const {
        double d = duration_seconds();
        return (d > 0.0) ? (total_bytes() / d) : 0.0;
    }

    double byte_asymmetry_ratio() const {
        return static_cast<double>(fwd.byte_count) / static_cast<double>(rev.byte_count + 1);
    }

    double packet_asymmetry_ratio() const {
        return static_cast<double>(fwd.packet_count) / static_cast<double>(rev.packet_count + 1);
    }

    // Serialization
    std::string toJson() const;
    std::string toCsvRow() const;
    static std::string csvHeader();
};

} // namespace DPI

#endif // DPI_FLOW_RECORD_H
