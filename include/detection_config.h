#ifndef DPI_DETECTION_CONFIG_H
#define DPI_DETECTION_CONFIG_H

#include <string>
#include <cstdint>
#include <cstddef>

namespace DPI {

struct DetectionConfig {
    // Detector Enablement Flags
    bool enable_port_scan = true;
    bool enable_connection_burst = true;
    bool enable_repeated_attempts = true;
    bool enable_dns_anomaly = true;
    bool enable_outbound_anomaly = true;
    bool enable_beaconing = true;
    bool enable_tcp_anomaly = true;

    // A. Port Scan Thresholds
    size_t port_scan_vertical_port_threshold = 10;      // Unique ports to single dst IP within window
    size_t port_scan_horizontal_ip_threshold = 10;      // Unique dst IPs on same port within window
    uint64_t port_scan_window_us = 10000000ULL;         // 10-second sliding window

    // B. Connection Burst Thresholds
    size_t burst_flow_count_threshold = 15;             // Flows initiated by a source IP within window
    uint64_t burst_window_us = 2000000ULL;              // 2-second sliding window

    // C. Repeated Connection Attempt Thresholds
    size_t repeated_attempts_threshold = 5;             // Flows to exact same (dst_ip, dst_port)
    uint64_t repeated_attempts_window_us = 10000000ULL; // 10-second sliding window
    double repeated_attempts_fail_ratio = 0.60;         // Incomplete / failed connection ratio

    // D. DNS Anomaly Thresholds
    size_t dns_query_count_threshold = 20;              // Total queries within window
    uint64_t dns_query_window_us = 10000000ULL;         // 10-second window
    size_t dns_domain_length_threshold = 45;            // Query string character length
    size_t dns_subdomain_depth_threshold = 5;           // Subdomain dot count >= 5
    size_t dns_unique_domain_threshold = 15;            // Distinct domains within window
    bool enable_dns_nxdomain_detection = true;          // Flag high NXDOMAIN counts (DGA indicator)
    size_t dns_nxdomain_burst_threshold = 5;            // Minimum NXDOMAIN responses to alert

    // E. Outbound Volume Anomaly Thresholds
    uint64_t outbound_bytes_threshold = 5000000ULL;     // 5 MB default volume threshold
    double outbound_asymmetry_ratio_threshold = 10.0;   // Forward / reverse byte asymmetry >= 10.0

    // F. Beacon-Like Communication Thresholds
    size_t beacon_min_connections = 4;                 // Minimum connections to same destination
    double beacon_max_jitter_cv = 0.20;                 // Max coefficient of variation (stddev / mean <= 20%)
    double beacon_min_interval_seconds = 0.5;          // Minimum mean interval (avoid sub-second bursts)

    // G. TCP Anomaly Thresholds
    double tcp_syn_heavy_ratio = 0.85;                  // SYN-heavy flows / total TCP flows >= 0.85
    size_t tcp_min_syn_flows = 5;                      // Minimum flows to evaluate ratio
    double tcp_rst_ratio_threshold = 0.40;              // RST packets / total packets >= 0.40
    size_t tcp_min_rst_flows = 5;

    // Validation
    bool validate() const;

    // Helper to toggle detectors by name
    bool setDetectorEnabled(const std::string& name, bool enabled);
    bool isDetectorEnabled(const std::string& name) const;
};

} // namespace DPI

#endif // DPI_DETECTION_CONFIG_H
