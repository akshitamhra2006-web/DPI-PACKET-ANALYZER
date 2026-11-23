#include "detection_config.h"
#include <algorithm>

namespace DPI {

bool DetectionConfig::validate() const {
    if (port_scan_vertical_port_threshold == 0 || port_scan_horizontal_ip_threshold == 0 || port_scan_window_us == 0) {
        return false;
    }
    if (burst_flow_count_threshold == 0 || burst_window_us == 0) {
        return false;
    }
    if (repeated_attempts_threshold == 0 || repeated_attempts_window_us == 0) {
        return false;
    }
    if (repeated_attempts_fail_ratio < 0.0 || repeated_attempts_fail_ratio > 1.0) {
        return false;
    }
    if (dns_query_count_threshold == 0 || dns_query_window_us == 0 || dns_domain_length_threshold == 0 || dns_nxdomain_burst_threshold == 0) {
        return false;
    }
    if (outbound_bytes_threshold == 0 || outbound_asymmetry_ratio_threshold < 0.0) {
        return false;
    }
    if (beacon_min_connections < 2 || beacon_max_jitter_cv <= 0.0) {
        return false;
    }
    if (tcp_syn_heavy_ratio < 0.0 || tcp_syn_heavy_ratio > 1.0) {
        return false;
    }
    if (tcp_rst_ratio_threshold < 0.0 || tcp_rst_ratio_threshold > 1.0) {
        return false;
    }
    return true;
}

static std::string normalizeName(const std::string& name) {
    std::string s = name;
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

bool DetectionConfig::setDetectorEnabled(const std::string& name, bool enabled) {
    std::string n = normalizeName(name);
    if (n == "port_scan" || n == "port_scan_detector" || n == "portscan") {
        enable_port_scan = enabled;
        return true;
    }
    if (n == "connection_burst" || n == "connection_burst_detector" || n == "burst") {
        enable_connection_burst = enabled;
        return true;
    }
    if (n == "repeated_attempts" || n == "repeated_attempts_detector" || n == "repeated") {
        enable_repeated_attempts = enabled;
        return true;
    }
    if (n == "dns_anomaly" || n == "dns_anomaly_detector" || n == "dns") {
        enable_dns_anomaly = enabled;
        return true;
    }
    if (n == "outbound_anomaly" || n == "outbound_anomaly_detector" || n == "outbound") {
        enable_outbound_anomaly = enabled;
        return true;
    }
    if (n == "beacon" || n == "beacon_detector" || n == "beaconing") {
        enable_beaconing = enabled;
        return true;
    }
    if (n == "tcp_anomaly" || n == "tcp_anomaly_detector" || n == "tcp") {
        enable_tcp_anomaly = enabled;
        return true;
    }
    return false;
}

bool DetectionConfig::isDetectorEnabled(const std::string& name) const {
    std::string n = normalizeName(name);
    if (n == "port_scan" || n == "port_scan_detector" || n == "portscan") return enable_port_scan;
    if (n == "connection_burst" || n == "connection_burst_detector" || n == "burst") return enable_connection_burst;
    if (n == "repeated_attempts" || n == "repeated_attempts_detector" || n == "repeated") return enable_repeated_attempts;
    if (n == "dns_anomaly" || n == "dns_anomaly_detector" || n == "dns") return enable_dns_anomaly;
    if (n == "outbound_anomaly" || n == "outbound_anomaly_detector" || n == "outbound") return enable_outbound_anomaly;
    if (n == "beacon" || n == "beacon_detector" || n == "beaconing") return enable_beaconing;
    if (n == "tcp_anomaly" || n == "tcp_anomaly_detector" || n == "tcp") return enable_tcp_anomaly;
    return false;
}

} // namespace DPI
