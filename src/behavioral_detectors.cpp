#include "behavioral_detectors.h"
#include "rule_manager.h"
#include <map>
#include <set>
#include <cmath>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace DPI {

namespace {

// Helper to format microsecond timestamp into ISO 8601 or relative format
std::string formatIsoTimestamp(uint64_t ts_us) {
    uint64_t sec = ts_us / 1000000ULL;
    uint32_t usec = static_cast<uint32_t>(ts_us % 1000000ULL);

    if (sec > 1500000000ULL) { // Epoch timestamp (> year 2017)
        time_t t = static_cast<time_t>(sec);
        struct tm tm_buf;
        gmtime_r(&t, &tm_buf);
        char buf[64];
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);
        char full[128];
        snprintf(full, sizeof(full), "%s.%03uZ", buf, usec / 1000);
        return std::string(full);
    }

    std::ostringstream ss;
    ss << "T+" << sec << "." << std::setfill('0') << std::setw(3) << (usec / 1000) << "s";
    return ss.str();
}

std::string generateEventId(const std::string& prefix, uint32_t src_ip, uint64_t ts_us, size_t counter) {
    std::ostringstream ss;
    ss << prefix << "-" << std::hex << src_ip << "-" << (ts_us / 1000ULL) << "-" << counter;
    return ss.str();
}

} // anonymous namespace

// ============================================================================
// A. PortScanDetector Implementation
// ============================================================================
std::vector<DetectionEvent> PortScanDetector::detect(
    const std::vector<FlowRecord>& flows,
    const DetectionConfig& config) {
    
    std::vector<DetectionEvent> events;
    if (!config.enable_port_scan || flows.empty()) return events;

    // Group flows by source IP
    std::map<uint32_t, std::vector<const FlowRecord*>> src_flow_map;
    for (const auto& f : flows) {
        src_flow_map[f.initial_tuple.src_ip].push_back(&f);
    }

    size_t event_counter = 0;

    for (const auto& pair : src_flow_map) {
        uint32_t src_ip = pair.first;
        const auto& src_flows = pair.second;

        // 1. Vertical Port Scan: (src_ip -> dst_ip, multiple ports)
        std::map<uint32_t, std::vector<const FlowRecord*>> dst_map;
        for (const auto* f : src_flows) {
            dst_map[f->initial_tuple.dst_ip].push_back(f);
        }

        for (const auto& dst_pair : dst_map) {
            uint32_t dst_ip = dst_pair.first;
            const auto& host_flows = dst_pair.second;

            // Sort flows by start time
            std::vector<const FlowRecord*> sorted_flows = host_flows;
            std::sort(sorted_flows.begin(), sorted_flows.end(), [](const FlowRecord* a, const FlowRecord* b) {
                return a->start_time_us < b->start_time_us;
            });

            // Sliding window to find unique ports
            for (size_t i = 0; i < sorted_flows.size(); ++i) {
                uint64_t window_start = sorted_flows[i]->start_time_us;
                uint64_t window_end = window_start + config.port_scan_window_us;

                std::set<uint16_t> unique_ports;
                std::vector<uint64_t> flow_ids;
                size_t incomplete_count = 0;

                for (size_t j = i; j < sorted_flows.size(); ++j) {
                    if (sorted_flows[j]->start_time_us > window_end) break;

                    unique_ports.insert(sorted_flows[j]->initial_tuple.dst_port);
                    flow_ids.push_back(sorted_flows[j]->flow_id);

                    if (sorted_flows[j]->rev.packet_count == 0 || 
                        sorted_flows[j]->termination_reason == FlowTerminationReason::IDLE_TIMEOUT) {
                        incomplete_count++;
                    }
                }

                if (unique_ports.size() >= config.port_scan_vertical_port_threshold) {
                    DetectionEvent ev;
                    ev.detection_id = generateEventId("DET-SCAN-V", src_ip, window_start, ++event_counter);
                    ev.detector_name = getName();
                    ev.category = getCategory();
                    ev.timestamp_us = window_start;
                    ev.timestamp_iso = formatIsoTimestamp(window_start);
                    ev.source_ip = src_ip;
                    ev.destination_ip = dst_ip;
                    ev.source_ip_str = RuleManager::ipToString(src_ip);
                    ev.destination_ip_str = RuleManager::ipToString(dst_ip);
                    ev.protocol = sorted_flows[i]->initial_tuple.protocol;

                    for (uint16_t p : unique_ports) {
                        ev.relevant_ports.push_back(p);
                        if (ev.relevant_ports.size() >= 20) break; // cap sample list
                    }
                    ev.related_flow_ids = flow_ids;

                    double incomplete_ratio = flow_ids.empty() ? 0.0 : 
                        static_cast<double>(incomplete_count) / flow_ids.size();

                    ev.severity = (incomplete_ratio >= 0.70 && unique_ports.size() >= config.port_scan_vertical_port_threshold * 2) 
                                  ? DetectionSeverity::HIGH : DetectionSeverity::MEDIUM;

                    ev.evidence["scan_type"] = "vertical_port_scan";
                    ev.evidence["unique_destination_ports"] = std::to_string(unique_ports.size());
                    ev.evidence["window_seconds"] = std::to_string(config.port_scan_window_us / 1000000.0);
                    ev.evidence["threshold"] = std::to_string(config.port_scan_vertical_port_threshold);
                    ev.evidence["observed_metric"] = std::to_string(unique_ports.size()) + " ports contacted";
                    ev.evidence["incomplete_ratio"] = std::to_string(incomplete_ratio);

                    ev.explanation = "Source host initiated connections to " + std::to_string(unique_ports.size()) +
                                     " distinct destination ports on " + ev.destination_ip_str + 
                                     " within a " + std::to_string(config.port_scan_window_us / 1000000ULL) + "-second window.";
                    ev.limitations = {
                        "Port diversity alone does not establish malicious intent; authorized vulnerability scanners and administrative tools generate similar profiles.",
                        "Offline PCAP analysis cannot confirm whether uncontacted services dropped packets or were filtered upstream."
                    };
                    ev.recommended_actions = {
                        "Verify if the source IP is an authorized network scanner or inventory asset.",
                        "Inspect target host firewall logs to confirm connection rejection status."
                    };

                    events.push_back(std::move(ev));
                    break; // Advance to next target host to avoid duplicate alerts in same window
                }
            }
        }

        // 2. Horizontal Port Scan: (src_ip, same dst_port -> multiple dst_ips)
        std::map<uint16_t, std::vector<const FlowRecord*>> port_map;
        for (const auto* f : src_flows) {
            port_map[f->initial_tuple.dst_port].push_back(f);
        }

        for (const auto& port_pair : port_map) {
            uint16_t dst_port = port_pair.first;
            const auto& port_flows = port_pair.second;

            std::vector<const FlowRecord*> sorted_flows = port_flows;
            std::sort(sorted_flows.begin(), sorted_flows.end(), [](const FlowRecord* a, const FlowRecord* b) {
                return a->start_time_us < b->start_time_us;
            });

            for (size_t i = 0; i < sorted_flows.size(); ++i) {
                uint64_t window_start = sorted_flows[i]->start_time_us;
                uint64_t window_end = window_start + config.port_scan_window_us;

                std::set<uint32_t> unique_dst_ips;
                std::vector<uint64_t> flow_ids;

                for (size_t j = i; j < sorted_flows.size(); ++j) {
                    if (sorted_flows[j]->start_time_us > window_end) break;
                    unique_dst_ips.insert(sorted_flows[j]->initial_tuple.dst_ip);
                    flow_ids.push_back(sorted_flows[j]->flow_id);
                }

                if (unique_dst_ips.size() >= config.port_scan_horizontal_ip_threshold) {
                    DetectionEvent ev;
                    ev.detection_id = generateEventId("DET-SCAN-H", src_ip, window_start, ++event_counter);
                    ev.detector_name = getName();
                    ev.category = getCategory();
                    ev.timestamp_us = window_start;
                    ev.timestamp_iso = formatIsoTimestamp(window_start);
                    ev.source_ip = src_ip;
                    ev.destination_ip = 0; // Multiple targets
                    ev.source_ip_str = RuleManager::ipToString(src_ip);
                    ev.destination_ip_str = "MULTIPLE (" + std::to_string(unique_dst_ips.size()) + " hosts)";
                    ev.protocol = sorted_flows[i]->initial_tuple.protocol;
                    ev.relevant_ports.push_back(dst_port);
                    ev.related_flow_ids = flow_ids;
                    ev.severity = DetectionSeverity::MEDIUM;

                    ev.evidence["scan_type"] = "horizontal_ip_sweep";
                    ev.evidence["target_port"] = std::to_string(dst_port);
                    ev.evidence["unique_target_ips"] = std::to_string(unique_dst_ips.size());
                    ev.evidence["threshold"] = std::to_string(config.port_scan_horizontal_ip_threshold);
                    ev.evidence["observed_metric"] = std::to_string(unique_dst_ips.size()) + " target IPs";

                    ev.explanation = "Source host swept " + std::to_string(unique_dst_ips.size()) +
                                     " distinct destination hosts targeting port " + std::to_string(dst_port) + ".";
                    ev.limitations = {
                        "Subnet discovery, multicast protocols, and cluster heartbeat probes can exhibit multi-host sweep patterns.",
                        "Traffic may originate from a legitimate network management probe."
                    };
                    ev.recommended_actions = {
                        "Determine if the source system is authorized for network discovery.",
                        "Inspect target subnet range to determine if discovery is internal or internet-wide."
                    };

                    events.push_back(std::move(ev));
                    break;
                }
            }
        }
    }

    return events;
}

// ============================================================================
// B. ConnectionBurstDetector Implementation
// ============================================================================
std::vector<DetectionEvent> ConnectionBurstDetector::detect(
    const std::vector<FlowRecord>& flows,
    const DetectionConfig& config) {

    std::vector<DetectionEvent> events;
    if (!config.enable_connection_burst || flows.empty()) return events;

    std::map<uint32_t, std::vector<const FlowRecord*>> src_flow_map;
    for (const auto& f : flows) {
        src_flow_map[f.initial_tuple.src_ip].push_back(&f);
    }

    size_t event_counter = 0;

    for (const auto& pair : src_flow_map) {
        uint32_t src_ip = pair.first;
        std::vector<const FlowRecord*> sorted_flows = pair.second;
        std::sort(sorted_flows.begin(), sorted_flows.end(), [](const FlowRecord* a, const FlowRecord* b) {
            return a->start_time_us < b->start_time_us;
        });

        for (size_t i = 0; i < sorted_flows.size(); ++i) {
            uint64_t window_start = sorted_flows[i]->start_time_us;
            uint64_t window_end = window_start + config.burst_window_us;

            std::vector<uint64_t> flow_ids;
            std::set<uint32_t> dst_ips;
            std::set<uint16_t> dst_ports;

            for (size_t j = i; j < sorted_flows.size(); ++j) {
                if (sorted_flows[j]->start_time_us > window_end) break;
                flow_ids.push_back(sorted_flows[j]->flow_id);
                dst_ips.insert(sorted_flows[j]->initial_tuple.dst_ip);
                dst_ports.insert(sorted_flows[j]->initial_tuple.dst_port);
            }

            if (flow_ids.size() >= config.burst_flow_count_threshold) {
                DetectionEvent ev;
                ev.detection_id = generateEventId("DET-BURST", src_ip, window_start, ++event_counter);
                ev.detector_name = getName();
                ev.category = getCategory();
                ev.timestamp_us = window_start;
                ev.timestamp_iso = formatIsoTimestamp(window_start);
                ev.source_ip = src_ip;
                ev.destination_ip = (dst_ips.size() == 1) ? *dst_ips.begin() : 0;
                ev.source_ip_str = RuleManager::ipToString(src_ip);
                ev.destination_ip_str = (dst_ips.size() == 1) ? RuleManager::ipToString(*dst_ips.begin()) 
                                                              : "MULTIPLE (" + std::to_string(dst_ips.size()) + " hosts)";
                ev.protocol = sorted_flows[i]->initial_tuple.protocol;
                for (uint16_t p : dst_ports) {
                    ev.relevant_ports.push_back(p);
                    if (ev.relevant_ports.size() >= 10) break;
                }
                ev.related_flow_ids = flow_ids;
                ev.severity = (flow_ids.size() >= config.burst_flow_count_threshold * 2) 
                              ? DetectionSeverity::MEDIUM : DetectionSeverity::LOW;

                ev.evidence["flow_count"] = std::to_string(flow_ids.size());
                ev.evidence["window_seconds"] = std::to_string(config.burst_window_us / 1000000.0);
                ev.evidence["threshold"] = std::to_string(config.burst_flow_count_threshold);
                ev.evidence["observed_metric"] = std::to_string(flow_ids.size()) + " flows in window";
                ev.evidence["destination_ip_count"] = std::to_string(dst_ips.size());

                ev.explanation = "Source host initiated a surge of " + std::to_string(flow_ids.size()) +
                                 " new connections within a " + std::to_string(config.burst_window_us / 1000000.0) + "-second window.";
                ev.limitations = {
                    "Short-lived connection bursts are common during browser multi-asset loading, application startup, and batch syncs.",
                    "Burst detection does not indicate payload content or malicious intent."
                };
                ev.recommended_actions = {
                    "Identify the local software or script initiating high-frequency connections.",
                    "Verify if burst aligns with a scheduled sync or automated workload."
                };

                events.push_back(std::move(ev));
                i += flow_ids.size(); // Skip past this burst window
            }
        }
    }

    return events;
}

// ============================================================================
// C. RepeatedAttemptsDetector Implementation
// ============================================================================
std::vector<DetectionEvent> RepeatedAttemptsDetector::detect(
    const std::vector<FlowRecord>& flows,
    const DetectionConfig& config) {

    std::vector<DetectionEvent> events;
    if (!config.enable_repeated_attempts || flows.empty()) return events;

    // Group by (src_ip, dst_ip, dst_port)
    struct EndpointKey {
        uint32_t src;
        uint32_t dst;
        uint16_t port;
        bool operator<(const EndpointKey& o) const {
            if (src != o.src) return src < o.src;
            if (dst != o.dst) return dst < o.dst;
            return port < o.port;
        }
    };

    std::map<EndpointKey, std::vector<const FlowRecord*>> endpoint_map;
    for (const auto& f : flows) {
        EndpointKey k{f.initial_tuple.src_ip, f.initial_tuple.dst_ip, f.initial_tuple.dst_port};
        endpoint_map[k].push_back(&f);
    }

    size_t event_counter = 0;

    for (const auto& pair : endpoint_map) {
        const auto& key = pair.first;
        std::vector<const FlowRecord*> sorted_flows = pair.second;
        std::sort(sorted_flows.begin(), sorted_flows.end(), [](const FlowRecord* a, const FlowRecord* b) {
            return a->start_time_us < b->start_time_us;
        });

        for (size_t i = 0; i < sorted_flows.size(); ++i) {
            uint64_t window_start = sorted_flows[i]->start_time_us;
            uint64_t window_end = window_start + config.repeated_attempts_window_us;

            std::vector<uint64_t> flow_ids;
            size_t failed_count = 0;

            for (size_t j = i; j < sorted_flows.size(); ++j) {
                if (sorted_flows[j]->start_time_us > window_end) break;
                flow_ids.push_back(sorted_flows[j]->flow_id);

                // Failed / Incomplete indicator: 0 reply packets or RST termination or unacknowledged SYN
                if (sorted_flows[j]->rev.packet_count == 0 ||
                    (sorted_flows[j]->fwd.syn_count > 0 && sorted_flows[j]->fwd.ack_count == 0) ||
                    sorted_flows[j]->rev.rst_count > 0 ||
                    sorted_flows[j]->termination_reason == FlowTerminationReason::IDLE_TIMEOUT) {
                    failed_count++;
                }
            }

            double fail_ratio = flow_ids.empty() ? 0.0 : static_cast<double>(failed_count) / flow_ids.size();

            if (flow_ids.size() >= config.repeated_attempts_threshold &&
                fail_ratio >= config.repeated_attempts_fail_ratio) {
                
                DetectionEvent ev;
                ev.detection_id = generateEventId("DET-REPEAT", key.src, window_start, ++event_counter);
                ev.detector_name = getName();
                ev.category = getCategory();
                ev.timestamp_us = window_start;
                ev.timestamp_iso = formatIsoTimestamp(window_start);
                ev.source_ip = key.src;
                ev.destination_ip = key.dst;
                ev.source_ip_str = RuleManager::ipToString(key.src);
                ev.destination_ip_str = RuleManager::ipToString(key.dst);
                ev.protocol = sorted_flows[i]->initial_tuple.protocol;
                ev.relevant_ports.push_back(key.port);
                ev.related_flow_ids = flow_ids;
                ev.severity = (flow_ids.size() >= config.repeated_attempts_threshold * 2) 
                              ? DetectionSeverity::MEDIUM : DetectionSeverity::LOW;

                ev.evidence["attempts_count"] = std::to_string(flow_ids.size());
                ev.evidence["failed_count"] = std::to_string(failed_count);
                ev.evidence["fail_ratio"] = std::to_string(fail_ratio);
                ev.evidence["threshold"] = std::to_string(config.repeated_attempts_threshold);
                ev.evidence["observed_metric"] = std::to_string(flow_ids.size()) + " attempts (" +
                                                 std::to_string(static_cast<int>(fail_ratio * 100)) + "% incomplete)";

                ev.explanation = "Source host made " + std::to_string(flow_ids.size()) +
                                 " repeated connection attempts to " + ev.destination_ip_str + ":" + 
                                 std::to_string(key.port) + " with a high rate of uncompleted handshakes.";
                ev.limitations = {
                    "Offline PCAPs with asymmetric routes or capture point filters may omit legitimate server ACK responses.",
                    "Legitimate network services retrying during brief outages can produce this pattern."
                };
                ev.recommended_actions = {
                    "Verify target service operational status and port availability.",
                    "Assess whether repeated connection attempts stem from misconfigured application retry loops."
                };

                events.push_back(std::move(ev));
                i += flow_ids.size();
            }
        }
    }

    return events;
}

// ============================================================================
// D. DNSAnomalyDetector Implementation
// ============================================================================
std::vector<DetectionEvent> DNSAnomalyDetector::detect(
    const std::vector<FlowRecord>& flows,
    const DetectionConfig& config) {

    std::vector<DetectionEvent> events;
    if (!config.enable_dns_anomaly || flows.empty()) return events;

    std::vector<const FlowRecord*> dns_flows;
    for (const auto& f : flows) {
        if (f.app_type == AppType::DNS || f.initial_tuple.dst_port == 53 || f.initial_tuple.src_port == 53) {
            dns_flows.push_back(&f);
        }
    }
    if (dns_flows.empty()) return events;

    size_t event_counter = 0;

    // 1. Check for suspiciously long domain names / high subdomain depth (DNS Tunneling candidates)
    for (const auto* f : dns_flows) {
        if (f->dns_query.empty()) continue;

        const std::string& query = f->dns_query;
        size_t query_len = query.length();

        // Count subdomains by dots
        size_t dot_count = std::count(query.begin(), query.end(), '.');

        if (query_len >= config.dns_domain_length_threshold || dot_count >= config.dns_subdomain_depth_threshold) {
            DetectionEvent ev;
            ev.detection_id = generateEventId("DET-DNS-TUNNEL", f->initial_tuple.src_ip, f->start_time_us, ++event_counter);
            ev.detector_name = getName();
            ev.category = getCategory();
            ev.timestamp_us = f->start_time_us;
            ev.timestamp_iso = formatIsoTimestamp(f->start_time_us);
            ev.source_ip = f->initial_tuple.src_ip;
            ev.destination_ip = f->initial_tuple.dst_ip;
            ev.source_ip_str = RuleManager::ipToString(f->initial_tuple.src_ip);
            ev.destination_ip_str = RuleManager::ipToString(f->initial_tuple.dst_ip);
            ev.protocol = f->initial_tuple.protocol;
            ev.relevant_ports.push_back(f->initial_tuple.dst_port);
            ev.related_flow_ids = {f->flow_id};
            ev.severity = (query_len >= config.dns_domain_length_threshold * 2) 
                          ? DetectionSeverity::HIGH : DetectionSeverity::MEDIUM;

            ev.evidence["dns_query"] = query;
            ev.evidence["query_length"] = std::to_string(query_len);
            ev.evidence["subdomain_depth"] = std::to_string(dot_count);
            ev.evidence["threshold_length"] = std::to_string(config.dns_domain_length_threshold);
            ev.evidence["threshold_depth"] = std::to_string(config.dns_subdomain_depth_threshold);
            ev.evidence["observed_metric"] = "Length " + std::to_string(query_len) + ", " + 
                                             std::to_string(dot_count) + " subdomains";

            ev.explanation = "Observed DNS query for '" + query + "' exhibits unusually long length (" +
                             std::to_string(query_len) + " chars) or high subdomain depth (" +
                             std::to_string(dot_count) + " levels), characteristic of encoded data tunneling.";
            ev.limitations = {
                "CDNs, anti-spam blocklists (DNSBL), and antivirus reputation lookups frequently query long encoded labels.",
                "Query length alone does not confirm data exfiltration without payload entropy validation."
            };
            ev.recommended_actions = {
                "Inspect the parent domain and nameserver authoritative delegation for the queried hostname.",
                "Review endpoint processes issuing long DNS requests."
            };

            events.push_back(std::move(ev));
        }
    }

    // 2. High DNS query frequency / high domain diversity
    std::map<uint32_t, std::vector<const FlowRecord*>> src_dns_map;
    for (const auto* f : dns_flows) {
        src_dns_map[f->initial_tuple.src_ip].push_back(f);
    }

    for (const auto& pair : src_dns_map) {
        uint32_t src_ip = pair.first;
        std::vector<const FlowRecord*> sorted_flows = pair.second;
        std::sort(sorted_flows.begin(), sorted_flows.end(), [](const FlowRecord* a, const FlowRecord* b) {
            return a->start_time_us < b->start_time_us;
        });

        for (size_t i = 0; i < sorted_flows.size(); ++i) {
            uint64_t window_start = sorted_flows[i]->start_time_us;
            uint64_t window_end = window_start + config.dns_query_window_us;

            std::vector<uint64_t> flow_ids;
            std::set<std::string> unique_domains;

            for (size_t j = i; j < sorted_flows.size(); ++j) {
                if (sorted_flows[j]->start_time_us > window_end) break;
                flow_ids.push_back(sorted_flows[j]->flow_id);
                if (!sorted_flows[j]->dns_query.empty()) {
                    unique_domains.insert(sorted_flows[j]->dns_query);
                }
            }

            if (flow_ids.size() >= config.dns_query_count_threshold ||
                unique_domains.size() >= config.dns_unique_domain_threshold) {
                
                DetectionEvent ev;
                ev.detection_id = generateEventId("DET-DNS-RATE", src_ip, window_start, ++event_counter);
                ev.detector_name = getName();
                ev.category = getCategory();
                ev.timestamp_us = window_start;
                ev.timestamp_iso = formatIsoTimestamp(window_start);
                ev.source_ip = src_ip;
                ev.destination_ip = sorted_flows[i]->initial_tuple.dst_ip;
                ev.source_ip_str = RuleManager::ipToString(src_ip);
                ev.destination_ip_str = RuleManager::ipToString(sorted_flows[i]->initial_tuple.dst_ip);
                ev.protocol = sorted_flows[i]->initial_tuple.protocol;
                ev.relevant_ports.push_back(53);
                ev.related_flow_ids = flow_ids;
                ev.severity = DetectionSeverity::MEDIUM;

                ev.evidence["query_count"] = std::to_string(flow_ids.size());
                ev.evidence["unique_domain_count"] = std::to_string(unique_domains.size());
                ev.evidence["window_seconds"] = std::to_string(config.dns_query_window_us / 1000000.0);
                ev.evidence["observed_metric"] = std::to_string(flow_ids.size()) + " queries (" +
                                                 std::to_string(unique_domains.size()) + " unique domains)";

                ev.explanation = "Source host generated an elevated volume of " + std::to_string(flow_ids.size()) +
                                 " DNS queries with " + std::to_string(unique_domains.size()) + 
                                 " unique domain names within a " + std::to_string(config.dns_query_window_us / 1000000.0) + "-second window.";
                ev.limitations = {
                    "DNS forwarders, caching resolvers, and web crawlers naturally exhibit high query rates.",
                    "Capture-derived DNS rates do not account for caching on client operating systems."
                };
                ev.recommended_actions = {
                    "Determine whether the querying source is a recursive DNS resolver.",
                    "Check for domain generation algorithm (DGA) malware activity on the source host."
                };

                events.push_back(std::move(ev));
                i += flow_ids.size();
            }
        }
    }

    // 3. High NXDOMAIN Failure Surge (DGA Anomaly Indicator from Phase 3.2 DNS intelligence)
    if (config.enable_dns_nxdomain_detection) {
        for (const auto& pair : src_dns_map) {
            uint32_t src_ip = pair.first;
            size_t nxdomain_count = 0;
            std::vector<uint64_t> nx_flow_ids;
            std::set<std::string> failed_domains;
            uint64_t first_ts = 0;

            for (const auto* f : pair.second) {
                if (f->dns_rcode == 3) { // NXDOMAIN
                    nxdomain_count++;
                    nx_flow_ids.push_back(f->flow_id);
                    if (!f->dns_query.empty()) failed_domains.insert(f->dns_query);
                    if (first_ts == 0) first_ts = f->start_time_us;
                }
            }

            if (nxdomain_count >= config.dns_nxdomain_burst_threshold) {
                DetectionEvent ev;
                ev.detection_id = generateEventId("DET-DNS-NXDOMAIN", src_ip, first_ts, ++event_counter);
                ev.detector_name = getName();
                ev.category = getCategory();
                ev.timestamp_us = first_ts;
                ev.timestamp_iso = formatIsoTimestamp(first_ts);
                ev.source_ip = src_ip;
                ev.destination_ip = pair.second.front()->initial_tuple.dst_ip;
                ev.source_ip_str = RuleManager::ipToString(src_ip);
                ev.destination_ip_str = RuleManager::ipToString(pair.second.front()->initial_tuple.dst_ip);
                ev.protocol = pair.second.front()->initial_tuple.protocol;
                ev.relevant_ports.push_back(53);
                ev.related_flow_ids = nx_flow_ids;
                ev.severity = DetectionSeverity::HIGH;

                ev.evidence["nxdomain_count"] = std::to_string(nxdomain_count);
                ev.evidence["failed_domains_count"] = std::to_string(failed_domains.size());
                ev.evidence["threshold_nxdomain"] = std::to_string(config.dns_nxdomain_burst_threshold);
                ev.evidence["observed_metric"] = std::to_string(nxdomain_count) + " NXDOMAIN responses";

                ev.explanation = "Source host received " + std::to_string(nxdomain_count) +
                                 " NXDOMAIN (Non-Existent Domain) responses, indicating possible DGA (Domain Generation Algorithm) malware querying algorithmically generated rendezvous domains.";
                ev.limitations = {
                    "Misconfigured search domains or typo-squatting defense can cause legitimate NXDOMAIN bursts.",
                    "Verify if host was querying internal search domains that failed to resolve."
                };
                ev.recommended_actions = {
                    "Inspect the failed queried domain names for algorithmic randomness (entropy).",
                    "Isolate the source host and check for running malware or command-and-control beaconing."
                };

                events.push_back(std::move(ev));
            }
        }
    }

    return events;
}

// ============================================================================
// E. OutboundAnomalyDetector Implementation
// ============================================================================
std::vector<DetectionEvent> OutboundAnomalyDetector::detect(
    const std::vector<FlowRecord>& flows,
    const DetectionConfig& config) {

    std::vector<DetectionEvent> events;
    if (!config.enable_outbound_anomaly || flows.empty()) return events;

    size_t event_counter = 0;

    for (const auto& f : flows) {
        uint64_t fwd_bytes = f.fwd.byte_count;
        uint64_t rev_bytes = f.rev.byte_count;
        double asymmetry = f.byte_asymmetry_ratio();

        // Check if forward bytes exceed volume threshold OR exhibit extreme forward asymmetry
        bool exceeds_volume = (fwd_bytes >= config.outbound_bytes_threshold);
        bool severe_asymmetry = (fwd_bytes >= 100000 && asymmetry >= config.outbound_asymmetry_ratio_threshold);

        if (exceeds_volume || severe_asymmetry) {
            DetectionEvent ev;
            ev.detection_id = generateEventId("DET-OUTBOUND", f.initial_tuple.src_ip, f.start_time_us, ++event_counter);
            ev.detector_name = getName();
            ev.category = getCategory();
            ev.timestamp_us = f.start_time_us;
            ev.timestamp_iso = formatIsoTimestamp(f.start_time_us);
            ev.source_ip = f.initial_tuple.src_ip;
            ev.destination_ip = f.initial_tuple.dst_ip;
            ev.source_ip_str = RuleManager::ipToString(f.initial_tuple.src_ip);
            ev.destination_ip_str = RuleManager::ipToString(f.initial_tuple.dst_ip);
            ev.protocol = f.initial_tuple.protocol;
            ev.relevant_ports.push_back(f.initial_tuple.dst_port);
            ev.related_flow_ids = {f.flow_id};

            // Non-standard destination port escalates severity
            bool is_standard_port = (f.initial_tuple.dst_port == 80 || f.initial_tuple.dst_port == 443 || 
                                     f.initial_tuple.dst_port == 8080 || f.initial_tuple.dst_port == 8443);

            if (fwd_bytes >= config.outbound_bytes_threshold * 5 && !is_standard_port) {
                ev.severity = DetectionSeverity::HIGH;
            } else if (exceeds_volume) {
                ev.severity = DetectionSeverity::MEDIUM;
            } else {
                ev.severity = DetectionSeverity::LOW;
            }

            ev.evidence["forward_bytes"] = std::to_string(fwd_bytes);
            ev.evidence["reverse_bytes"] = std::to_string(rev_bytes);
            ev.evidence["asymmetry_ratio"] = std::to_string(asymmetry);
            ev.evidence["destination_port"] = std::to_string(f.initial_tuple.dst_port);
            ev.evidence["threshold_bytes"] = std::to_string(config.outbound_bytes_threshold);
            ev.evidence["observed_metric"] = std::to_string(fwd_bytes) + " bytes forwarded (ratio: " + 
                                             std::to_string(asymmetry) + ")";

            ev.explanation = "Flow transferred " + std::to_string(fwd_bytes) + " bytes outbound with an asymmetry ratio of " +
                             std::to_string(asymmetry) + " to " + ev.destination_ip_str + ":" + 
                             std::to_string(f.initial_tuple.dst_port) + ".";
            ev.limitations = {
                "Traffic direction is relative to the first observed packet; server-initiated downloads may appear as forward transfers.",
                "Authorized cloud backups, video uploads, and file transfers regularly produce high outbound asymmetry."
            };
            ev.recommended_actions = {
                "Confirm if the outbound transfer was authorized by data governance policies.",
                "Verify whether the external destination IP belongs to a reputable cloud service provider."
            };

            events.push_back(std::move(ev));
        }
    }

    return events;
}

// ============================================================================
// F. BeaconDetector Implementation
// ============================================================================
std::vector<DetectionEvent> BeaconDetector::detect(
    const std::vector<FlowRecord>& flows,
    const DetectionConfig& config) {

    std::vector<DetectionEvent> events;
    if (!config.enable_beaconing || flows.empty()) return events;

    // Group flows by (src_ip, dst_ip, dst_port)
    struct EndpointKey {
        uint32_t src;
        uint32_t dst;
        uint16_t port;
        bool operator<(const EndpointKey& o) const {
            if (src != o.src) return src < o.src;
            if (dst != o.dst) return dst < o.dst;
            return port < o.port;
        }
    };

    std::map<EndpointKey, std::vector<const FlowRecord*>> endpoint_map;
    for (const auto& f : flows) {
        EndpointKey k{f.initial_tuple.src_ip, f.initial_tuple.dst_ip, f.initial_tuple.dst_port};
        endpoint_map[k].push_back(&f);
    }

    size_t event_counter = 0;

    for (const auto& pair : endpoint_map) {
        const auto& key = pair.first;
        const auto& ep_flows = pair.second;

        if (ep_flows.size() < config.beacon_min_connections) continue;

        // Sort flows chronologically
        std::vector<const FlowRecord*> sorted_flows = ep_flows;
        std::sort(sorted_flows.begin(), sorted_flows.end(), [](const FlowRecord* a, const FlowRecord* b) {
            return a->start_time_us < b->start_time_us;
        });

        // Compute inter-connection intervals (seconds)
        std::vector<double> intervals;
        std::vector<uint64_t> flow_ids;
        flow_ids.push_back(sorted_flows[0]->flow_id);

        for (size_t i = 1; i < sorted_flows.size(); ++i) {
            flow_ids.push_back(sorted_flows[i]->flow_id);
            if (sorted_flows[i]->start_time_us > sorted_flows[i - 1]->start_time_us) {
                double dt = (sorted_flows[i]->start_time_us - sorted_flows[i - 1]->start_time_us) / 1000000.0;
                intervals.push_back(dt);
            }
        }

        if (intervals.size() < config.beacon_min_connections - 1) continue;

        // Compute mean and standard deviation of intervals
        double sum = 0.0;
        for (double dt : intervals) sum += dt;
        double mean_dt = sum / intervals.size();

        if (mean_dt < config.beacon_min_interval_seconds) {
            continue; // Sub-second bursts are handled by connection burst detector
        }

        double sum_sq_diff = 0.0;
        for (double dt : intervals) {
            double diff = dt - mean_dt;
            sum_sq_diff += diff * diff;
        }
        double variance_dt = (intervals.size() > 1) ? (sum_sq_diff / (intervals.size() - 1)) : 0.0;
        double stddev_dt = std::sqrt(variance_dt);

        // Coefficient of Variation: CV = stddev / mean (dimensionless jitter metric)
        double cv = (mean_dt > 0.0) ? (stddev_dt / mean_dt) : 1.0;

        if (cv <= config.beacon_max_jitter_cv) {
            DetectionEvent ev;
            ev.detection_id = generateEventId("DET-BEACON", key.src, sorted_flows[0]->start_time_us, ++event_counter);
            ev.detector_name = getName();
            ev.category = getCategory();
            ev.timestamp_us = sorted_flows[0]->start_time_us;
            ev.timestamp_iso = formatIsoTimestamp(sorted_flows[0]->start_time_us);
            ev.source_ip = key.src;
            ev.destination_ip = key.dst;
            ev.source_ip_str = RuleManager::ipToString(key.src);
            ev.destination_ip_str = RuleManager::ipToString(key.dst);
            ev.protocol = sorted_flows[0]->initial_tuple.protocol;
            ev.relevant_ports.push_back(key.port);
            ev.related_flow_ids = flow_ids;

            // Highly strict low-jitter (<10%) over many connections escalates severity
            if (cv <= 0.08 && intervals.size() >= 8) {
                ev.severity = DetectionSeverity::HIGH;
            } else {
                ev.severity = DetectionSeverity::MEDIUM;
            }

            ev.evidence["connection_count"] = std::to_string(sorted_flows.size());
            ev.evidence["mean_interval_seconds"] = std::to_string(mean_dt);
            ev.evidence["stddev_seconds"] = std::to_string(stddev_dt);
            ev.evidence["coefficient_of_variation"] = std::to_string(cv);
            ev.evidence["threshold_max_cv"] = std::to_string(config.beacon_max_jitter_cv);
            ev.evidence["observed_metric"] = "Period: " + std::to_string(mean_dt) + "s (CV: " + 
                                             std::to_string(cv) + ")";

            ev.explanation = "Source host maintained " + std::to_string(sorted_flows.size()) +
                             " periodic connections to " + ev.destination_ip_str + ":" + 
                             std::to_string(key.port) + " with low interval jitter (mean: " + 
                             std::to_string(mean_dt) + "s, CV: " + std::to_string(cv) + ").";
            ev.limitations = {
                "Legitimate background telemetry, NTP sync, email polling, and keepalive heartbeats regularly produce periodic intervals.",
                "Low jitter does not conclusively establish malicious command-and-control communication."
            };
            ev.recommended_actions = {
                "Determine if the target endpoint represents a known infrastructure management service or public NTP/DNS server.",
                "Inspect client endpoint task scheduler and service configuration."
            };

            events.push_back(std::move(ev));
        }
    }

    return events;
}

// ============================================================================
// G. TCPAnomalyDetector Implementation
// ============================================================================
std::vector<DetectionEvent> TCPAnomalyDetector::detect(
    const std::vector<FlowRecord>& flows,
    const DetectionConfig& config) {

    std::vector<DetectionEvent> events;
    if (!config.enable_tcp_anomaly || flows.empty()) return events;

    std::map<uint32_t, std::vector<const FlowRecord*>> src_tcp_map;
    for (const auto& f : flows) {
        if (f.initial_tuple.protocol == 6) { // TCP
            src_tcp_map[f.initial_tuple.src_ip].push_back(&f);
        }
    }

    size_t event_counter = 0;

    for (const auto& pair : src_tcp_map) {
        uint32_t src_ip = pair.first;
        const auto& tcp_flows = pair.second;

        // 1. SYN-Heavy Pattern Detection
        if (tcp_flows.size() >= config.tcp_min_syn_flows) {
            size_t syn_heavy_count = 0;
            std::vector<uint64_t> flow_ids;

            for (const auto* f : tcp_flows) {
                // Flow has SYN but 0 ACKs or 0 reverse reply packets
                if (f->fwd.syn_count > 0 && f->fwd.ack_count == 0 && f->rev.packet_count == 0) {
                    syn_heavy_count++;
                    flow_ids.push_back(f->flow_id);
                }
            }

            double syn_ratio = static_cast<double>(syn_heavy_count) / tcp_flows.size();

            if (syn_ratio >= config.tcp_syn_heavy_ratio) {
                DetectionEvent ev;
                ev.detection_id = generateEventId("DET-TCP-SYN", src_ip, tcp_flows[0]->start_time_us, ++event_counter);
                ev.detector_name = getName();
                ev.category = getCategory();
                ev.timestamp_us = tcp_flows[0]->start_time_us;
                ev.timestamp_iso = formatIsoTimestamp(tcp_flows[0]->start_time_us);
                ev.source_ip = src_ip;
                ev.destination_ip = 0;
                ev.source_ip_str = RuleManager::ipToString(src_ip);
                ev.destination_ip_str = "MULTIPLE";
                ev.protocol = 6;
                ev.related_flow_ids = flow_ids;
                ev.severity = (syn_heavy_count >= 20) ? DetectionSeverity::HIGH : DetectionSeverity::MEDIUM;

                ev.evidence["total_tcp_flows"] = std::to_string(tcp_flows.size());
                ev.evidence["syn_heavy_flows"] = std::to_string(syn_heavy_count);
                ev.evidence["syn_ratio"] = std::to_string(syn_ratio);
                ev.evidence["threshold_ratio"] = std::to_string(config.tcp_syn_heavy_ratio);
                ev.evidence["observed_metric"] = std::to_string(syn_heavy_count) + "/" + 
                                                 std::to_string(tcp_flows.size()) + " SYN-heavy flows (" + 
                                                 std::to_string(static_cast<int>(syn_ratio * 100)) + "%)";

                ev.explanation = "Source host exhibited a SYN-heavy communication pattern where " + 
                                 std::to_string(syn_heavy_count) + " out of " + std::to_string(tcp_flows.size()) + 
                                 " TCP flows initiated connections without receiving or completing handshakes.";
                ev.limitations = {
                    "Asymmetric network capture taps where reply traffic travels over a different route can cause false SYN-heavy classifications.",
                    "Active firewall drops on network boundaries can result in unacknowledged SYNs."
                };
                ev.recommended_actions = {
                    "Verify TAP/SPAN port mirroring coverage to ensure bidirectional packet capture.",
                    "Examine source host for potential SYN flood or port scanning activity."
                };

                events.push_back(std::move(ev));
            }
        }

        // 2. High RST Abort Pattern Detection
        if (tcp_flows.size() >= config.tcp_min_rst_flows) {
            size_t rst_count = 0;
            std::vector<uint64_t> flow_ids;

            for (const auto* f : tcp_flows) {
                if (f->fwd.rst_count > 0 || f->rev.rst_count > 0 || 
                    f->termination_reason == FlowTerminationReason::NATURAL_FIN_RST) {
                    rst_count++;
                    flow_ids.push_back(f->flow_id);
                }
            }

            double rst_ratio = static_cast<double>(rst_count) / tcp_flows.size();

            if (rst_ratio >= config.tcp_rst_ratio_threshold) {
                DetectionEvent ev;
                ev.detection_id = generateEventId("DET-TCP-RST", src_ip, tcp_flows[0]->start_time_us, ++event_counter);
                ev.detector_name = getName();
                ev.category = getCategory();
                ev.timestamp_us = tcp_flows[0]->start_time_us;
                ev.timestamp_iso = formatIsoTimestamp(tcp_flows[0]->start_time_us);
                ev.source_ip = src_ip;
                ev.destination_ip = 0;
                ev.source_ip_str = RuleManager::ipToString(src_ip);
                ev.destination_ip_str = "MULTIPLE";
                ev.protocol = 6;
                ev.related_flow_ids = flow_ids;
                ev.severity = DetectionSeverity::LOW;

                ev.evidence["total_tcp_flows"] = std::to_string(tcp_flows.size());
                ev.evidence["rst_flow_count"] = std::to_string(rst_count);
                ev.evidence["rst_ratio"] = std::to_string(rst_ratio);
                ev.evidence["threshold_ratio"] = std::to_string(config.tcp_rst_ratio_threshold);
                ev.evidence["observed_metric"] = std::to_string(rst_count) + " flows with RST (" + 
                                                 std::to_string(static_cast<int>(rst_ratio * 100)) + "%)";

                ev.explanation = "Source host engaged in TCP sessions with an unusually high proportion of reset (RST) terminations (" +
                                 std::to_string(static_cast<int>(rst_ratio * 100)) + "%).";
                ev.limitations = {
                    "Client socket timeouts, closed destination ports, and middlebox connection terminates commonly generate RST packets."
                };
                ev.recommended_actions = {
                    "Inspect destination services to verify whether ports were intentionally refusing connections."
                };

                events.push_back(std::move(ev));
            }
        }
    }

    return events;
}

} // namespace DPI
