#include "network_analytics.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <set>
#include <unordered_set>
#include <cmath>

namespace DPI {

static inline std::string formatIP(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

static inline std::string portToServiceName(uint16_t port) {
    switch (port) {
        case 20: return "FTP-Data";
        case 21: return "FTP-Control";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 67: case 68: return "DHCP";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 123: return "NTP";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 445: return "SMB";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        case 1433: return "MSSQL";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 6379: return "Redis";
        case 8080: return "HTTP-Proxy";
        case 8443: return "HTTPS-Alt";
        default: return "Custom/" + std::to_string(port);
    }
}

// ============================================================================
// TEMPORAL ANALYTICS IMPLEMENTATION
// ============================================================================

std::string TimeBucket::toJson() const {
    std::ostringstream ss;
    ss << "{"
       << "\"timestamp_us\":" << timestamp_us << ","
       << "\"packet_count\":" << packet_count << ","
       << "\"byte_count\":" << byte_count << ","
       << "\"flow_count\":" << flow_count << ","
       << "\"alert_count\":" << alert_count << ","
       << "\"incident_count\":" << incident_count << ","
       << "\"threat_match_count\":" << threat_match_count
       << "}";
    return ss.str();
}

void TemporalAnalytics::buildBuckets(const std::vector<FlowRecord>& flows,
                                    const std::vector<DetectionEvent>& detections,
                                    const std::vector<SecurityIncident>& incidents,
                                    const std::vector<ThreatMatchEvent>& threat_matches,
                                    uint64_t interval_us) {
    buckets.clear();
    peak_pps = 0;
    peak_bps = 0;

    if (flows.empty()) return;

    // Find min and max timestamp
    uint64_t min_t = flows[0].start_time_us;
    uint64_t max_t = flows[0].last_time_us;
    for (const auto& f : flows) {
        if (f.start_time_us < min_t && f.start_time_us > 0) min_t = f.start_time_us;
        if (f.last_time_us > max_t) max_t = f.last_time_us;
    }

    start_time_us = min_t;
    end_time_us = max_t;

    // Dynamically adjust interval if span is wide or narrow
    uint64_t duration = (max_t > min_t) ? (max_t - min_t) : 1000000;
    if (duration > 3600ULL * 1000000ULL) {
        bucket_interval_us = 60ULL * 1000000ULL; // 1-minute buckets
    } else if (duration > 300ULL * 1000000ULL) {
        bucket_interval_us = 5ULL * 1000000ULL;  // 5-second buckets
    } else {
        bucket_interval_us = interval_us;        // 1-second default
    }
    if (bucket_interval_us == 0) bucket_interval_us = 1000000;

    size_t num_buckets = (duration / bucket_interval_us) + 1;
    if (num_buckets > 500) num_buckets = 500; // Cap to 500 points for frontend rendering performance
    buckets.resize(num_buckets);

    for (size_t i = 0; i < num_buckets; i++) {
        buckets[i].timestamp_us = min_t + i * bucket_interval_us;
    }

    // Populate flow metrics
    for (const auto& f : flows) {
        if (f.start_time_us < min_t) continue;
        size_t b_idx = (f.start_time_us - min_t) / bucket_interval_us;
        if (b_idx < num_buckets) {
            buckets[b_idx].flow_count++;
            buckets[b_idx].packet_count += (f.fwd.packet_count + f.rev.packet_count);
            buckets[b_idx].byte_count += (f.fwd.byte_count + f.rev.byte_count);
        }
    }

    // Populate detections
    for (const auto& d : detections) {
        if (d.timestamp_us < min_t) continue;
        size_t b_idx = (d.timestamp_us - min_t) / bucket_interval_us;
        if (b_idx < num_buckets) {
            buckets[b_idx].alert_count++;
        }
    }

    // Populate incidents
    for (const auto& inc : incidents) {
        if (inc.first_seen_us < min_t) continue;
        size_t b_idx = (inc.first_seen_us - min_t) / bucket_interval_us;
        if (b_idx < num_buckets) {
            buckets[b_idx].incident_count++;
        }
    }

    // Populate threat matches
    for (const auto& tm : threat_matches) {
        if (tm.match_timestamp_us < min_t) continue;
        size_t b_idx = (tm.match_timestamp_us - min_t) / bucket_interval_us;
        if (b_idx < num_buckets) {
            buckets[b_idx].threat_match_count++;
        }
    }

    // Compute peaks
    double interval_sec = static_cast<double>(bucket_interval_us) / 1000000.0;
    if (interval_sec <= 0.0) interval_sec = 1.0;
    for (const auto& b : buckets) {
        uint32_t pps = static_cast<uint32_t>(b.packet_count / interval_sec);
        uint64_t bps = static_cast<uint64_t>((b.byte_count * 8) / interval_sec);
        if (pps > peak_pps) peak_pps = pps;
        if (bps > peak_bps) peak_bps = bps;
    }
}

std::string TemporalAnalytics::toJson() const {
    std::ostringstream ss;
    ss << "{\n"
       << "  \"start_time_us\": " << start_time_us << ",\n"
       << "  \"end_time_us\": " << end_time_us << ",\n"
       << "  \"bucket_interval_us\": " << bucket_interval_us << ",\n"
       << "  \"peak_pps\": " << peak_pps << ",\n"
       << "  \"peak_bps\": " << peak_bps << ",\n"
       << "  \"buckets\": [\n";
    bool first = true;
    for (const auto& b : buckets) {
        if (!first) ss << ",\n";
        ss << "    " << b.toJson();
        first = false;
    }
    ss << "\n  ]\n}";
    return ss.str();
}

// ============================================================================
// BEHAVIORAL STATS IMPLEMENTATION
// ============================================================================

std::string ProtocolStats::toJson() const {
    std::ostringstream ss;
    ss << "{\"flows\":" << flows << ",\"packets\":" << packets << ",\"bytes\":" << bytes << "}";
    return ss.str();
}

std::string EndpointRank::toJson() const {
    std::ostringstream ss;
    ss << "{"
       << "\"ip\":\"" << ip << "\","
       << "\"bytes\":" << bytes << ","
       << "\"packets\":" << packets << ","
       << "\"flows\":" << flows << ","
       << "\"risk_score\":" << std::fixed << std::setprecision(1) << risk_score << ","
       << "\"risk_level\":\"" << risk_level << "\""
       << "}";
    return ss.str();
}

std::string PortRank::toJson() const {
    std::ostringstream ss;
    ss << "{"
       << "\"port\":" << port << ","
       << "\"service\":\"" << service_name << "\","
       << "\"flow_count\":" << flow_count << ","
       << "\"byte_count\":" << byte_count
       << "}";
    return ss.str();
}

void NetworkBehavioralStats::compute(const std::vector<FlowRecord>& flows,
                                    const std::unordered_map<std::string, EndpointRiskProfile>& endpoint_profiles,
                                    const std::vector<DetectionEvent>& detections,
                                    const std::vector<SecurityIncident>& incidents,
                                    const std::vector<ThreatMatchEvent>& threat_matches) {
    total_packets = 0;
    total_bytes = 0;
    total_flows = flows.size();

    std::set<std::string> unique_src_set;
    std::set<std::string> unique_dst_set;
    std::set<uint16_t> unique_dst_ports_set;
    std::map<uint16_t, std::pair<uint32_t, uint64_t>> port_counters;

    std::vector<double> durations_ms;
    std::vector<uint32_t> packet_sizes;
    std::set<std::string> sni_set;
    std::set<std::string> host_set;

    protocol_breakdown.clear();

    for (const auto& f : flows) {
        std::string src_ip = formatIP(f.initial_tuple.src_ip);
        std::string dst_ip = formatIP(f.initial_tuple.dst_ip);
        unique_src_set.insert(src_ip);
        unique_dst_set.insert(dst_ip);
        unique_dst_ports_set.insert(f.initial_tuple.dst_port);

        uint64_t flow_pkts = f.fwd.packet_count + f.rev.packet_count;
        uint64_t flow_b = f.fwd.byte_count + f.rev.byte_count;
        total_packets += flow_pkts;
        total_bytes += flow_b;

        std::string proto = f.detected_app_name.empty() || f.detected_app_name == "Unknown" ?
                            (f.initial_tuple.protocol == 6 ? "TCP" : (f.initial_tuple.protocol == 17 ? "UDP" : "Other")) :
                            f.detected_app_name;
        auto& p_stat = protocol_breakdown[proto];
        p_stat.flows++;
        p_stat.packets += flow_pkts;
        p_stat.bytes += flow_b;

        port_counters[f.initial_tuple.dst_port].first++;
        port_counters[f.initial_tuple.dst_port].second += flow_b;

        durations_ms.push_back(f.duration_microseconds() / 1000.0);

        if (f.fwd.packet_count > 0) packet_sizes.push_back(static_cast<uint32_t>(f.fwd.byte_count / f.fwd.packet_count));
        if (f.rev.packet_count > 0) packet_sizes.push_back(static_cast<uint32_t>(f.rev.byte_count / f.rev.packet_count));

        tcp_syn_count += (f.fwd.syn_count + f.rev.syn_count);
        tcp_ack_count += (f.fwd.ack_count + f.rev.ack_count);
        tcp_fin_count += (f.fwd.fin_count + f.rev.fin_count);
        tcp_rst_count += (f.fwd.rst_count + f.rev.rst_count);
        tcp_psh_count += (f.fwd.psh_count + f.rev.psh_count);

        if (!f.dns_query.empty()) dns_total_queries++;
        if (!f.dns_answers.empty()) dns_total_answers += f.dns_answers.size();
        if (f.dns_rcode == 3) dns_nxdomain_count++;

        if (!f.sni.empty()) sni_set.insert(f.sni);
        if (!f.http_host.empty()) host_set.insert(f.http_host);
    }

    unique_sources = unique_src_set.size();
    unique_destinations = unique_dst_set.size();
    unique_destination_ports = unique_dst_ports_set.size();
    tls_unique_sni_count = sni_set.size();
    http_unique_hosts_count = host_set.size();

    // Duration percentiles
    if (!durations_ms.empty()) {
        std::sort(durations_ms.begin(), durations_ms.end());
        duration_min_ms = durations_ms.front();
        duration_max_ms = durations_ms.back();
        duration_p25_ms = durations_ms[durations_ms.size() * 25 / 100];
        duration_median_ms = durations_ms[durations_ms.size() * 50 / 100];
        duration_p75_ms = durations_ms[durations_ms.size() * 75 / 100];
        duration_p95_ms = durations_ms[durations_ms.size() * 95 / 100];
    }

    // Packet size percentiles
    if (!packet_sizes.empty()) {
        std::sort(packet_sizes.begin(), packet_sizes.end());
        packet_size_min = packet_sizes.front();
        packet_size_max = packet_sizes.back();
        packet_size_median = packet_sizes[packet_sizes.size() * 50 / 100];
        packet_size_p95 = packet_sizes[packet_sizes.size() * 95 / 100];
        double sum_sz = 0;
        for (auto sz : packet_sizes) sum_sz += sz;
        packet_size_avg = sum_sz / packet_sizes.size();
    }

    // Top talkers
    top_talkers_bytes.clear();
    top_talkers_flows.clear();
    for (const auto& pair : endpoint_profiles) {
        const auto& ep = pair.second;
        EndpointRank r;
        r.ip = ep.ip;
        r.bytes = ep.total_bytes;
        r.packets = ep.total_packets;
        r.flows = ep.total_flows;
        r.risk_score = ep.risk_score;
        r.risk_level = riskLevelToString(ep.risk_level);
        top_talkers_bytes.push_back(r);
        top_talkers_flows.push_back(r);
    }
    std::sort(top_talkers_bytes.begin(), top_talkers_bytes.end(), [](const EndpointRank& a, const EndpointRank& b) {
        return a.bytes > b.bytes;
    });
    if (top_talkers_bytes.size() > 10) top_talkers_bytes.resize(10);

    std::sort(top_talkers_flows.begin(), top_talkers_flows.end(), [](const EndpointRank& a, const EndpointRank& b) {
        return a.flows > b.flows;
    });
    if (top_talkers_flows.size() > 10) top_talkers_flows.resize(10);

    // Top destination ports
    top_ports.clear();
    for (const auto& p : port_counters) {
        PortRank pr;
        pr.port = p.first;
        pr.service_name = portToServiceName(p.first);
        pr.flow_count = p.second.first;
        pr.byte_count = p.second.second;
        top_ports.push_back(pr);
    }
    std::sort(top_ports.begin(), top_ports.end(), [](const PortRank& a, const PortRank& b) {
        return a.flow_count > b.flow_count;
    });
    if (top_ports.size() > 10) top_ports.resize(10);

    // Detections by category
    detections_by_category.clear();
    for (const auto& d : detections) {
        detections_by_category[detectionCategoryToString(d.category)]++;
    }

    // Incidents by severity
    incidents_by_severity.clear();
    for (const auto& inc : incidents) {
        incidents_by_severity[incidentSeverityToString(inc.severity)]++;
    }

    // Threats by category
    threats_by_category.clear();
    for (const auto& tm : threat_matches) {
        threats_by_category[tm.category]++;
    }
}

std::string NetworkBehavioralStats::toJson() const {
    std::ostringstream ss;
    ss << "{\n"
       << "  \"total_packets\": " << total_packets << ",\n"
       << "  \"total_bytes\": " << total_bytes << ",\n"
       << "  \"total_flows\": " << total_flows << ",\n"
       << "  \"unique_sources\": " << unique_sources << ",\n"
       << "  \"unique_destinations\": " << unique_destinations << ",\n"
       << "  \"unique_destination_ports\": " << unique_destination_ports << ",\n"
       << "  \"protocol_breakdown\": {\n";
    bool first = true;
    for (const auto& p : protocol_breakdown) {
        if (!first) ss << ",\n";
        ss << "    \"" << p.first << "\": " << p.second.toJson();
        first = false;
    }
    ss << "\n  },\n  \"top_talkers_bytes\": [\n";
    first = true;
    for (const auto& r : top_talkers_bytes) {
        if (!first) ss << ",\n";
        ss << "    " << r.toJson();
        first = false;
    }
    ss << "\n  ],\n  \"top_talkers_flows\": [\n";
    first = true;
    for (const auto& r : top_talkers_flows) {
        if (!first) ss << ",\n";
        ss << "    " << r.toJson();
        first = false;
    }
    ss << "\n  ],\n  \"top_ports\": [\n";
    first = true;
    for (const auto& p : top_ports) {
        if (!first) ss << ",\n";
        ss << "    " << p.toJson();
        first = false;
    }
    ss << "\n  ],\n  \"durations_ms\": {\n"
       << "    \"min\": " << std::fixed << std::setprecision(2) << duration_min_ms << ",\n"
       << "    \"p25\": " << duration_p25_ms << ",\n"
       << "    \"median\": " << duration_median_ms << ",\n"
       << "    \"p75\": " << duration_p75_ms << ",\n"
       << "    \"p95\": " << duration_p95_ms << ",\n"
       << "    \"max\": " << duration_max_ms << "\n"
       << "  },\n  \"packet_sizes\": {\n"
       << "    \"min\": " << packet_size_min << ",\n"
       << "    \"median\": " << packet_size_median << ",\n"
       << "    \"p95\": " << packet_size_p95 << ",\n"
       << "    \"max\": " << packet_size_max << ",\n"
       << "    \"avg\": " << packet_size_avg << "\n"
       << "  },\n  \"tcp_flags\": {\n"
       << "    \"syn\": " << tcp_syn_count << ",\n"
       << "    \"ack\": " << tcp_ack_count << ",\n"
       << "    \"fin\": " << tcp_fin_count << ",\n"
       << "    \"rst\": " << tcp_rst_count << ",\n"
       << "    \"psh\": " << tcp_psh_count << "\n"
       << "  },\n  \"dns_queries\": " << dns_total_queries << ",\n"
       << "  \"dns_answers\": " << dns_total_answers << ",\n"
       << "  \"dns_nxdomain\": " << dns_nxdomain_count << ",\n"
       << "  \"tls_unique_sni\": " << tls_unique_sni_count << ",\n"
       << "  \"http_unique_hosts\": " << http_unique_hosts_count << ",\n"
       << "  \"detections_by_category\": {\n";
    first = true;
    for (const auto& c : detections_by_category) {
        if (!first) ss << ",\n";
        ss << "    \"" << c.first << "\": " << c.second;
        first = false;
    }
    ss << "\n  },\n  \"incidents_by_severity\": {\n";
    first = true;
    for (const auto& inc : incidents_by_severity) {
        if (!first) ss << ",\n";
        ss << "    \"" << inc.first << "\": " << inc.second;
        first = false;
    }
    ss << "\n  },\n  \"threats_by_category\": {\n";
    first = true;
    for (const auto& tm : threats_by_category) {
        if (!first) ss << ",\n";
        ss << "    \"" << tm.first << "\": " << tm.second;
        first = false;
    }
    ss << "\n  }\n}";
    return ss.str();
}

// ============================================================================
// NETWORK GRAPH MODEL IMPLEMENTATION
// ============================================================================

std::string GraphNode::toJson() const {
    std::ostringstream ss;
    ss << "{"
       << "\"id\":\"" << id << "\","
       << "\"label\":\"" << label << "\","
       << "\"category\":\"" << category << "\","
       << "\"risk_score\":" << std::fixed << std::setprecision(1) << risk_score << ","
       << "\"risk_level\":\"" << risk_level << "\","
       << "\"role\":\"" << role << "\","
       << "\"bytes\":" << bytes << ","
       << "\"flows\":" << flows
       << "}";
    return ss.str();
}

std::string GraphEdge::toJson() const {
    std::ostringstream ss;
    ss << "{"
       << "\"id\":\"" << id << "\","
       << "\"source\":\"" << source << "\","
       << "\"target\":\"" << target << "\","
       << "\"category\":\"" << category << "\","
       << "\"protocol\":\"" << protocol << "\","
       << "\"bytes\":" << bytes << ","
       << "\"packets\":" << packets << ","
       << "\"weight\":" << std::fixed << std::setprecision(1) << weight
       << "}";
    return ss.str();
}

void NetworkGraph::build(const std::vector<FlowRecord>& flows,
                         const std::unordered_map<std::string, EndpointRiskProfile>& endpoint_profiles,
                         const std::vector<SecurityIncident>& incidents,
                         const std::vector<ThreatMatchEvent>& threat_matches) {
    nodes.clear();
    edges.clear();

    std::unordered_map<std::string, size_t> node_id_map;

    auto addNode = [&](const std::string& id, const std::string& label, const std::string& cat,
                       double score, const std::string& level, const std::string& role,
                       uint64_t bytes, uint32_t fl) {
        if (node_id_map.find(id) != node_id_map.end()) return;
        if (nodes.size() >= max_nodes) return;
        GraphNode n;
        n.id = id;
        n.label = label;
        n.category = cat;
        n.risk_score = score;
        n.risk_level = level;
        n.role = role;
        n.bytes = bytes;
        n.flows = fl;
        node_id_map[id] = nodes.size();
        nodes.push_back(n);
    };

    // 1. Add Incident Nodes (High priority)
    for (const auto& inc : incidents) {
        std::string node_id = "inc:" + inc.incident_id;
        addNode(node_id, inc.incident_id + ": " + inc.title, "INCIDENT",
                inc.correlation_score, incidentSeverityToString(inc.severity), "INCIDENT", 0, 0);
    }

    // 1b. Add Threat IOC Nodes
    for (const auto& tm : threat_matches) {
        if (nodes.size() >= max_nodes) break;
        std::string tm_id = "ioc:" + tm.ioc_id;
        addNode(tm_id, tm.ioc_value + " (" + iocTypeToString(tm.ioc_type) + ")", "IOC",
                85.0, "HIGH", "THREAT_IOC", 0, 0);
    }

    // 2. Add Endpoint Nodes
    for (const auto& pair : endpoint_profiles) {
        const auto& ep = pair.second;
        std::string node_id = "ep:" + ep.ip;
        addNode(node_id, ep.ip, "ENDPOINT", ep.risk_score,
                riskLevelToString(ep.risk_level), ep.role, ep.total_bytes, ep.total_flows);
    }

    // 3. Add Domain Nodes for observed SNI & HTTP hosts
    for (const auto& f : flows) {
        if (!f.sni.empty()) {
            std::string dom_id = "dom:" + f.sni;
            addNode(dom_id, f.sni, "DOMAIN", (f.ioc_match_count > 0 ? 80.0 : 0.0),
                    (f.ioc_match_count > 0 ? "HIGH" : "CLEAN"), "DOMAIN", 0, 0);
        }
        if (!f.http_host.empty() && f.http_host != f.sni) {
            std::string dom_id = "dom:" + f.http_host;
            addNode(dom_id, f.http_host, "DOMAIN", (f.ioc_match_count > 0 ? 80.0 : 0.0),
                    (f.ioc_match_count > 0 ? "HIGH" : "CLEAN"), "DOMAIN", 0, 0);
        }
    }

    // 4. Build Flow Edges (aggregated by pair + protocol)
    std::map<std::tuple<std::string, std::string, std::string>, std::pair<uint64_t, uint32_t>> flow_agg;
    for (const auto& f : flows) {
        std::string src_id = "ep:" + formatIP(f.initial_tuple.src_ip);
        std::string dst_id = "ep:" + formatIP(f.initial_tuple.dst_ip);
        if (node_id_map.find(src_id) == node_id_map.end() || node_id_map.find(dst_id) == node_id_map.end()) {
            continue;
        }
        std::string proto = f.detected_app_name.empty() ? (f.initial_tuple.protocol == 6 ? "TCP" : "UDP") : f.detected_app_name;
        auto key = std::make_tuple(src_id, dst_id, proto);
        flow_agg[key].first += (f.fwd.byte_count + f.rev.byte_count);
        flow_agg[key].second += (f.fwd.packet_count + f.rev.packet_count);
    }

    uint32_t edge_idx = 1;
    for (const auto& p : flow_agg) {
        if (edges.size() >= max_edges) break;
        GraphEdge e;
        e.id = "edge:" + std::to_string(edge_idx++);
        e.source = std::get<0>(p.first);
        e.target = std::get<1>(p.first);
        e.protocol = std::get<2>(p.first);
        e.category = "FLOW";
        e.bytes = p.second.first;
        e.packets = p.second.second;
        e.weight = std::log10(static_cast<double>(e.bytes) + 1.0) * 2.0;
        edges.push_back(e);
    }

    // 5. Connect Domains to Endpoints
    for (const auto& f : flows) {
        if (edges.size() >= max_edges) break;
        std::string src_id = "ep:" + formatIP(f.initial_tuple.src_ip);
        if (node_id_map.find(src_id) == node_id_map.end()) continue;

        if (!f.sni.empty()) {
            std::string dom_id = "dom:" + f.sni;
            if (node_id_map.find(dom_id) != node_id_map.end()) {
                GraphEdge e;
                e.id = "edge:" + std::to_string(edge_idx++);
                e.source = src_id;
                e.target = dom_id;
                e.protocol = "TLS";
                e.category = "TLS_SNI";
                e.weight = 3.0;
                edges.push_back(e);
            }
        }
    }

    // 6. Connect Incidents to Primary Endpoints
    for (const auto& inc : incidents) {
        if (edges.size() >= max_edges) break;
        std::string inc_id = "inc:" + inc.incident_id;
        std::string ep_id = "ep:" + inc.primary_endpoint;
        if (node_id_map.find(inc_id) != node_id_map.end() && node_id_map.find(ep_id) != node_id_map.end()) {
            GraphEdge e;
            e.id = "edge:" + std::to_string(edge_idx++);
            e.source = ep_id;
            e.target = inc_id;
            e.protocol = "CORRELATION";
            e.category = "INCIDENT_LINK";
            e.weight = inc.correlation_score / 10.0;
            edges.push_back(e);
        }
    }

    // 7. Connect Threat IOCs to Observed Endpoints
    for (const auto& tm : threat_matches) {
        if (edges.size() >= max_edges) break;
        std::string tm_id = "ioc:" + tm.ioc_id;
        std::string ep_id = "ep:" + tm.src_ip;
        if (node_id_map.find(tm_id) != node_id_map.end() && node_id_map.find(ep_id) != node_id_map.end()) {
            GraphEdge e;
            e.id = "edge:" + std::to_string(edge_idx++);
            e.source = ep_id;
            e.target = tm_id;
            e.protocol = "IOC_MATCH";
            e.category = "THREAT_INTEL";
            e.weight = 5.0;
            edges.push_back(e);
        }
    }
}

std::string NetworkGraph::toJson() const {
    std::ostringstream ss;
    ss << "{\n"
       << "  \"nodes\": [\n";
    bool first = true;
    for (const auto& n : nodes) {
        if (!first) ss << ",\n";
        ss << "    " << n.toJson();
        first = false;
    }
    ss << "\n  ],\n  \"edges\": [\n";
    first = true;
    for (const auto& e : edges) {
        if (!first) ss << ",\n";
        ss << "    " << e.toJson();
        first = false;
    }
    ss << "\n  ]\n}";
    return ss.str();
}

// ============================================================================
// NETWORK ANALYTICS ENGINE IMPLEMENTATION
// ============================================================================

void NetworkAnalyticsEngine::runAnalytics(const std::vector<FlowRecord>& flows,
                                         const std::unordered_map<std::string, EndpointRiskProfile>& endpoint_profiles,
                                         const std::vector<DetectionEvent>& detections,
                                         const std::vector<SecurityIncident>& incidents,
                                         const std::vector<ThreatMatchEvent>& threat_matches) {
    stats_.compute(flows, endpoint_profiles, detections, incidents, threat_matches);
    temporal_.buildBuckets(flows, detections, incidents, threat_matches);
    graph_.build(flows, endpoint_profiles, incidents, threat_matches);
}

std::string NetworkAnalyticsEngine::toJson() const {
    std::ostringstream ss;
    ss << "{\n"
       << "  \"statistics\": " << stats_.toJson() << ",\n"
       << "  \"temporal\": " << temporal_.toJson() << ",\n"
       << "  \"graph\": " << graph_.toJson() << "\n"
       << "}";
    return ss.str();
}

std::string NetworkAnalyticsEngine::generateAnalyticsReport() const {
    std::ostringstream ss;
    ss << "\n"
       << "╔══════════════════════════════════════════════════════════════╗\n"
       << "║          NETWORK BEHAVIORAL ANALYTICS REPORT                 ║\n"
       << "╠══════════════════════════════════════════════════════════════╣\n"
       << "║ Total Traffic Volume:       " << std::setw(10) << stats_.total_bytes << " bytes ("
       << std::setw(5) << stats_.total_packets << " pkts) ║\n"
       << "║ Total Analyzed Flows:       " << std::setw(10) << stats_.total_flows << " flows            ║\n"
       << "║ Unique Active Endpoints:    " << std::setw(10) << (stats_.unique_sources + stats_.unique_destinations) << " endpoints        ║\n"
       << "║ Destination Ports Probed:   " << std::setw(10) << stats_.unique_destination_ports << " ports            ║\n"
       << "║ Peak Throughput:            " << std::setw(10) << stats_.packet_size_avg << " bytes/pkt       ║\n"
       << "╠══════════════════════════════════════════════════════════════╣\n"
       << "║                     PROTOCOL DISTRIBUTION                    ║\n"
       << "╠══════════════════════════════════════════════════════════════╣\n";

    for (const auto& p : stats_.protocol_breakdown) {
        double pct = stats_.total_bytes > 0 ? (p.second.bytes * 100.0 / stats_.total_bytes) : 0.0;
        ss << "║ " << std::left << std::setw(12) << p.first
           << " Flows: " << std::right << std::setw(5) << p.second.flows
           << " Bytes: " << std::setw(8) << p.second.bytes
           << " (" << std::fixed << std::setprecision(1) << std::setw(4) << pct << "%) ║\n";
    }

    ss << "╠══════════════════════════════════════════════════════════════╣\n"
       << "║                     TOP TALKERS BY VOLUME                    ║\n"
       << "╠══════════════════════════════════════════════════════════════╣\n";

    for (const auto& t : stats_.top_talkers_bytes) {
        ss << "║ " << std::left << std::setw(18) << t.ip
           << " Bytes: " << std::right << std::setw(8) << t.bytes
           << " Pkts: " << std::setw(5) << t.packets
           << " [" << std::setw(8) << t.risk_level << "] ║\n";
    }

    ss << "╠══════════════════════════════════════════════════════════════╣\n"
       << "║                  TOP TARGET DESTINATION PORTS                ║\n"
       << "╠══════════════════════════════════════════════════════════════╣\n";

    for (const auto& pr : stats_.top_ports) {
        ss << "║ Port " << std::left << std::setw(6) << pr.port
           << std::setw(14) << ("(" + pr.service_name + ")")
           << " Flows: " << std::right << std::setw(5) << pr.flow_count
           << " Bytes: " << std::setw(8) << pr.byte_count << " ║\n";
    }

    ss << "╠══════════════════════════════════════════════════════════════╣\n"
       << "║                 RELATIONSHIP GRAPH TOPOLOGY                  ║\n"
       << "╠══════════════════════════════════════════════════════════════╣\n"
       << "║ Graph Nodes:                " << std::setw(10) << graph_.nodes.size() << " nodes            ║\n"
       << "║ Graph Edges:                " << std::setw(10) << graph_.edges.size() << " edges            ║\n"
       << "║ Temporal Data Points:       " << std::setw(10) << temporal_.buckets.size() << " buckets          ║\n"
       << "╚══════════════════════════════════════════════════════════════╝\n";
    return ss.str();
}

} // namespace DPI
