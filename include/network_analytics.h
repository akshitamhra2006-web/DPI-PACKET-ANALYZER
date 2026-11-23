#ifndef DPI_NETWORK_ANALYTICS_H
#define DPI_NETWORK_ANALYTICS_H

#include "flow_record.h"
#include "risk_profiler.h"
#include "detection_types.h"
#include "incident_types.h"
#include "signature_types.h"
#include "threat_intel_types.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <cstdint>

namespace DPI {

// ============================================================================
// TEMPORAL ANALYTICS
// ============================================================================
struct TimeBucket {
    uint64_t timestamp_us = 0;
    uint32_t packet_count = 0;
    uint64_t byte_count = 0;
    uint32_t flow_count = 0;
    uint32_t alert_count = 0;
    uint32_t incident_count = 0;
    uint32_t threat_match_count = 0;

    std::string toJson() const;
};

struct TemporalAnalytics {
    uint64_t start_time_us = 0;
    uint64_t end_time_us = 0;
    uint64_t bucket_interval_us = 1000000; // 1 second default
    std::vector<TimeBucket> buckets;

    uint32_t peak_pps = 0;
    uint64_t peak_bps = 0;

    void buildBuckets(const std::vector<FlowRecord>& flows,
                      const std::vector<DetectionEvent>& detections,
                      const std::vector<SecurityIncident>& incidents,
                      const std::vector<ThreatMatchEvent>& threat_matches,
                      uint64_t interval_us = 1000000);

    std::string toJson() const;
};

// ============================================================================
// NETWORK BEHAVIORAL STATISTICS
// ============================================================================
struct ProtocolStats {
    uint32_t flows = 0;
    uint64_t packets = 0;
    uint64_t bytes = 0;

    std::string toJson() const;
};

struct EndpointRank {
    std::string ip;
    uint64_t bytes = 0;
    uint64_t packets = 0;
    uint32_t flows = 0;
    double risk_score = 0.0;
    std::string risk_level;

    std::string toJson() const;
};

struct PortRank {
    uint16_t port = 0;
    std::string service_name;
    uint32_t flow_count = 0;
    uint64_t byte_count = 0;

    std::string toJson() const;
};

struct NetworkBehavioralStats {
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    uint32_t total_flows = 0;
    uint32_t unique_sources = 0;
    uint32_t unique_destinations = 0;
    uint32_t unique_destination_ports = 0;

    std::map<std::string, ProtocolStats> protocol_breakdown;
    std::vector<EndpointRank> top_talkers_bytes;
    std::vector<EndpointRank> top_talkers_flows;
    std::vector<PortRank> top_ports;

    // Distribution percentiles (in microseconds for duration, bytes for size)
    double duration_min_ms = 0.0;
    double duration_p25_ms = 0.0;
    double duration_median_ms = 0.0;
    double duration_p75_ms = 0.0;
    double duration_p95_ms = 0.0;
    double duration_max_ms = 0.0;

    uint32_t packet_size_min = 0;
    uint32_t packet_size_median = 0;
    uint32_t packet_size_p95 = 0;
    uint32_t packet_size_max = 0;
    double packet_size_avg = 0.0;

    // TCP Flag Counts
    uint64_t tcp_syn_count = 0;
    uint64_t tcp_ack_count = 0;
    uint64_t tcp_fin_count = 0;
    uint64_t tcp_rst_count = 0;
    uint64_t tcp_psh_count = 0;

    // Protocol specifics
    uint32_t dns_total_queries = 0;
    uint32_t dns_total_answers = 0;
    uint32_t dns_nxdomain_count = 0;
    uint32_t tls_unique_sni_count = 0;
    uint32_t http_unique_hosts_count = 0;

    // Security metrics
    std::map<std::string, uint32_t> detections_by_category;
    std::map<std::string, uint32_t> incidents_by_severity;
    std::map<std::string, uint32_t> threats_by_category;

    void compute(const std::vector<FlowRecord>& flows,
                 const std::unordered_map<std::string, EndpointRiskProfile>& endpoint_profiles,
                 const std::vector<DetectionEvent>& detections,
                 const std::vector<SecurityIncident>& incidents,
                 const std::vector<ThreatMatchEvent>& threat_matches);

    std::string toJson() const;
};

// ============================================================================
// NETWORK RELATIONSHIP GRAPH MODEL
// ============================================================================
struct GraphNode {
    std::string id;
    std::string label;
    std::string category; // ENDPOINT, DOMAIN, INCIDENT, THREAT_IOC
    double risk_score = 0.0;
    std::string risk_level = "CLEAN";
    std::string role; // CLIENT, SERVER, EXTERNAL
    uint64_t bytes = 0;
    uint32_t flows = 0;

    std::string toJson() const;
};

struct GraphEdge {
    std::string id;
    std::string source;
    std::string target;
    std::string category; // FLOW, DNS_RESOLUTION, TLS_SNI, INCIDENT_LINK, THREAT_MATCH
    std::string protocol;
    uint64_t bytes = 0;
    uint32_t packets = 0;
    double weight = 1.0;

    std::string toJson() const;
};

struct NetworkGraph {
    std::vector<GraphNode> nodes;
    std::vector<GraphEdge> edges;

    // Maximum limits to ensure browser rendering safety
    size_t max_nodes = 250;
    size_t max_edges = 500;

    void build(const std::vector<FlowRecord>& flows,
               const std::unordered_map<std::string, EndpointRiskProfile>& endpoint_profiles,
               const std::vector<SecurityIncident>& incidents,
               const std::vector<ThreatMatchEvent>& threat_matches);

    std::string toJson() const;
};

// ============================================================================
// NETWORK ANALYTICS ENGINE
// ============================================================================
class NetworkAnalyticsEngine {
public:
    NetworkAnalyticsEngine() = default;

    void runAnalytics(const std::vector<FlowRecord>& flows,
                      const std::unordered_map<std::string, EndpointRiskProfile>& endpoint_profiles,
                      const std::vector<DetectionEvent>& detections,
                      const std::vector<SecurityIncident>& incidents,
                      const std::vector<ThreatMatchEvent>& threat_matches);

    const NetworkBehavioralStats& getStats() const { return stats_; }
    const TemporalAnalytics& getTemporal() const { return temporal_; }
    const NetworkGraph& getGraph() const { return graph_; }

    std::string generateAnalyticsReport() const;
    std::string toJson() const;

private:
    NetworkBehavioralStats stats_;
    TemporalAnalytics temporal_;
    NetworkGraph graph_;
};

} // namespace DPI

#endif // DPI_NETWORK_ANALYTICS_H
