#ifndef DPI_ENGINE_H
#define DPI_ENGINE_H

#include "types.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "load_balancer.h"
#include "fast_path.h"
#include "rule_manager.h"
#include "connection_tracker.h"
#include "detection_engine.h"
#include "incident_types.h"
#include "incident_config.h"
#include "incident_correlator.h"
#include "signature_types.h"
#include "signature_engine.h"
#include "threat_intel_types.h"
#include "threat_intel_engine.h"
#include "risk_profiler.h"
#include "network_analytics.h"
#include "investigation_types.h"
#include "investigation_manager.h"
#include "report_generator.h"
#include <memory>
#include <thread>
#include <atomic>
#include <fstream>
#include <mutex>
#include <condition_variable>
#include <unordered_map>

namespace DPI {

// ============================================================================
// DPI Engine - Main orchestrator
// ============================================================================
//
// Architecture Overview:
//
//   +------------------+
//   |   PCAP Reader    |  (Reads packets from input file)
//   +--------+---------+
//            |
//            v (hash to select LB)
//   +--------+----------+
//   |   Load Balancers  |  (2 LB threads)
//   |   LB0      LB1    |
//   +----+--------+-----+
//        |        |
//        v        v (hash to select FP within LB's pool)
//   +----+--------+-----+
//   |  Fast Path Procs  |  (4 FP threads, 2 per LB)
//   |  FP0 FP1  FP2 FP3 |
//   +----+--------+-----+
//        |        |
//        v        v
//   +----+--------+-----+
//   |   Output Queue    |  (Packets to forward)
//   +----+--------+-----+
//        |
//        v
//   +----+--------+-----+
//   |   Output Writer   |  (Writes to output PCAP)
//   +-------------------+
//
// ============================================================================

class DPIEngine {
public:
    // Configuration
    struct Config {
        int num_load_balancers = 2;
        int fps_per_lb = 2;
        size_t queue_size = 10000;
        std::string rules_file;
        bool verbose = false;
        std::string export_flows_json;
        std::string export_flows_csv;
        bool show_flow_stats = false;
        
        // Behavioral Network Detection (Phase 3.1)
        bool enable_detection = false;
        std::string export_detections_json;
        std::string export_detections_csv;
        bool show_detection_stats = false;
        DetectionConfig detection_config;

        // Phase 3.2 TCP Stream Reassembly & Protocol Intelligence
        bool enable_stream_reassembly = true;
        StreamReassemblyConfig reassembly_config;
        std::string export_streams_json;
        std::string export_streams_csv;
        bool show_stream_stats = false;

        // Security Incident Intelligence & Threat Correlation (Phase 3.3)
        bool enable_incidents = false;
        std::string export_incidents_json;
        std::string export_incidents_csv;
        bool show_incident_stats = false;
        IncidentConfig incident_config;

        // Signature Engine & Threat Pattern Matching (Phase 3.4)
        bool enable_signatures = false;
        std::string signature_rules_file;
        std::string signature_rules_dir;
        bool show_signature_stats = false;
        std::string export_signatures_json;
        std::string export_signatures_csv;
        uint32_t signature_max_matches = 10000;
        SignatureEngineConfig signature_config;

        // Threat Intelligence Enrichment (Phase 3.5)
        bool enable_threat_intel = false;
        std::string threat_intel_file;
        std::string threat_intel_dir;
        bool show_threat_intel_stats = false;
        std::string export_threat_matches_json;
        std::string export_threat_matches_csv;
        uint32_t threat_match_limit = 10000;
        ThreatIntelConfig threat_intel_config;

        // Advanced Network Analytics & Risk Profiling (Phase 3.6)
        bool enable_risk_profiling = false;
        bool show_risk_stats = false;
        std::string export_endpoints_json;
        std::string export_risk_json;
        RiskProfilerConfig risk_config;

        bool enable_analytics = false;
        bool show_analytics_stats = false;
        std::string export_analytics_json;
        std::string export_graph_json;
        std::string export_temporal_json;

        // Comprehensive Analytical Reporting (Phase 3.8)
        std::string report_executive_json;
        std::string report_technical_json;
        std::string report_security_json;
        std::string report_incident_json;
        std::string report_threat_intel_json;
        std::string report_html_file;
        std::string analyze_all_dir;
    };
    
    DPIEngine(const Config& config);
    ~DPIEngine();
    
    // Initialize the engine (create threads, queues)
    bool initialize();
    
    // Process a PCAP file
    // input_file: Path to input PCAP (user traffic)
    // output_file: Path to output PCAP (forwarded traffic)
    bool processFile(const std::string& input_file, 
                     const std::string& output_file);
    
    // Start the engine (starts all threads)
    void start();
    
    // Stop the engine (stops all threads)
    void stop();
    
    // Wait for processing to complete
    void waitForCompletion();
    
    // ========== Rule Management ==========
    
    // Block an IP address
    void blockIP(const std::string& ip);
    
    // Unblock an IP address
    void unblockIP(const std::string& ip);
    
    // Block an application
    void blockApp(AppType app);
    void blockApp(const std::string& app_name);
    
    // Unblock an application
    void unblockApp(AppType app);
    void unblockApp(const std::string& app_name);
    
    // Block a domain
    void blockDomain(const std::string& domain);
    
    // Unblock a domain
    void unblockDomain(const std::string& domain);
    
    // Block a port
    void blockPort(uint16_t port);
    
    // Unblock a port
    void unblockPort(uint16_t port);
    
    // Load rules from file
    bool loadRules(const std::string& filename);
    
    // Save rules to file
    bool saveRules(const std::string& filename);
    
    // ========== Reporting ==========
    
    // Generate full statistics report
    std::string generateReport() const;
    
    // Generate classification report (app distribution)
    std::string generateClassificationReport() const;
    
    // Generate flow intelligence report (Phase 3.0)
    std::string generateFlowIntelligenceReport() const;
    
    // Export flow records to JSON / CSV files (Phase 3.0)
    void exportFlowsJson(const std::string& filepath) const;
    void exportFlowsCsv(const std::string& filepath) const;
    
    // Generate behavioral detection report (Phase 3.1)
    std::string generateDetectionReport() const;
    
    // Export behavioral detections to JSON / CSV files (Phase 3.1)
    void exportDetectionsJson(const std::string& filepath) const;
    void exportDetectionsCsv(const std::string& filepath) const;

    // Generate stream reassembly report (Phase 3.2)
    std::string generateStreamReport() const;
    void exportStreamsJson(const std::string& filepath) const;
    void exportStreamsCsv(const std::string& filepath) const;

    // Generate security incident intelligence report (Phase 3.3)
    std::string generateIncidentReport() const;
    void exportIncidentsJson(const std::string& filepath) const;
    void exportIncidentsCsv(const std::string& filepath) const;
    const std::vector<SecurityIncident>& getIncidents() const { return incidents_; }

    // Signature Detection API (Phase 3.4)
    bool loadSignatureRules(const std::string& filepath);
    bool loadSignatureDirectory(const std::string& dirpath);
    std::string generateSignatureReport() const;
    void exportSignaturesJson(const std::string& filepath) const;
    void exportSignaturesCsv(const std::string& filepath) const;
    const std::vector<SignatureEvent>& getSignatures() const { return signature_events_; }
    SignatureEngine& getSignatureEngine() { return signature_engine_; }
    const SignatureEngine& getSignatureEngine() const { return signature_engine_; }
    
    // Threat Intelligence API (Phase 3.5)
    bool loadThreatIntelDataset(const std::string& filepath);
    bool loadThreatIntelDirectory(const std::string& dirpath);
    std::string generateThreatIntelReport() const;
    void exportThreatMatchesJson(const std::string& filepath) const;
    void exportThreatMatchesCsv(const std::string& filepath) const;
    const std::vector<ThreatMatchEvent>& getThreatMatches() const { return threat_matches_; }
    ThreatIntelEngine& getThreatIntelEngine() { return threat_intel_engine_; }
    const ThreatIntelEngine& getThreatIntelEngine() const { return threat_intel_engine_; }

    // Risk Profiling & Analytics API (Phase 3.6)
    const RiskProfiler& getRiskProfiler() const { return risk_profiler_; }
    RiskProfiler& getRiskProfiler() { return risk_profiler_; }
    std::string generateRiskReport() const { return risk_profiler_.generateRiskReport(); }
    void exportEndpointsJson(const std::string& filepath) const;
    void exportRiskJson(const std::string& filepath) const;

    const NetworkAnalyticsEngine& getAnalyticsEngine() const { return analytics_engine_; }
    NetworkAnalyticsEngine& getAnalyticsEngine() { return analytics_engine_; }
    std::string generateAnalyticsReport() const { return analytics_engine_.generateAnalyticsReport(); }
    void exportAnalyticsJson(const std::string& filepath) const;
    void exportGraphJson(const std::string& filepath) const;
    void exportTemporalJson(const std::string& filepath) const;

    // Investigation Workspace API (Phase 3.7)
    const InvestigationManager& getInvestigationManager() const { return investigation_manager_; }
    InvestigationManager& getInvestigationManager() { return investigation_manager_; }

    // Reporting & Comprehensive Artifact Export (Phase 3.8 & 4.2)
    std::string generateHtmlReport(const std::string& pcap_filename = "") const;
    bool exportHtmlReport(const std::string& filepath, const std::string& pcap_filename = "") const;
    bool exportAllArtifacts(const std::string& directory, const std::string& pcap_filename = "");
    
    // Get detected behavioral events
    const std::vector<DetectionEvent>& getDetections() const { return detections_; }
    
    // Get real-time statistics
    const DPIStats& getStats() const;
    
    // Print live status
    void printStatus() const;
    
    // ========== Accessors ==========
    
    RuleManager& getRuleManager() { return *rule_manager_; }
    FPManager* getFPManager() { return fp_manager_.get(); }
    const FPManager* getFPManager() const { return fp_manager_.get(); }
    const Config& getConfig() const { return config_; }
    bool isRunning() const { return running_; }

private:
    Config config_;
    std::vector<DetectionEvent> detections_;
    std::vector<SecurityIncident> incidents_;
    std::vector<SignatureEvent> signature_events_;
    SignatureEngine signature_engine_;
    std::vector<ThreatMatchEvent> threat_matches_;
    ThreatIntelEngine threat_intel_engine_;
    RiskProfiler risk_profiler_;
    NetworkAnalyticsEngine analytics_engine_;
    InvestigationManager investigation_manager_;
    
    // Shared components
    std::unique_ptr<RuleManager> rule_manager_;
    std::unique_ptr<GlobalConnectionTable> global_conn_table_;
    
    // Thread pools
    std::unique_ptr<FPManager> fp_manager_;
    std::unique_ptr<LBManager> lb_manager_;
    
    // Output handling
    ThreadSafeQueue<PacketJob> output_queue_;
    std::thread output_thread_;
    std::ofstream output_file_;
    std::mutex output_mutex_;
    
    // In-order packet reordering
    std::mutex reorder_mutex_;
    uint32_t next_expected_packet_id_{0};
    std::unordered_map<uint32_t, PacketJob> reorder_buffer_;
    
    // Statistics
    DPIStats stats_;
    
    // Control and deterministic synchronization
    std::atomic<bool> running_{false};
    std::atomic<bool> processing_complete_{false};
    std::atomic<bool> reader_finished_{false};
    std::atomic<uint32_t> total_input_packets_{0};
    std::atomic<bool> all_packets_done_{false};
    std::mutex completion_mutex_;
    std::condition_variable completion_cv_;
    
    // Reader thread (separate for PCAP input)
    std::thread reader_thread_;
    
    // Output handling
    void outputThreadFunc();
    void handleOutput(const PacketJob& job, PacketAction action);
    
    // Write PCAP header to output file
    bool writeOutputHeader(const PacketAnalyzer::PcapGlobalHeader& header);
    
    // Write a packet to output file
    void writeOutputPacket(const PacketJob& job);
    
    // Reader function
    void readerThreadFunc(const std::string& input_file);
    
    // Convert ParsedPacket to PacketJob
    PacketJob createPacketJob(const PacketAnalyzer::RawPacket& raw,
                               const PacketAnalyzer::ParsedPacket& parsed,
                               uint32_t packet_id);
};

} // namespace DPI

#endif // DPI_ENGINE_H
