#include "dpi_engine.h"
#include "logger.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <filesystem>

namespace DPI {

// ============================================================================
// DPIEngine Implementation
// ============================================================================

DPIEngine::DPIEngine(const Config& config)
    : config_(config), output_queue_(10000) {
    
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    DPI ENGINE v1.0                            ║\n";
    std::cout << "║               Deep Packet Inspection System                   ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Configuration:                                                ║\n";
    std::cout << "║   Load Balancers:    " << std::setw(3) << config.num_load_balancers << "                                       ║\n";
    std::cout << "║   FPs per LB:        " << std::setw(3) << config.fps_per_lb << "                                       ║\n";
    std::cout << "║   Total FP threads:  " << std::setw(3) << (config.num_load_balancers * config.fps_per_lb) << "                                       ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
}

DPIEngine::~DPIEngine() {
    stop();
}

bool DPIEngine::initialize() {
    // Create rule manager
    rule_manager_ = std::make_unique<RuleManager>();
    
    // Load rules if specified
    if (!config_.rules_file.empty()) {
        rule_manager_->loadRules(config_.rules_file);
    }
    
    // Create output callback
    auto output_cb = [this](const PacketJob& job, PacketAction action) {
        handleOutput(job, action);
    };
    
    // Create FP manager (creates FP threads and their queues)
    int total_fps = config_.num_load_balancers * config_.fps_per_lb;
    fp_manager_ = std::make_unique<FPManager>(total_fps, rule_manager_.get(), output_cb,
                                              config_.reassembly_config, config_.enable_stream_reassembly);
    
    // Create LB manager (creates LB threads, connects to FP queues)
    lb_manager_ = std::make_unique<LBManager>(
        config_.num_load_balancers,
        config_.fps_per_lb,
        fp_manager_->getQueuePtrs()
    );
    
    // Create global connection table
    global_conn_table_ = std::make_unique<GlobalConnectionTable>(total_fps);
    for (int i = 0; i < total_fps; i++) {
        global_conn_table_->registerTracker(i, &fp_manager_->getFP(i).getConnectionTracker());
    }
    
    std::cout << "[DPIEngine] Initialized successfully\n";
    return true;
}

void DPIEngine::start() {
    if (running_) return;
    
    running_ = true;
    processing_complete_ = false;
    reader_finished_ = false;
    total_input_packets_ = 0;
    all_packets_done_ = false;
    next_expected_packet_id_ = 0;
    reorder_buffer_.clear();
    
    // Start output thread
    output_thread_ = std::thread(&DPIEngine::outputThreadFunc, this);
    
    // Start FP threads
    fp_manager_->startAll();
    
    // Start LB threads
    lb_manager_->startAll();
    
    std::cout << "[DPIEngine] All threads started\n";
}

void DPIEngine::stop() {
    if (!running_) return;
    
    running_ = false;
    
    // Stop LB threads first (they feed FPs)
    if (lb_manager_) {
        lb_manager_->stopAll();
    }
    
    // Stop FP threads
    if (fp_manager_) {
        fp_manager_->stopAll();
    }
    
    // Unblock completion wait if pending
    {
        std::lock_guard<std::mutex> lock(completion_mutex_);
        all_packets_done_ = true;
    }
    completion_cv_.notify_all();
    
    // Stop output thread
    output_queue_.shutdown();
    if (output_thread_.joinable()) {
        output_thread_.join();
    }
    
    std::cout << "[DPIEngine] All threads stopped\n";
}

void DPIEngine::waitForCompletion() {
    // Wait for reader to finish
    if (reader_thread_.joinable()) {
        reader_thread_.join();
    }
    
    // Wait for output thread to finish writing all packets deterministically
    {
        std::unique_lock<std::mutex> lock(completion_mutex_);
        completion_cv_.wait(lock, [this]() {
            return all_packets_done_.load() || !running_.load();
        });
    }
    
    // Signal completion
    processing_complete_ = true;
}

bool DPIEngine::processFile(const std::string& input_file,
                            const std::string& output_file) {
    
    std::cout << "\n[DPIEngine] Processing: " << input_file << "\n";
    std::cout << "[DPIEngine] Output to:  " << output_file << "\n\n";
    
    // Initialize if not already done
    if (!rule_manager_) {
        if (!initialize()) {
            return false;
        }
    }
    
    // Open output file
    output_file_.open(output_file, std::ios::binary);
    if (!output_file_.is_open()) {
        std::cerr << "[DPIEngine] Error: Cannot open output file\n";
        return false;
    }
    
    // Start processing threads
    start();
    
    // Start reader thread
    reader_thread_ = std::thread(&DPIEngine::readerThreadFunc, this, input_file);
    
    // Wait for completion
    waitForCompletion();
    
    // Stop all threads
    stop();
    
    // Close output file
    if (output_file_.is_open()) {
        output_file_.close();
    }
    
    // Print final report
    std::cout << generateReport();
    std::cout << fp_manager_->generateClassificationReport();
    
    if (config_.show_flow_stats) {
        std::cout << generateFlowIntelligenceReport();
    }
    
    if (!config_.export_flows_json.empty()) {
        exportFlowsJson(config_.export_flows_json);
    }
    
    if (!config_.export_flows_csv.empty()) {
        exportFlowsCsv(config_.export_flows_csv);
    }
    
    // Behavioral Network Detection (Phase 3.1)
    if (config_.enable_detection || !config_.export_detections_json.empty() || 
        !config_.export_detections_csv.empty() || config_.show_detection_stats) {
        DetectionEngine detection_engine(config_.detection_config);
        auto all_flows = fp_manager_->getAllFinalizedFlows();
        detections_ = detection_engine.runDetections(all_flows);
        
        if (config_.show_detection_stats) {
            std::cout << generateDetectionReport();
        }
        if (!config_.export_detections_json.empty()) {
            exportDetectionsJson(config_.export_detections_json);
        }
        if (!config_.export_detections_csv.empty()) {
            exportDetectionsCsv(config_.export_detections_csv);
        }
    }
    
    // TCP Stream Reassembly Reporting & Export (Phase 3.2)
    if (config_.show_stream_stats) {
        std::cout << generateStreamReport();
    }
    if (!config_.export_streams_json.empty()) {
        exportStreamsJson(config_.export_streams_json);
    }
    if (!config_.export_streams_csv.empty()) {
        exportStreamsCsv(config_.export_streams_csv);
    }

    // Signature-Based Intrusion Detection Engine (Phase 3.4)
    if (config_.enable_signatures || !config_.signature_rules_file.empty() ||
        !config_.signature_rules_dir.empty() || !config_.export_signatures_json.empty() ||
        !config_.export_signatures_csv.empty() || config_.show_signature_stats) {
        
        signature_engine_.setConfig(config_.signature_config);
        std::vector<std::string> sig_errors;
        if (!config_.signature_rules_file.empty()) {
            signature_engine_.getRuleManager().loadRuleFile(config_.signature_rules_file, sig_errors);
        }
        if (!config_.signature_rules_dir.empty()) {
            signature_engine_.getRuleManager().loadRuleDirectory(config_.signature_rules_dir, sig_errors);
        }
        for (const auto& err : sig_errors) {
            std::cerr << "[SignatureEngine] Rule Load Error: " << err << "\n";
        }

        auto all_flows = fp_manager_->getAllFinalizedFlows();
        auto all_streams = fp_manager_->getAllFinalizedStreams();
        signature_events_ = signature_engine_.evaluateAll(all_flows, all_streams);

        if (config_.show_signature_stats) {
            std::cout << generateSignatureReport();
        }
        if (!config_.export_signatures_json.empty()) {
            exportSignaturesJson(config_.export_signatures_json);
        }
        if (!config_.export_signatures_csv.empty()) {
            exportSignaturesCsv(config_.export_signatures_csv);
        }
    }

    // Threat Intelligence Enrichment & IOC Matching (Phase 3.5)
    if (config_.enable_threat_intel || !config_.threat_intel_file.empty() ||
        !config_.threat_intel_dir.empty() || !config_.export_threat_matches_json.empty() ||
        !config_.export_threat_matches_csv.empty() || config_.show_threat_intel_stats) {

        threat_intel_engine_.setConfig(config_.threat_intel_config);
        std::vector<std::string> ti_errors;
        if (!config_.threat_intel_file.empty()) {
            threat_intel_engine_.getManager().loadDatasetFile(config_.threat_intel_file, ti_errors);
        }
        if (!config_.threat_intel_dir.empty()) {
            threat_intel_engine_.getManager().loadDatasetDirectory(config_.threat_intel_dir, ti_errors);
        }
        for (const auto& err : ti_errors) {
            std::cerr << "[ThreatIntel] Load Error: " << err << "\n";
        }

        auto all_flows = fp_manager_->getAllFinalizedFlows();
        auto all_streams = fp_manager_->getAllFinalizedStreams();
        threat_matches_ = threat_intel_engine_.evaluateAll(all_flows, all_streams, &detections_, &signature_events_);

        if (config_.show_threat_intel_stats) {
            std::cout << generateThreatIntelReport();
        }
        if (!config_.export_threat_matches_json.empty()) {
            exportThreatMatchesJson(config_.export_threat_matches_json);
        }
        if (!config_.export_threat_matches_csv.empty()) {
            exportThreatMatchesCsv(config_.export_threat_matches_csv);
        }
    }

    // Security Incident Intelligence & Threat Correlation (Phase 3.3)
    if (config_.enable_incidents) {
        IncidentCorrelator correlator(config_.incident_config);
        auto all_flows = fp_manager_->getAllFinalizedFlows();
        auto all_streams = fp_manager_->getAllFinalizedStreams();
        incidents_ = correlator.correlate(detections_, all_flows, all_streams, signature_events_, threat_matches_);

        if (config_.show_incident_stats) {
            std::cout << generateIncidentReport();
        }
        if (!config_.export_incidents_json.empty()) {
            exportIncidentsJson(config_.export_incidents_json);
        }
        if (!config_.export_incidents_csv.empty()) {
            exportIncidentsCsv(config_.export_incidents_csv);
        }
    }

    // Advanced Network Analytics & Risk Profiling (Phase 3.6)
    if (config_.enable_risk_profiling || config_.show_risk_stats ||
        !config_.export_endpoints_json.empty() || !config_.export_risk_json.empty() ||
        !config_.analyze_all_dir.empty()) {
        auto all_flows = fp_manager_->getAllFinalizedFlows();
        risk_profiler_.profileAll(all_flows, detections_, incidents_, signature_events_, threat_matches_);

        if (config_.show_risk_stats) {
            std::cout << generateRiskReport();
        }
        if (!config_.export_endpoints_json.empty()) {
            exportEndpointsJson(config_.export_endpoints_json);
        }
        if (!config_.export_risk_json.empty()) {
            exportRiskJson(config_.export_risk_json);
        }
    }

    // Network Behavioral Statistics, Temporal Analytics & Graph (Phase 3.6)
    if (config_.enable_analytics || config_.show_analytics_stats ||
        !config_.export_analytics_json.empty() || !config_.export_graph_json.empty() ||
        !config_.export_temporal_json.empty() || !config_.analyze_all_dir.empty()) {
        auto all_flows = fp_manager_->getAllFinalizedFlows();
        analytics_engine_.runAnalytics(all_flows, risk_profiler_.getEndpointProfiles(),
                                      detections_, incidents_, threat_matches_);

        if (config_.show_analytics_stats) {
            std::cout << generateAnalyticsReport();
        }
        if (!config_.export_analytics_json.empty()) {
            exportAnalyticsJson(config_.export_analytics_json);
        }
        if (!config_.export_graph_json.empty()) {
            exportGraphJson(config_.export_graph_json);
        }
        if (!config_.export_temporal_json.empty()) {
            exportTemporalJson(config_.export_temporal_json);
        }
    }

    // Investigation Workspace Initialization (Phase 3.7)
    if (!incidents_.empty() && investigation_manager_.getInvestigationCount() == 0) {
        std::string inv_id = investigation_manager_.createInvestigation(
            "Automated Security Investigation - " + input_file,
            "Correlated findings from deep packet inspection of " + input_file,
            InvestigationPriority::HIGH, {"AUTOMATED_DPI", "TRIAGE"});
        
        for (const auto& inc : incidents_) {
            investigation_manager_.linkIncident(inv_id, inc.incident_id);
            investigation_manager_.linkEndpoint(inv_id, inc.primary_endpoint);
            investigation_manager_.addEvidence(inv_id, EvidenceType::SECURITY_INCIDENT,
                                               inc.incident_id, inc.title, inc.toJson());
        }
        for (const auto& tm : threat_matches_) {
            investigation_manager_.linkIOC(inv_id, tm.ioc_id);
            investigation_manager_.addEvidence(inv_id, EvidenceType::THREAT_IOC,
                                               tm.ioc_id, tm.evidence, tm.toJson());
        }
        investigation_manager_.addNote(inv_id, "SYSTEM_TRIAGE",
                                       "Created automated investigation containing " +
                                       std::to_string(incidents_.size()) + " correlated incident(s) and " +
                                       std::to_string(threat_matches_.size()) + " threat intelligence match(es).");
    }

    // Reporting Engine (Phase 3.8)
    CaptureMetadata meta;
    meta.pcap_filename = input_file;
    meta.total_packets = stats_.total_packets;
    meta.total_bytes = stats_.total_bytes;

    auto all_flows = fp_manager_->getAllFinalizedFlows();
    ReportGenerator rep_gen(meta, all_flows, risk_profiler_.getEndpointProfiles(),
                            analytics_engine_.getStats(), analytics_engine_.getTemporal(),
                            detections_, signature_events_, incidents_, threat_matches_,
                            investigation_manager_.getAllInvestigations());

    if (!config_.report_executive_json.empty()) {
        rep_gen.exportReport(ReportType::EXECUTIVE, config_.report_executive_json);
    }
    if (!config_.report_technical_json.empty()) {
        rep_gen.exportReport(ReportType::TECHNICAL, config_.report_technical_json);
    }
    if (!config_.report_security_json.empty()) {
        rep_gen.exportReport(ReportType::SECURITY, config_.report_security_json);
    }
    if (!config_.report_incident_json.empty()) {
        rep_gen.exportReport(ReportType::INCIDENT, config_.report_incident_json);
    }
    if (!config_.report_threat_intel_json.empty()) {
        rep_gen.exportReport(ReportType::THREAT_INTEL, config_.report_threat_intel_json);
    }
    if (!config_.report_html_file.empty()) {
        rep_gen.exportHtml(config_.report_html_file);
        std::cout << "[DPIEngine] Exported HTML analysis report to " << config_.report_html_file << "\n";
    }

    // Unified Pipeline Artifact Bundle Export (Phase 4.2)
    if (!config_.analyze_all_dir.empty()) {
        exportAllArtifacts(config_.analyze_all_dir, input_file);
    }

    return true;
}

void DPIEngine::readerThreadFunc(const std::string& input_file) {
    PacketAnalyzer::PcapReader reader;
    
    if (!reader.open(input_file)) {
        std::cerr << "[Reader] Error: Cannot open input file\n";
        reader_finished_ = true;
        {
            std::lock_guard<std::mutex> lock(completion_mutex_);
            all_packets_done_ = true;
        }
        completion_cv_.notify_all();
        return;
    }
    
    // Write PCAP header to output
    writeOutputHeader(reader.getGlobalHeader());
    
    PacketAnalyzer::RawPacket raw;
    PacketAnalyzer::ParsedPacket parsed;
    uint32_t packet_id = 0;
    
    Logger::log("[Reader] Starting packet processing...");
    
    int total_fps = config_.num_load_balancers * config_.fps_per_lb;
    FiveTupleHash hasher;
    
    while (running_ && reader.readNextPacket(raw)) {
        stats_.total_packets++;
        stats_.total_bytes += raw.data.size();
        
        // Parse the packet
        if (!PacketAnalyzer::PacketParser::parse(raw, parsed)) {
            continue;  // Skip unparseable packets
        }
        
        // Only process IP packets with TCP/UDP
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) {
            continue;
        }
        
        // Create packet job
        PacketJob job = createPacketJob(raw, parsed, packet_id++);
        
        if (parsed.has_tcp) {
            stats_.tcp_packets++;
        } else if (parsed.has_udp) {
            stats_.udp_packets++;
        }
        
        // Pre-compute deterministic target global FP so it's guaranteed identical across LB and FP
        job.target_fp = (total_fps > 0) ? static_cast<int>(hasher(job.tuple) % total_fps) : 0;
        
        // Send to appropriate LB based on hash
        LoadBalancer& lb = lb_manager_->getLBForPacket(job.tuple);
        lb.getInputQueue().push(std::move(job));
    }
    
    Logger::log("[Reader] Finished reading " + std::to_string(packet_id) + " packets");
    reader.close();
    
    total_input_packets_ = packet_id;
    reader_finished_ = true;
    
    if (packet_id == 0) {
        {
            std::lock_guard<std::mutex> lock(completion_mutex_);
            all_packets_done_ = true;
        }
        completion_cv_.notify_all();
    }
}

PacketJob DPIEngine::createPacketJob(const PacketAnalyzer::RawPacket& raw,
                                      const PacketAnalyzer::ParsedPacket& parsed,
                                      uint32_t packet_id) {
    PacketJob job;
    job.packet_id = packet_id;
    job.ts_sec = raw.header.ts_sec;
    job.ts_usec = raw.header.ts_usec;
    job.action = PacketAction::FORWARD;
    
    // Set five-tuple - parse IP addresses from string back to uint32
    auto parseIP = [](const std::string& ip) -> uint32_t {
        uint32_t result = 0;
        int octet = 0;
        int shift = 0;
        for (char c : ip) {
            if (c == '.') {
                result |= (octet << shift);
                shift += 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
            }
        }
        result |= (octet << shift);
        return result;
    };
    
    job.tuple.src_ip = parseIP(parsed.src_ip);
    job.tuple.dst_ip = parseIP(parsed.dest_ip);
    job.tuple.src_port = parsed.src_port;
    job.tuple.dst_port = parsed.dest_port;
    job.tuple.protocol = parsed.protocol;
    
    // TCP flags and sequence numbers
    job.tcp_flags = parsed.tcp_flags;
    if (parsed.has_tcp) {
        job.tcp_seq = parsed.seq_number;
        job.tcp_ack = parsed.ack_number;
    }
    
    // Copy packet data
    job.data = raw.data;
    job.eth_offset = 0;
    
    // Safely assign payload bounds using parsed offsets directly
    if (parsed.payload_data && parsed.payload_length > 0 &&
        parsed.payload_data >= raw.data.data() &&
        parsed.payload_data <= raw.data.data() + raw.data.size()) {
        job.payload_offset = parsed.payload_data - raw.data.data();
        job.payload_length = parsed.payload_length;
        job.payload_data = job.data.data() + job.payload_offset;
    } else {
        job.payload_offset = job.data.size();
        job.payload_length = 0;
        job.payload_data = nullptr;
    }
    
    return job;
}

void DPIEngine::outputThreadFunc() {
    while (running_ || !output_queue_.empty()) {
        auto job_opt = output_queue_.popWithTimeout(std::chrono::milliseconds(50));
        
        if (job_opt) {
            std::lock_guard<std::mutex> lock(reorder_mutex_);
            reorder_buffer_[job_opt->packet_id] = std::move(*job_opt);
            
            while (true) {
                auto it = reorder_buffer_.find(next_expected_packet_id_);
                if (it == reorder_buffer_.end()) {
                    break;
                }
                
                if (it->second.action == PacketAction::FORWARD) {
                    writeOutputPacket(it->second);
                }
                reorder_buffer_.erase(it);
                next_expected_packet_id_++;
            }
        }
        
        if (reader_finished_.load()) {
            std::lock_guard<std::mutex> lock(reorder_mutex_);
            if (next_expected_packet_id_ >= total_input_packets_.load()) {
                {
                    std::lock_guard<std::mutex> c_lock(completion_mutex_);
                    all_packets_done_ = true;
                }
                completion_cv_.notify_all();
            }
        }
    }
}

void DPIEngine::handleOutput(const PacketJob& job, PacketAction action) {
    PacketJob out_job = job;
    out_job.action = action;
    if (action == PacketAction::DROP) {
        stats_.dropped_packets++;
        out_job.data.clear();
    } else {
        stats_.forwarded_packets++;
    }
    output_queue_.push(std::move(out_job));
}

bool DPIEngine::writeOutputHeader(const PacketAnalyzer::PcapGlobalHeader& header) {
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    if (!output_file_.is_open()) return false;
    
    output_file_.write(reinterpret_cast<const char*>(&header), sizeof(header));
    return output_file_.good();
}

void DPIEngine::writeOutputPacket(const PacketJob& job) {
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    if (!output_file_.is_open()) return;
    
    // Write packet header
    PacketAnalyzer::PcapPacketHeader pkt_header;
    pkt_header.ts_sec = job.ts_sec;
    pkt_header.ts_usec = job.ts_usec;
    pkt_header.incl_len = job.data.size();
    pkt_header.orig_len = job.data.size();
    
    output_file_.write(reinterpret_cast<const char*>(&pkt_header), sizeof(pkt_header));
    output_file_.write(reinterpret_cast<const char*>(job.data.data()), job.data.size());
}

// ============================================================================
// Rule Management API
// ============================================================================

void DPIEngine::blockIP(const std::string& ip) {
    if (rule_manager_) {
        rule_manager_->blockIP(ip);
    }
}

void DPIEngine::unblockIP(const std::string& ip) {
    if (rule_manager_) {
        rule_manager_->unblockIP(ip);
    }
}

void DPIEngine::blockApp(AppType app) {
    if (rule_manager_) {
        rule_manager_->blockApp(app);
    }
}

void DPIEngine::blockApp(const std::string& app_name) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        if (appTypeToString(static_cast<AppType>(i)) == app_name) {
            blockApp(static_cast<AppType>(i));
            return;
        }
    }
    std::cerr << "[DPIEngine] Unknown app: " << app_name << "\n";
}

void DPIEngine::unblockApp(AppType app) {
    if (rule_manager_) {
        rule_manager_->unblockApp(app);
    }
}

void DPIEngine::unblockApp(const std::string& app_name) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        if (appTypeToString(static_cast<AppType>(i)) == app_name) {
            unblockApp(static_cast<AppType>(i));
            return;
        }
    }
}

void DPIEngine::blockDomain(const std::string& domain) {
    if (rule_manager_) {
        rule_manager_->blockDomain(domain);
    }
}

void DPIEngine::unblockDomain(const std::string& domain) {
    if (rule_manager_) {
        rule_manager_->unblockDomain(domain);
    }
}

void DPIEngine::blockPort(uint16_t port) {
    if (rule_manager_) {
        rule_manager_->blockPort(port);
    }
}

void DPIEngine::unblockPort(uint16_t port) {
    if (rule_manager_) {
        rule_manager_->unblockPort(port);
    }
}

bool DPIEngine::loadRules(const std::string& filename) {
    if (rule_manager_) {
        return rule_manager_->loadRules(filename);
    }
    return false;
}

bool DPIEngine::saveRules(const std::string& filename) {
    if (rule_manager_) {
        return rule_manager_->saveRules(filename);
    }
    return false;
}

// ============================================================================
// Reporting
// ============================================================================

std::string DPIEngine::generateReport() const {
    std::ostringstream ss;
    
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║                    DPI ENGINE STATISTICS                      ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    ss << "║ PACKET STATISTICS                                             ║\n";
    ss << "║   Total Packets:      " << std::setw(12) << stats_.total_packets.load() << "                        ║\n";
    ss << "║   Total Bytes:        " << std::setw(12) << stats_.total_bytes.load() << "                        ║\n";
    ss << "║   TCP Packets:        " << std::setw(12) << stats_.tcp_packets.load() << "                        ║\n";
    ss << "║   UDP Packets:        " << std::setw(12) << stats_.udp_packets.load() << "                        ║\n";
    
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║ FILTERING STATISTICS                                          ║\n";
    ss << "║   Forwarded:          " << std::setw(12) << stats_.forwarded_packets.load() << "                        ║\n";
    ss << "║   Dropped/Blocked:    " << std::setw(12) << stats_.dropped_packets.load() << "                        ║\n";
    
    if (stats_.total_packets > 0) {
        double drop_rate = 100.0 * stats_.dropped_packets.load() / stats_.total_packets.load();
        ss << "║   Drop Rate:          " << std::setw(11) << std::fixed << std::setprecision(2) << drop_rate << "%                        ║\n";
    }
    
    if (lb_manager_) {
        auto lb_stats = lb_manager_->getAggregatedStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ LOAD BALANCER STATISTICS                                      ║\n";
        ss << "║   LB Received:        " << std::setw(12) << lb_stats.total_received << "                        ║\n";
        ss << "║   LB Dispatched:      " << std::setw(12) << lb_stats.total_dispatched << "                        ║\n";
    }
    
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ FAST PATH STATISTICS                                          ║\n";
        ss << "║   FP Processed:       " << std::setw(12) << fp_stats.total_processed << "                        ║\n";
        ss << "║   FP Forwarded:       " << std::setw(12) << fp_stats.total_forwarded << "                        ║\n";
        ss << "║   FP Dropped:         " << std::setw(12) << fp_stats.total_dropped << "                        ║\n";
        ss << "║   Active Connections: " << std::setw(12) << fp_stats.total_connections << "                        ║\n";
    }
    
    if (rule_manager_) {
        auto rule_stats = rule_manager_->getStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ BLOCKING RULES                                                ║\n";
        ss << "║   Blocked IPs:        " << std::setw(12) << rule_stats.blocked_ips << "                        ║\n";
        ss << "║   Blocked Apps:       " << std::setw(12) << rule_stats.blocked_apps << "                        ║\n";
        ss << "║   Blocked Domains:    " << std::setw(12) << rule_stats.blocked_domains << "                        ║\n";
        ss << "║   Blocked Ports:      " << std::setw(12) << rule_stats.blocked_ports << "                        ║\n";
    }
    
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return ss.str();
}

std::string DPIEngine::generateClassificationReport() const {
    if (fp_manager_) {
        return fp_manager_->generateClassificationReport();
    }
    return "";
}

std::string DPIEngine::generateFlowIntelligenceReport() const {
    if (fp_manager_) {
        return fp_manager_->generateFlowIntelligenceReport();
    }
    return "";
}

void DPIEngine::exportFlowsJson(const std::string& filepath) const {
    if (!fp_manager_) return;
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[DPIEngine] Error: Failed to open " << filepath << " for JSON export\n";
        return;
    }
    fp_manager_->exportAllFlowsJson(ofs);
    ofs.close();
    std::cout << "[DPIEngine] Exported flow intelligence JSON to " << filepath << "\n";
}

void DPIEngine::exportFlowsCsv(const std::string& filepath) const {
    if (!fp_manager_) return;
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[DPIEngine] Error: Failed to open " << filepath << " for CSV export\n";
        return;
    }
    fp_manager_->exportAllFlowsCsv(ofs);
    ofs.close();
    std::cout << "[DPIEngine] Exported flow intelligence CSV to " << filepath << "\n";
}

std::string DPIEngine::generateDetectionReport() const {
    return DetectionEngine::generateReport(detections_);
}

void DPIEngine::exportDetectionsJson(const std::string& filepath) const {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[DPIEngine] Error: Failed to open " << filepath << " for detection JSON export\n";
        return;
    }
    DetectionEngine::exportJson(detections_, ofs);
    ofs.close();
    std::cout << "[DPIEngine] Exported behavioral detections JSON to " << filepath << "\n";
}

void DPIEngine::exportDetectionsCsv(const std::string& filepath) const {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[DPIEngine] Error: Failed to open " << filepath << " for detection CSV export\n";
        return;
    }
    DetectionEngine::exportCsv(detections_, ofs);
    ofs.close();
    std::cout << "[DPIEngine] Exported behavioral detections CSV to " << filepath << "\n";
}

const DPIStats& DPIEngine::getStats() const {
    return stats_;
}

void DPIEngine::printStatus() const {
    std::cout << "\n--- Live Status ---\n";
    std::cout << "Packets: " << stats_.total_packets.load()
              << " | Forwarded: " << stats_.forwarded_packets.load()
              << " | Dropped: " << stats_.dropped_packets.load() << "\n";
    
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        std::cout << "Connections: " << fp_stats.total_connections << "\n";
    }
}

std::string DPIEngine::generateStreamReport() const {
    if (!fp_manager_) return "";
    return fp_manager_->generateStreamStatsReport();
}

void DPIEngine::exportStreamsJson(const std::string& filepath) const {
    if (!fp_manager_) return;
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[DPIEngine] Error opening stream JSON export file: " << filepath << "\n";
        return;
    }
    fp_manager_->exportAllStreamsJson(ofs);
    ofs.close();
    std::cout << "[DPIEngine] Exported stream reassembly JSON to " << filepath << "\n";
}

void DPIEngine::exportStreamsCsv(const std::string& filepath) const {
    if (!fp_manager_) return;
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[DPIEngine] Error opening stream CSV export file: " << filepath << "\n";
        return;
    }
    fp_manager_->exportAllStreamsCsv(ofs);
    ofs.close();
    std::cout << "[DPIEngine] Exported stream reassembly CSV to " << filepath << "\n";
}

std::string DPIEngine::generateIncidentReport() const {
    return IncidentCorrelator::generateReport(incidents_);
}

void DPIEngine::exportIncidentsJson(const std::string& filepath) const {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[DPIEngine] Error opening incident JSON export file: " << filepath << "\n";
        return;
    }
    IncidentCorrelator::exportJson(incidents_, ofs);
    ofs.close();
    std::cout << "[DPIEngine] Exported security incidents JSON to " << filepath << "\n";
}

void DPIEngine::exportIncidentsCsv(const std::string& filepath) const {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[DPIEngine] Error opening incident CSV export file: " << filepath << "\n";
        return;
    }
    IncidentCorrelator::exportCsv(incidents_, ofs);
    ofs.close();
    std::cout << "[DPIEngine] Exported security incidents CSV to " << filepath << "\n";
}

bool DPIEngine::loadSignatureRules(const std::string& filepath) {
    std::vector<std::string> errors;
    bool ok = signature_engine_.getRuleManager().loadRuleFile(filepath, errors);
    for (const auto& err : errors) {
        std::cerr << "[DPIEngine] Signature rule load error: " << err << "\n";
    }
    return ok;
}

bool DPIEngine::loadSignatureDirectory(const std::string& dirpath) {
    std::vector<std::string> errors;
    bool ok = signature_engine_.getRuleManager().loadRuleDirectory(dirpath, errors);
    for (const auto& err : errors) {
        std::cerr << "[DPIEngine] Signature directory load error: " << err << "\n";
    }
    return ok;
}

std::string DPIEngine::generateSignatureReport() const {
    return signature_engine_.generateReport(signature_events_);
}

void DPIEngine::exportSignaturesJson(const std::string& filepath) const {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[DPIEngine] Error opening signature JSON export file: " << filepath << "\n";
        return;
    }
    signature_engine_.exportJson(signature_events_, ofs);
    ofs.close();
    std::cout << "[DPIEngine] Exported signature events JSON to " << filepath << "\n";
}

void DPIEngine::exportSignaturesCsv(const std::string& filepath) const {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[DPIEngine] Error opening signature CSV export file: " << filepath << "\n";
        return;
    }
    signature_engine_.exportCsv(signature_events_, ofs);
    ofs.close();
    std::cout << "[DPIEngine] Exported signature events CSV to " << filepath << "\n";
}

bool DPIEngine::loadThreatIntelDataset(const std::string& filepath) {
    std::vector<std::string> errors;
    bool ok = threat_intel_engine_.getManager().loadDatasetFile(filepath, errors);
    for (const auto& err : errors) {
        std::cerr << "[DPIEngine] Threat intel dataset load error: " << err << "\n";
    }
    return ok;
}

bool DPIEngine::loadThreatIntelDirectory(const std::string& dirpath) {
    std::vector<std::string> errors;
    bool ok = threat_intel_engine_.getManager().loadDatasetDirectory(dirpath, errors);
    for (const auto& err : errors) {
        std::cerr << "[DPIEngine] Threat intel directory load error: " << err << "\n";
    }
    return ok;
}

std::string DPIEngine::generateThreatIntelReport() const {
    return threat_intel_engine_.generateReport(threat_matches_);
}

void DPIEngine::exportThreatMatchesJson(const std::string& filepath) const {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[DPIEngine] Error opening threat matches JSON export file: " << filepath << "\n";
        return;
    }
    threat_intel_engine_.exportJson(threat_matches_, ofs);
    ofs.close();
    std::cout << "[DPIEngine] Exported threat match events JSON to " << filepath << "\n";
}

void DPIEngine::exportThreatMatchesCsv(const std::string& filepath) const {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[DPIEngine] Error opening threat matches CSV export file: " << filepath << "\n";
        return;
    }
    threat_intel_engine_.exportCsv(threat_matches_, ofs);
    ofs.close();
    std::cout << "[DPIEngine] Exported threat match events CSV to " << filepath << "\n";
}

void DPIEngine::exportEndpointsJson(const std::string& filepath) const {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[DPIEngine] Error opening endpoints JSON export file: " << filepath << "\n";
        return;
    }
    ofs << risk_profiler_.endpointsToJson();
    ofs.close();
    std::cout << "[DPIEngine] Exported endpoint profiles to " << filepath << "\n";
}

void DPIEngine::exportRiskJson(const std::string& filepath) const {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[DPIEngine] Error opening risk summary JSON export file: " << filepath << "\n";
        return;
    }
    ofs << risk_profiler_.summaryToJson();
    ofs.close();
    std::cout << "[DPIEngine] Exported risk assessment summary to " << filepath << "\n";
}

void DPIEngine::exportAnalyticsJson(const std::string& filepath) const {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[DPIEngine] Error opening analytics JSON export file: " << filepath << "\n";
        return;
    }
    ofs << analytics_engine_.toJson();
    ofs.close();
    std::cout << "[DPIEngine] Exported behavioral analytics JSON to " << filepath << "\n";
}

void DPIEngine::exportGraphJson(const std::string& filepath) const {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[DPIEngine] Error opening graph JSON export file: " << filepath << "\n";
        return;
    }
    ofs << analytics_engine_.getGraph().toJson();
    ofs.close();
    std::cout << "[DPIEngine] Exported network relationship graph to " << filepath << "\n";
}

void DPIEngine::exportTemporalJson(const std::string& filepath) const {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) {
        std::cerr << "[DPIEngine] Error opening temporal JSON export file: " << filepath << "\n";
        return;
    }
    ofs << analytics_engine_.getTemporal().toJson();
    ofs.close();
    std::cout << "[DPIEngine] Exported temporal analytics to " << filepath << "\n";
}

std::string DPIEngine::generateHtmlReport(const std::string& pcap_filename) const {
    CaptureMetadata meta;
    meta.pcap_filename = pcap_filename.empty() ? "capture.pcap" : pcap_filename;
    meta.total_packets = stats_.total_packets;
    meta.total_bytes = stats_.total_bytes;

    auto all_flows = fp_manager_->getAllFinalizedFlows();
    ReportGenerator rep_gen(meta, all_flows, risk_profiler_.getEndpointProfiles(),
                            analytics_engine_.getStats(), analytics_engine_.getTemporal(),
                            detections_, signature_events_, incidents_, threat_matches_,
                            investigation_manager_.getAllInvestigations());
    return rep_gen.generateHtmlReport();
}

bool DPIEngine::exportHtmlReport(const std::string& filepath, const std::string& pcap_filename) const {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) return false;
    ofs << generateHtmlReport(pcap_filename);
    ofs.close();
    return true;
}

bool DPIEngine::exportAllArtifacts(const std::string& directory, const std::string& pcap_filename) {
    if (!directory.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(directory, ec);
    }

    std::string prefix = directory;
    if (!prefix.empty() && prefix.back() != '/') prefix += "/";

    std::cout << "\n[DPIEngine] Exporting unified analysis artifact bundle to directory: " << directory << "\n";

    exportFlowsJson(prefix + "flows.json");
    exportFlowsCsv(prefix + "flows.csv");
    exportDetectionsJson(prefix + "detections.json");
    exportDetectionsCsv(prefix + "detections.csv");
    exportStreamsJson(prefix + "streams.json");
    exportStreamsCsv(prefix + "streams.csv");
    exportSignaturesJson(prefix + "signatures.json");
    exportSignaturesCsv(prefix + "signatures.csv");
    exportThreatMatchesJson(prefix + "threat_matches.json");
    exportThreatMatchesCsv(prefix + "threat_matches.csv");
    exportIncidentsJson(prefix + "incidents.json");
    exportIncidentsCsv(prefix + "incidents.csv");
    exportEndpointsJson(prefix + "endpoints.json");
    exportRiskJson(prefix + "risk_summary.json");
    exportAnalyticsJson(prefix + "analytics.json");
    exportGraphJson(prefix + "network_graph.json");
    exportTemporalJson(prefix + "temporal_analytics.json");

    // Save investigations
    investigation_manager_.saveToFile(prefix + "investigations.json");

    // Save HTML Report
    exportHtmlReport(prefix + "analysis_report.html", pcap_filename);

    std::cout << "[DPIEngine] Complete analysis artifact bundle exported successfully.\n";
    return true;
}

} // namespace DPI
