#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include "dpi_engine.h"

using namespace DPI;

void printUsage(const char* program) {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v1.0                            ║
║               Deep Packet Inspection System                   ║
╚══════════════════════════════════════════════════════════════╝

Usage: )" << program << R"( <input.pcap> <output.pcap> [options]

Arguments:
  input.pcap     Input PCAP file (captured user traffic)
  output.pcap    Output PCAP file (filtered traffic to internet)

Options:
  --block-ip <ip>        Block packets from source IP
  --block-app <app>      Block application (e.g., YouTube, Facebook)
  --block-domain <dom>   Block domain (supports wildcards: *.facebook.com)
  --block-port <port>    Block destination port (e.g., 80, 443)
  --rules <file>         Load blocking rules from file
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)
  --export-flows <file>  Export flow intelligence records to JSON
  --export-csv <file>    Export flow intelligence records to CSV
  --flow-stats           Print detailed Network Flow Intelligence report
  --detect               Enable behavioral network detection engine
  --export-detections <f> Export behavioral detections to JSON
  --export-detections-csv <f> Export behavioral detections to CSV
  --detection-stats      Print detailed Behavioral Network Detection report
  --enable-detector <d>  Enable specific detector (e.g. port_scan, beacon)
  --disable-detector <d> Disable specific detector (e.g. dns, burst)
  --stream-reassembly    Enable TCP stream reassembly (default)
  --no-stream-reassembly Disable TCP stream reassembly
  --stream-stats         Print detailed TCP Stream Reassembly report
  --export-streams <f>   Export reconstructed stream summaries to JSON
  --export-streams-csv <f> Export reconstructed stream summaries to CSV
  --stream-max-mem <mb>  Maximum total reassembly memory in MB (default: 64)
  --incidents            Enable security incident correlation
  --incident-stats       Print detailed Security Incident report
  --export-incidents <f> Export security incidents to JSON
  --export-incidents-csv <f> Export security incidents to CSV
  --incident-window <sec> Aggregation time window in seconds (default: 60)
  --incident-threshold <v> Minimum correlation score threshold (default: 20)
  --enable-correlation-rule <r> Enable specific correlation rule
  --disable-correlation-rule <r> Disable specific correlation rule
  --signatures           Enable signature-based intrusion detection engine
  --signature-stats      Print detailed Signature Detection report
  --sig-rules <f>        Load signature rules from JSON file
  --rules-dir <d>        Load signature rules from directory of JSON files
  --export-signatures <f> Export signature events to JSON
  --export-signatures-csv <f> Export signature events to CSV
  --signature-max-matches <n> Maximum signature matches to generate (default: 10000)
  --list-rules           List loaded signature rules and exit
  --threat-intel <f>     Load threat intelligence dataset from JSON file
  --threat-intel-dir <d> Load threat intelligence datasets from directory
  --threat-intelligence Enable threat intelligence enrichment engine
  --list-threat-datasets List loaded threat intelligence datasets and exit
  --threat-intel-stats   Print detailed Threat Intelligence & IOC report
  --export-threat-matches <f> Export threat match events to JSON
  --export-threat-matches-csv <f> Export threat match events to CSV
  --enable-threat-dataset <id> Enable specific threat dataset
  --disable-threat-dataset <id> Disable specific threat dataset
  --threat-match-limit <n> Maximum threat matches to generate (default: 10000)
  --risk-stats           Print detailed Network Risk Assessment report
  --export-endpoints <f> Export endpoint risk profiles to JSON
  --export-risk <f>      Export risk assessment summary to JSON
  --analytics-stats      Print detailed Network Behavioral Analytics report
  --export-analytics <f> Export behavioral statistics to JSON
  --export-graph <f>     Export network relationship graph to JSON
  --export-temporal <f>  Export temporal analytics to JSON
  --report-executive <f> Export Executive Summary report to JSON
  --report-technical <f> Export Technical Traffic report to JSON
  --report-security <f>  Export Security Assessment report to JSON
  --report-incident <f>  Export Incident report to JSON
  --report-threat-intel <f> Export Threat Intel report to JSON
  --report-html <f>      Generate standalone HTML analysis report
  --analyze-all <dir>    Execute full pipeline and export unified artifact bundle to directory
  --verbose              Enable verbose output

Examples:
  )" << program << R"( capture.pcap filtered.pcap
  )" << program << R"( capture.pcap filtered.pcap --block-app YouTube
  )" << program << R"( capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain *.tiktok.com
  )" << program << R"( capture.pcap filtered.pcap --rules blocking_rules.txt

Supported Apps for Blocking:
  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,
  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub

Architecture:
  ┌─────────────┐
  │ PCAP Reader │  Reads packets from input file
  └──────┬──────┘
         │ hash(5-tuple) % num_lbs
         ▼
  ┌──────┴──────┐
  │ Load Balancer │  2 LB threads distribute to FPs
  │   LB0 │ LB1   │
  └──┬────┴────┬──┘
     │         │  hash(5-tuple) % fps_per_lb
     ▼         ▼
  ┌──┴──┐   ┌──┴──┐
  │FP0-1│   │FP2-3│  4 FP threads: DPI, classification, blocking
  └──┬──┘   └──┬──┘
     │         │
     ▼         ▼
  ┌──┴─────────┴──┐
  │ Output Writer │  Writes forwarded packets to output
  └───────────────┘

)";
}

std::vector<std::string> split(const std::string& s) {
    std::vector<std::string> tokens;
    std::istringstream iss(s);
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string input_file = argv[1];
    std::string output_file = argv[2];
    
    // Parse options
    DPIEngine::Config config;
    config.num_load_balancers = 2;
    config.fps_per_lb = 2;
    
    std::vector<std::string> block_ips;
    std::vector<std::string> block_apps;
    std::vector<std::string> block_domains;
    std::vector<uint16_t> block_ports;
    std::string rules_file;
    bool list_rules = false;
    bool list_threat_datasets = false;
    std::vector<std::pair<std::string, bool>> dataset_toggles;
    
    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--block-ip" && i + 1 < argc) {
            block_ips.push_back(argv[++i]);
        } else if (arg == "--block-app" && i + 1 < argc) {
            block_apps.push_back(argv[++i]);
        } else if (arg == "--block-domain" && i + 1 < argc) {
            block_domains.push_back(argv[++i]);
        } else if (arg == "--block-port" && i + 1 < argc) {
            try {
                int p = std::stoi(argv[++i]);
                if (p > 0 && p <= 65535) {
                    block_ports.push_back(static_cast<uint16_t>(p));
                } else {
                    std::cerr << "[Warning] Invalid port number: " << argv[i] << "\n";
                }
            } catch (const std::exception& e) {
                std::cerr << "[Warning] Could not parse port: " << argv[i] << "\n";
            }
        } else if (arg == "--rules" && i + 1 < argc) {
            rules_file = argv[++i];
        } else if (arg == "--lbs" && i + 1 < argc) {
            try {
                int val = std::stoi(argv[++i]);
                if (val > 0) config.num_load_balancers = val;
            } catch (...) {
                std::cerr << "[Warning] Invalid --lbs parameter\n";
            }
        } else if (arg == "--fps" && i + 1 < argc) {
            try {
                int val = std::stoi(argv[++i]);
                if (val > 0) config.fps_per_lb = val;
            } catch (...) {
                std::cerr << "[Warning] Invalid --fps parameter\n";
            }
        } else if (arg == "--export-flows" && i + 1 < argc) {
            config.export_flows_json = argv[++i];
        } else if (arg == "--export-csv" && i + 1 < argc) {
            config.export_flows_csv = argv[++i];
        } else if (arg == "--flow-stats") {
            config.show_flow_stats = true;
        } else if (arg == "--detect") {
            config.enable_detection = true;
        } else if (arg == "--export-detections" && i + 1 < argc) {
            config.export_detections_json = argv[++i];
            config.enable_detection = true;
        } else if (arg == "--export-detections-csv" && i + 1 < argc) {
            config.export_detections_csv = argv[++i];
            config.enable_detection = true;
        } else if (arg == "--detection-stats") {
            config.show_detection_stats = true;
            config.enable_detection = true;
        } else if (arg == "--enable-detector" && i + 1 < argc) {
            config.detection_config.setDetectorEnabled(argv[++i], true);
        } else if (arg == "--disable-detector" && i + 1 < argc) {
            config.detection_config.setDetectorEnabled(argv[++i], false);
        } else if (arg == "--stream-reassembly") {
            config.enable_stream_reassembly = true;
        } else if (arg == "--no-stream-reassembly") {
            config.enable_stream_reassembly = false;
        } else if (arg == "--stream-stats") {
            config.show_stream_stats = true;
        } else if (arg == "--export-streams" && i + 1 < argc) {
            config.export_streams_json = argv[++i];
            config.enable_stream_reassembly = true;
        } else if (arg == "--export-streams-csv" && i + 1 < argc) {
            config.export_streams_csv = argv[++i];
            config.enable_stream_reassembly = true;
        } else if (arg == "--stream-max-mem" && i + 1 < argc) {
            try {
                size_t mb = std::stoul(argv[++i]);
                if (mb > 0) {
                    config.reassembly_config.max_total_reassembly_memory = mb * 1024 * 1024;
                }
            } catch (...) {}
        } else if (arg == "--incidents") {
            config.enable_incidents = true;
            config.enable_detection = true;
        } else if (arg == "--incident-stats") {
            config.show_incident_stats = true;
            config.enable_incidents = true;
            config.enable_detection = true;
        } else if (arg == "--export-incidents" && i + 1 < argc) {
            config.export_incidents_json = argv[++i];
            config.enable_incidents = true;
            config.enable_detection = true;
        } else if (arg == "--export-incidents-csv" && i + 1 < argc) {
            config.export_incidents_csv = argv[++i];
            config.enable_incidents = true;
            config.enable_detection = true;
        } else if (arg == "--incident-window" && i + 1 < argc) {
            try {
                double sec = std::stod(argv[++i]);
                if (sec > 0.0) config.incident_config.incident_window_seconds = sec;
            } catch (...) {}
        } else if (arg == "--incident-threshold" && i + 1 < argc) {
            try {
                double th = std::stod(argv[++i]);
                if (th >= 0.0) config.incident_config.min_incident_score = th;
            } catch (...) {}
        } else if (arg == "--enable-correlation-rule" && i + 1 < argc) {
            config.incident_config.setRuleEnabled(argv[++i], true);
        } else if (arg == "--disable-correlation-rule" && i + 1 < argc) {
            config.incident_config.setRuleEnabled(argv[++i], false);
        } else if ((arg == "--sig-rules" || arg == "--signature-rules") && i + 1 < argc) {
            config.signature_rules_file = argv[++i];
            config.enable_signatures = true;
        } else if (arg == "--rules-dir" && i + 1 < argc) {
            config.signature_rules_dir = argv[++i];
            config.enable_signatures = true;
        } else if (arg == "--signature-detection" || arg == "--signatures") {
            config.enable_signatures = true;
        } else if (arg == "--signature-stats") {
            config.show_signature_stats = true;
            config.enable_signatures = true;
        } else if (arg == "--export-signatures" && i + 1 < argc) {
            config.export_signatures_json = argv[++i];
            config.enable_signatures = true;
        } else if (arg == "--export-signatures-csv" && i + 1 < argc) {
            config.export_signatures_csv = argv[++i];
            config.enable_signatures = true;
        } else if (arg == "--signature-max-matches" && i + 1 < argc) {
            try {
                int mm = std::stoi(argv[++i]);
                if (mm > 0) config.signature_config.max_matches = static_cast<uint32_t>(mm);
            } catch (...) {}
        } else if (arg == "--list-rules") {
            list_rules = true;
        } else if ((arg == "--threat-intel" || arg == "--threat-intelligence") && i + 1 < argc && argv[i + 1][0] != '-') {
            config.threat_intel_file = argv[++i];
            config.enable_threat_intel = true;
        } else if (arg == "--threat-intelligence" || arg == "--threat-intel") {
            config.enable_threat_intel = true;
        } else if (arg == "--threat-intel-dir" && i + 1 < argc) {
            config.threat_intel_dir = argv[++i];
            config.enable_threat_intel = true;
        } else if (arg == "--threat-intel-stats") {
            config.show_threat_intel_stats = true;
            config.enable_threat_intel = true;
        } else if (arg == "--export-threat-matches" && i + 1 < argc) {
            config.export_threat_matches_json = argv[++i];
            config.enable_threat_intel = true;
        } else if (arg == "--export-threat-matches-csv" && i + 1 < argc) {
            config.export_threat_matches_csv = argv[++i];
            config.enable_threat_intel = true;
        } else if (arg == "--threat-match-limit" && i + 1 < argc) {
            try {
                int ml = std::stoi(argv[++i]);
                if (ml > 0) config.threat_intel_config.max_matches = static_cast<uint32_t>(ml);
            } catch (...) {}
        } else if (arg == "--enable-threat-dataset" && i + 1 < argc) {
            dataset_toggles.push_back({argv[++i], true});
        } else if (arg == "--disable-threat-dataset" && i + 1 < argc) {
            dataset_toggles.push_back({argv[++i], false});
        } else if (arg == "--list-threat-datasets") {
            list_threat_datasets = true;
        } else if (arg == "--risk-stats") {
            config.show_risk_stats = true;
            config.enable_risk_profiling = true;
        } else if (arg == "--export-endpoints" && i + 1 < argc) {
            config.export_endpoints_json = argv[++i];
            config.enable_risk_profiling = true;
        } else if (arg == "--export-risk" && i + 1 < argc) {
            config.export_risk_json = argv[++i];
            config.enable_risk_profiling = true;
        } else if (arg == "--analytics-stats") {
            config.show_analytics_stats = true;
            config.enable_analytics = true;
            config.enable_risk_profiling = true;
        } else if (arg == "--export-analytics" && i + 1 < argc) {
            config.export_analytics_json = argv[++i];
            config.enable_analytics = true;
            config.enable_risk_profiling = true;
        } else if (arg == "--export-graph" && i + 1 < argc) {
            config.export_graph_json = argv[++i];
            config.enable_analytics = true;
            config.enable_risk_profiling = true;
        } else if (arg == "--export-temporal" && i + 1 < argc) {
            config.export_temporal_json = argv[++i];
            config.enable_analytics = true;
            config.enable_risk_profiling = true;
        } else if (arg == "--report-executive" && i + 1 < argc) {
            config.report_executive_json = argv[++i];
        } else if (arg == "--report-technical" && i + 1 < argc) {
            config.report_technical_json = argv[++i];
            config.enable_analytics = true;
        } else if (arg == "--report-security" && i + 1 < argc) {
            config.report_security_json = argv[++i];
            config.enable_detection = true;
        } else if (arg == "--report-incident" && i + 1 < argc) {
            config.report_incident_json = argv[++i];
            config.enable_incidents = true;
        } else if (arg == "--report-threat-intel" && i + 1 < argc) {
            config.report_threat_intel_json = argv[++i];
            config.enable_threat_intel = true;
        } else if (arg == "--report-html" && i + 1 < argc) {
            config.report_html_file = argv[++i];
            config.enable_detection = true;
            config.enable_incidents = true;
            config.enable_risk_profiling = true;
            config.enable_analytics = true;
        } else if (arg == "--analyze-all" && i + 1 < argc) {
            config.analyze_all_dir = argv[++i];
            config.enable_detection = true;
            config.enable_stream_reassembly = true;
            config.enable_incidents = true;
            config.enable_signatures = true;
            config.enable_threat_intel = true;
            config.enable_risk_profiling = true;
            config.enable_analytics = true;
        } else if (arg == "--verbose") {
            config.verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        }
    }
    
    // Create DPI engine
    DPIEngine engine(config);
    
    // Initialize
    if (!engine.initialize()) {
        std::cerr << "Failed to initialize DPI engine\n";
        return 1;
    }
    
    // Load rules from file if specified
    if (!rules_file.empty()) {
        if (rules_file.size() > 5 && rules_file.substr(rules_file.size() - 5) == ".json") {
            engine.loadSignatureRules(rules_file);
        } else {
            engine.loadRules(rules_file);
        }
    }

    if (list_rules) {
        if (!config.signature_rules_file.empty()) {
            engine.loadSignatureRules(config.signature_rules_file);
        }
        if (!config.signature_rules_dir.empty()) {
            engine.loadSignatureDirectory(config.signature_rules_dir);
        }
        const auto& rules = engine.getSignatureEngine().getRuleManager().getRules();
        std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                 LOADED SIGNATURE RULES                       ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Total Rules: " << std::setw(47) << std::left << rules.size() << " ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        for (const auto& r : rules) {
            std::string status = r.enabled ? "ACTIVE" : "DISABLED";
            std::string id_str = r.rule_id;
            std::string name_str = r.name.size() > 34 ? r.name.substr(0, 31) + "..." : r.name;
            std::cout << "║ [" << std::setw(8) << std::left << status << "] "
                      << std::setw(15) << std::left << id_str << " "
                      << std::setw(34) << std::left << name_str << " ║\n";
        }
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
        return 0;
    }

    if (list_threat_datasets) {
        if (!config.threat_intel_file.empty()) {
            engine.loadThreatIntelDataset(config.threat_intel_file);
        }
        if (!config.threat_intel_dir.empty()) {
            engine.loadThreatIntelDirectory(config.threat_intel_dir);
        }
        for (const auto& [id, en] : dataset_toggles) {
            engine.getThreatIntelEngine().getManager().setDatasetEnabled(id, en);
        }
        const auto& dss = engine.getThreatIntelEngine().getManager().getDatasets();
        std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║            LOADED THREAT INTELLIGENCE DATASETS               ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Total Datasets: " << std::setw(44) << std::left << dss.size() << " ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        for (const auto& ds : dss) {
            std::string st = ds.enabled ? "ACTIVE" : "DISABLED";
            std::string id_str = ds.dataset_id + " v" + ds.version;
            std::string name_str = ds.name + " (" + std::to_string(ds.iocs.size()) + " IOCs)";
            if (name_str.size() > 32) name_str = name_str.substr(0, 29) + "...";
            std::cout << "║ [" << std::setw(8) << std::left << st << "] "
                      << std::setw(16) << std::left << id_str << " "
                      << std::setw(32) << std::left << name_str << " ║\n";
        }
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
        return 0;
    }
    
    // Apply command-line blocking rules
    for (const auto& ip : block_ips) {
        engine.blockIP(ip);
    }
    
    for (const auto& app : block_apps) {
        engine.blockApp(app);
    }
    
    for (const auto& domain : block_domains) {
        engine.blockDomain(domain);
    }
    
    for (uint16_t port : block_ports) {
        engine.blockPort(port);
    }
    
    // Process the file
    if (!engine.processFile(input_file, output_file)) {
        std::cerr << "Failed to process file\n";
        return 1;
    }
    
    std::cout << "\nProcessing complete!\n";
    std::cout << "Output written to: " << output_file << "\n";
    
    return 0;
}
