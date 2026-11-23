#include "report_generator.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <filesystem>

namespace DPI {

ReportGenerator::ReportGenerator(const CaptureMetadata& meta,
                                 const std::vector<FlowRecord>& flows,
                                 const std::unordered_map<std::string, EndpointRiskProfile>& endpoints,
                                 const NetworkBehavioralStats& stats,
                                 const TemporalAnalytics& temporal,
                                 const std::vector<DetectionEvent>& detections,
                                 const std::vector<SignatureEvent>& signatures,
                                 const std::vector<SecurityIncident>& incidents,
                                 const std::vector<ThreatMatchEvent>& threat_matches,
                                 const std::vector<InvestigationRecord>& investigations)
    : meta_(meta), flows_(flows), endpoints_(endpoints), stats_(stats),
      temporal_(temporal), detections_(detections), signatures_(signatures),
      incidents_(incidents), threat_matches_(threat_matches), investigations_(investigations) {}

std::string ReportGenerator::generateExecutiveJson() const {
    size_t crit_inc = 0, high_inc = 0, med_inc = 0;
    for (const auto& inc : incidents_) {
        if (inc.severity == IncidentSeverity::CRITICAL) crit_inc++;
        else if (inc.severity == IncidentSeverity::HIGH) high_inc++;
        else if (inc.severity == IncidentSeverity::MEDIUM) med_inc++;
    }

    std::ostringstream ss;
    ss << "{\n"
       << "  \"report_type\": \"EXECUTIVE_SUMMARY\",\n"
       << "  \"engine_version\": \"" << meta_.engine_version << "\",\n"
       << "  \"pcap_file\": \"" << meta_.pcap_filename << "\",\n"
       << "  \"total_packets\": " << stats_.total_packets << ",\n"
       << "  \"total_bytes\": " << stats_.total_bytes << ",\n"
       << "  \"total_flows\": " << stats_.total_flows << ",\n"
       << "  \"unique_endpoints\": " << (stats_.unique_sources + stats_.unique_destinations) << ",\n"
       << "  \"total_detections\": " << detections_.size() << ",\n"
       << "  \"total_signatures\": " << signatures_.size() << ",\n"
       << "  \"total_threat_matches\": " << threat_matches_.size() << ",\n"
       << "  \"total_incidents\": " << incidents_.size() << ",\n"
       << "  \"critical_incidents\": " << crit_inc << ",\n"
       << "  \"high_incidents\": " << high_inc << ",\n"
       << "  \"medium_incidents\": " << med_inc << ",\n"
       << "  \"top_protocols\": {\n";
    bool first = true;
    for (const auto& p : stats_.protocol_breakdown) {
        if (!first) ss << ",\n";
        ss << "    \"" << p.first << "\": " << p.second.bytes;
        first = false;
    }
    ss << "\n  }\n}";
    return ss.str();
}

std::string ReportGenerator::generateTechnicalJson() const {
    std::ostringstream ss;
    ss << "{\n"
       << "  \"report_type\": \"TECHNICAL_TRAFFIC_ANALYSIS\",\n"
       << "  \"metadata\": {\n"
       << "    \"pcap\": \"" << meta_.pcap_filename << "\",\n"
       << "    \"packets\": " << stats_.total_packets << ",\n"
       << "    \"bytes\": " << stats_.total_bytes << "\n"
       << "  },\n"
       << "  \"statistics\": " << stats_.toJson() << ",\n"
       << "  \"temporal\": " << temporal_.toJson() << "\n"
       << "}";
    return ss.str();
}

std::string ReportGenerator::generateSecurityJson() const {
    std::ostringstream ss;
    ss << "{\n"
       << "  \"report_type\": \"SECURITY_ASSESSMENT\",\n"
       << "  \"total_detections\": " << detections_.size() << ",\n"
       << "  \"total_signatures\": " << signatures_.size() << ",\n"
       << "  \"total_threat_matches\": " << threat_matches_.size() << ",\n"
       << "  \"total_incidents\": " << incidents_.size() << ",\n"
       << "  \"detections\": [\n";
    for (size_t i = 0; i < detections_.size(); ++i) {
        if (i > 0) ss << ",\n";
        ss << "    " << detections_[i].toJson();
    }
    ss << "\n  ],\n  \"signatures\": [\n";
    for (size_t i = 0; i < signatures_.size(); ++i) {
        if (i > 0) ss << ",\n";
        ss << "    " << signatures_[i].toJson();
    }
    ss << "\n  ]\n}";
    return ss.str();
}

std::string ReportGenerator::generateIncidentJson() const {
    std::ostringstream ss;
    ss << "[\n";
    for (size_t i = 0; i < incidents_.size(); ++i) {
        if (i > 0) ss << ",\n";
        ss << "  " << incidents_[i].toJson();
    }
    ss << "\n]\n";
    return ss.str();
}

std::string ReportGenerator::generateThreatIntelJson() const {
    std::ostringstream ss;
    ss << "[\n";
    for (size_t i = 0; i < threat_matches_.size(); ++i) {
        if (i > 0) ss << ",\n";
        ss << "  " << threat_matches_[i].toJson();
    }
    ss << "\n]\n";
    return ss.str();
}

std::string ReportGenerator::generateHtmlReport() const {
    std::ostringstream ss;
    ss << "<!DOCTYPE html>\n"
       << "<html lang=\"en\">\n"
       << "<head>\n"
       << "  <meta charset=\"UTF-8\">\n"
       << "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
       << "  <title>DPI & Network Security Analysis Report</title>\n"
       << "  <style>\n"
       << "    :root { --bg: #090d16; --card-bg: #111827; --card-border: #1f293d; --text: #f3f4f6; --text-muted: #9ca3af; --primary: #38bdf8; --danger: #ef4444; --warning: #f59e0b; --success: #10b981; }\n"
       << "    body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; }\n"
       << "    .container { max-width: 1400px; margin: 0 auto; padding: 24px; }\n"
       << "    header { border-bottom: 1px solid var(--card-border); padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }\n"
       << "    h1 { margin: 0; font-size: 24px; font-weight: 700; color: var(--primary); }\n"
       << "    .subtitle { color: var(--text-muted); font-size: 14px; margin-top: 4px; }\n"
       << "    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }\n"
       << "    .stat-card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 8px; padding: 16px; }\n"
       << "    .stat-title { font-size: 12px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }\n"
       << "    .stat-value { font-size: 28px; font-weight: 700; color: var(--text); margin-top: 6px; }\n"
       << "    .nav-tabs { display: flex; gap: 8px; border-bottom: 1px solid var(--card-border); margin-bottom: 24px; }\n"
       << "    .tab-btn { background: none; border: none; color: var(--text-muted); padding: 10px 16px; font-size: 14px; font-weight: 600; cursor: pointer; border-bottom: 2px solid transparent; transition: all 0.2s; }\n"
       << "    .tab-btn.active { color: var(--primary); border-bottom-color: var(--primary); }\n"
       << "    .tab-pane { display: none; }\n"
       << "    .tab-pane.active { display: block; }\n"
       << "    .card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 8px; padding: 20px; margin-bottom: 24px; }\n"
       << "    .card-title { font-size: 18px; font-weight: 600; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between; }\n"
       << "    table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }\n"
       << "    th { background: #1a2234; padding: 10px 12px; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--card-border); }\n"
       << "    td { padding: 10px 12px; border-bottom: 1px solid var(--card-border); }\n"
       << "    tr:hover td { background: #151e30; }\n"
       << "    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }\n"
       << "    .badge-critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }\n"
       << "    .badge-high { background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b; }\n"
       << "    .badge-medium { background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid #38bdf8; }\n"
       << "    .badge-low { background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; }\n"
       << "    .badge-clean { background: rgba(156, 163, 175, 0.2); color: #9ca3af; border: 1px solid #9ca3af; }\n"
       << "  </style>\n"
       << "</head>\n"
       << "<body>\n"
       << "  <div class=\"container\">\n"
       << "    <header>\n"
       << "      <div>\n"
       << "        <h1>DPI Engine & Network Security Analysis</h1>\n"
       << "        <div class=\"subtitle\">Target PCAP: <strong>" << meta_.pcap_filename << "</strong> | Engine: " << meta_.engine_version << "</div>\n"
       << "      </div>\n"
       << "      <div style=\"text-align: right; font-size: 12px; color: var(--text-muted);\">\n"
       << "        <div>Analyzed Traffic: " << stats_.total_bytes << " bytes (" << stats_.total_packets << " packets)</div>\n"
       << "        <div>Active Flows: " << stats_.total_flows << " | Distinct Endpoints: " << (stats_.unique_sources + stats_.unique_destinations) << "</div>\n"
       << "      </div>\n"
       << "    </header>\n\n"
       << "    <div class=\"stats-grid\">\n"
       << "      <div class=\"stat-card\">\n"
       << "        <div class=\"stat-title\">Total Packets</div>\n"
       << "        <div class=\"stat-value\">" << stats_.total_packets << "</div>\n"
       << "      </div>\n"
       << "      <div class=\"stat-card\">\n"
       << "        <div class=\"stat-title\">Total Flows</div>\n"
       << "        <div class=\"stat-value\">" << stats_.total_flows << "</div>\n"
       << "      </div>\n"
       << "      <div class=\"stat-card\">\n"
       << "        <div class=\"stat-title\">Security Incidents</div>\n"
       << "        <div class=\"stat-value\" style=\"color: " << (incidents_.empty() ? "var(--success)" : "var(--danger)") << ";\">" << incidents_.size() << "</div>\n"
       << "      </div>\n"
       << "      <div class=\"stat-card\">\n"
       << "        <div class=\"stat-title\">Threat IOC Matches</div>\n"
       << "        <div class=\"stat-value\" style=\"color: " << (threat_matches_.empty() ? "var(--success)" : "var(--warning)") << ";\">" << threat_matches_.size() << "</div>\n"
       << "      </div>\n"
       << "      <div class=\"stat-card\">\n"
       << "        <div class=\"stat-title\">Behavioral Alerts</div>\n"
       << "        <div class=\"stat-value\">" << detections_.size() << "</div>\n"
       << "      </div>\n"
       << "    </div>\n\n"
       << "    <div class=\"nav-tabs\">\n"
       << "      <button class=\"tab-btn active\" onclick=\"showTab('executive')\">Executive Summary</button>\n"
       << "      <button class=\"tab-btn\" onclick=\"showTab('traffic')\">Traffic & Endpoints</button>\n"
       << "      <button class=\"tab-btn\" onclick=\"showTab('incidents')\">Security Incidents (" << incidents_.size() << ")</button>\n"
       << "      <button class=\"tab-btn\" onclick=\"showTab('threats')\">Threat Intel (" << threat_matches_.size() << ")</button>\n"
       << "      <button class=\"tab-btn\" onclick=\"showTab('investigations')\">Investigations (" << investigations_.size() << ")</button>\n"
       << "    </div>\n\n"
       << "    <div id=\"executive\" class=\"tab-pane active\">\n"
       << "      <div class=\"card\">\n"
       << "        <div class=\"card-title\">Executive Overview & Security Posture</div>\n"
       << "        <p>This automated Deep Packet Inspection analysis performed deep stateful flow reconstruction, behavioral anomaly detection, signature matching, and local threat intelligence enrichment across <strong>" << stats_.total_packets << "</strong> packets and <strong>" << flows_.size() << "</strong> bidirectional flows.</p>\n"
       << "        <p>A total of <strong>" << incidents_.size() << "</strong> security incident(s) and <strong>" << threat_matches_.size() << "</strong> threat intelligence match(es) were identified.</p>\n"
       << "      </div>\n"
       << "      <div class=\"card\">\n"
       << "        <div class=\"card-title\">Top Protocol Volume Distribution</div>\n"
       << "        <table>\n"
       << "          <thead><tr><th>Protocol</th><th>Flows</th><th>Packets</th><th>Bytes</th><th>Traffic Share</th></tr></thead>\n"
       << "          <tbody>\n";
    for (const auto& p : stats_.protocol_breakdown) {
        double pct = stats_.total_bytes > 0 ? (p.second.bytes * 100.0 / stats_.total_bytes) : 0.0;
        ss << "            <tr><td><strong>" << p.first << "</strong></td><td>" << p.second.flows << "</td><td>"
           << p.second.packets << "</td><td>" << p.second.bytes << " B</td><td>"
           << std::fixed << std::setprecision(1) << pct << "%</td></tr>\n";
    }
    ss << "          </tbody>\n        </table>\n      </div>\n    </div>\n\n"
       << "    <div id=\"traffic\" class=\"tab-pane\">\n"
       << "      <div class=\"card\">\n"
       << "        <div class=\"card-title\">Top Endpoints & Risk Ratings</div>\n"
       << "        <table>\n"
       << "          <thead><tr><th>IP Address</th><th>Internal</th><th>Role</th><th>Traffic Volume</th><th>Flows</th><th>Risk Score</th><th>Rating</th></tr></thead>\n"
       << "          <tbody>\n";
    for (const auto& pair : endpoints_) {
        const auto& ep = pair.second;
        std::string badge_cls = (ep.risk_level == RiskLevel::CRITICAL) ? "badge-critical" :
                                (ep.risk_level == RiskLevel::HIGH) ? "badge-high" :
                                (ep.risk_level == RiskLevel::MEDIUM) ? "badge-medium" :
                                (ep.risk_level == RiskLevel::LOW) ? "badge-low" : "badge-clean";
        ss << "            <tr><td><code>" << ep.ip << "</code></td><td>" << (ep.is_internal ? "Yes" : "No") << "</td><td>"
           << ep.role << "</td><td>" << ep.total_bytes << " B</td><td>" << ep.total_flows << "</td><td>"
           << std::fixed << std::setprecision(1) << ep.risk_score << "</td><td><span class=\"badge " << badge_cls << "\">"
           << riskLevelToString(ep.risk_level) << "</span></td></tr>\n";
    }
    ss << "          </tbody>\n        </table>\n      </div>\n    </div>\n\n"
       << "    <div id=\"incidents\" class=\"tab-pane\">\n"
       << "      <div class=\"card\">\n"
       << "        <div class=\"card-title\">Correlated Security Incidents</div>\n";
    if (incidents_.empty()) {
        ss << "        <p style=\"color: var(--success);\">No security incidents correlated for this capture.</p>\n";
    } else {
        ss << "        <table>\n"
           << "          <thead><tr><th>Incident ID</th><th>Severity</th><th>Score</th><th>Title</th><th>Primary Host</th><th>Correlated Flows</th></tr></thead>\n"
           << "          <tbody>\n";
        for (const auto& inc : incidents_) {
            std::string b_cls = (inc.severity == IncidentSeverity::CRITICAL) ? "badge-critical" :
                                (inc.severity == IncidentSeverity::HIGH) ? "badge-high" :
                                (inc.severity == IncidentSeverity::MEDIUM) ? "badge-medium" : "badge-low";
            ss << "            <tr><td><strong>" << inc.incident_id << "</strong></td><td><span class=\"badge " << b_cls << "\">"
               << incidentSeverityToString(inc.severity) << "</span></td><td>" << std::fixed << std::setprecision(1)
               << inc.correlation_score << "</td><td>" << inc.title << "</td><td><code>" << inc.primary_endpoint
               << "</code></td><td>" << inc.related_flow_ids.size() << "</td></tr>\n";
        }
        ss << "          </tbody>\n        </table>\n";
    }
    ss << "      </div>\n    </div>\n\n"
       << "    <div id=\"threats\" class=\"tab-pane\">\n"
       << "      <div class=\"card\">\n"
       << "        <div class=\"card-title\">Threat Intelligence Match Events</div>\n";
    if (threat_matches_.empty()) {
        ss << "        <p style=\"color: var(--success);\">No threat intelligence indicators matched in observed traffic.</p>\n";
    } else {
        ss << "        <table>\n"
           << "          <thead><tr><th>Event ID</th><th>Severity</th><th>IOC Type</th><th>IOC Value</th><th>Observed Host</th><th>Category</th></tr></thead>\n"
           << "          <tbody>\n";
        for (const auto& tm : threat_matches_) {
            std::string b_cls = (tm.severity == IOCSeverity::CRITICAL) ? "badge-critical" :
                                (tm.severity == IOCSeverity::HIGH) ? "badge-high" :
                                (tm.severity == IOCSeverity::MEDIUM) ? "badge-medium" : "badge-low";
            ss << "            <tr><td>" << tm.event_id << "</td><td><span class=\"badge " << b_cls << "\">"
               << iocSeverityToString(tm.severity) << "</span></td><td>" << iocTypeToString(tm.ioc_type) << "</td><td><code>"
               << tm.ioc_value << "</code></td><td><code>" << tm.src_ip << " -> " << tm.dst_ip << "</code></td><td>"
               << tm.category << "</td></tr>\n";
        }
        ss << "          </tbody>\n        </table>\n";
    }
    ss << "      </div>\n    </div>\n\n"
       << "    <div id=\"investigations\" class=\"tab-pane\">\n"
       << "      <div class=\"card\">\n"
       << "        <div class=\"card-title\">Active Investigation Workspace</div>\n";
    if (investigations_.empty()) {
        ss << "        <p style=\"color: var(--text-muted);\">No investigations active for this session.</p>\n";
    } else {
        ss << "        <table>\n"
           << "          <thead><tr><th>ID</th><th>Priority</th><th>Status</th><th>Title</th><th>Evidence Items</th><th>Notes</th></tr></thead>\n"
           << "          <tbody>\n";
        for (const auto& inv : investigations_) {
            ss << "            <tr><td><strong>" << inv.investigation_id << "</strong></td><td>"
               << investigationPriorityToString(inv.priority) << "</td><td>" << investigationStatusToString(inv.status)
               << "</td><td>" << inv.title << "</td><td>" << inv.evidence_list.size() << "</td><td>"
               << inv.notes.size() << "</td></tr>\n";
        }
        ss << "          </tbody>\n        </table>\n";
    }
    ss << "      </div>\n    </div>\n"
       << "  </div>\n\n"
       << "  <script>\n"
       << "    function showTab(tabId) {\n"
       << "      document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));\n"
       << "      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));\n"
       << "      document.getElementById(tabId).classList.add('active');\n"
       << "      event.currentTarget.classList.add('active');\n"
       << "    }\n"
       << "  </script>\n"
       << "</body>\n"
       << "</html>\n";
    return ss.str();
}

bool ReportGenerator::exportReport(ReportType type, const std::string& filepath) const {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) return false;

    switch (type) {
        case ReportType::EXECUTIVE:
            ofs << generateExecutiveJson();
            break;
        case ReportType::TECHNICAL:
            ofs << generateTechnicalJson();
            break;
        case ReportType::SECURITY:
            ofs << generateSecurityJson();
            break;
        case ReportType::INCIDENT:
            ofs << generateIncidentJson();
            break;
        case ReportType::THREAT_INTEL:
            ofs << generateThreatIntelJson();
            break;
        case ReportType::ALL:
            ofs << generateExecutiveJson();
            break;
    }
    return ofs.good();
}

bool ReportGenerator::exportHtml(const std::string& filepath) const {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) return false;
    ofs << generateHtmlReport();
    return ofs.good();
}

bool ReportGenerator::exportAll(const std::string& directory) const {
    if (!directory.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(directory, ec);
    }
    std::string prefix = directory;
    if (!prefix.empty() && prefix.back() != '/') prefix += "/";

    bool ok = true;
    ok &= exportReport(ReportType::EXECUTIVE, prefix + "report_executive.json");
    ok &= exportReport(ReportType::TECHNICAL, prefix + "report_technical.json");
    ok &= exportReport(ReportType::SECURITY, prefix + "report_security.json");
    ok &= exportReport(ReportType::INCIDENT, prefix + "report_incidents.json");
    ok &= exportReport(ReportType::THREAT_INTEL, prefix + "report_threat_intel.json");
    ok &= exportHtml(prefix + "analysis_report.html");
    return ok;
}

} // namespace DPI
