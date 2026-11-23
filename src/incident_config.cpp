#include "incident_config.h"
#include <algorithm>

namespace DPI {

bool IncidentConfig::validate() const {
    if (incident_window_seconds <= 0.0 || incident_window_seconds > 86400.0) return false;
    if (min_incident_score < 0.0 || min_incident_score > 1000.0) return false;
    if (max_timeline_events == 0 || max_timeline_events > 10000) return false;
    if (max_incidents == 0 || max_incidents > 100000) return false;
    if (critical_score_threshold < high_score_threshold) return false;
    if (high_score_threshold < medium_score_threshold) return false;
    if (medium_score_threshold < min_incident_score) return false;
    return true;
}

bool IncidentConfig::setRuleEnabled(const std::string& rule_name, bool enabled) {
    if (rule_name == "reconnaissance" || rule_name == "recon") {
        enable_reconnaissance_correlation = enabled;
        return true;
    }
    if (rule_name == "dns" || rule_name == "dns_suspicious") {
        enable_dns_correlation = enabled;
        return true;
    }
    if (rule_name == "outbound" || rule_name == "suspicious_outbound") {
        enable_outbound_correlation = enabled;
        return true;
    }
    if (rule_name == "exfiltration" || rule_name == "data_exfiltration") {
        enable_exfiltration_correlation = enabled;
        return true;
    }
    if (rule_name == "multistage" || rule_name == "multi_stage") {
        enable_multistage_correlation = enabled;
        return true;
    }
    if (rule_name == "tcp" || rule_name == "tcp_anomaly") {
        enable_tcp_anomaly_correlation = enabled;
        return true;
    }
    return false;
}

} // namespace DPI
