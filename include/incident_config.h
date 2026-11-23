#ifndef DPI_INCIDENT_CONFIG_H
#define DPI_INCIDENT_CONFIG_H

#include <string>
#include <cstdint>
#include <cstddef>

namespace DPI {

struct IncidentConfig {
    // General Settings
    bool enable_correlation = false;
    double incident_window_seconds = 60.0; // Aggregation time window
    double min_incident_score = 20.0;      // Score threshold to promote to incident
    size_t max_timeline_events = 50;       // Max events per incident timeline (bounded memory)
    size_t max_incidents = 1000;           // Max tracked incidents per run

    // Rule Toggles
    bool enable_reconnaissance_correlation = true;
    bool enable_dns_correlation = true;
    bool enable_outbound_correlation = true;
    bool enable_exfiltration_correlation = true;
    bool enable_multistage_correlation = true;
    bool enable_tcp_anomaly_correlation = true;

    // Severity Weights
    double weight_critical = 40.0;
    double weight_high = 25.0;
    double weight_medium = 15.0;
    double weight_low = 8.0;
    double weight_info = 2.0;

    // Feature Weights
    double weight_multi_category = 15.0;
    double weight_stage_sequence = 20.0;
    double weight_high_asymmetry = 10.0;
    double weight_multiple_destinations = 10.0;
    double weight_beacon_consistency = 15.0;
    double weight_large_volume = 15.0;
    double weight_repeated_attempts = 10.0;

    // Thresholds
    double critical_score_threshold = 80.0;
    double high_score_threshold = 50.0;
    double medium_score_threshold = 25.0;

    // Methods
    bool validate() const;
    bool setRuleEnabled(const std::string& rule_name, bool enabled);
};

} // namespace DPI

#endif // DPI_INCIDENT_CONFIG_H
