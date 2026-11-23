#ifndef DPI_REPORT_GENERATOR_H
#define DPI_REPORT_GENERATOR_H

#include "flow_record.h"
#include "risk_profiler.h"
#include "network_analytics.h"
#include "detection_types.h"
#include "incident_types.h"
#include "signature_types.h"
#include "threat_intel_types.h"
#include "investigation_types.h"
#include <string>
#include <vector>
#include <unordered_map>

namespace DPI {

enum class ReportType {
    EXECUTIVE,
    TECHNICAL,
    SECURITY,
    INCIDENT,
    THREAT_INTEL,
    ALL
};

struct CaptureMetadata {
    std::string pcap_filename;
    uint64_t file_size_bytes = 0;
    uint64_t start_time_us = 0;
    uint64_t end_time_us = 0;
    uint32_t total_packets = 0;
    uint64_t total_bytes = 0;
    std::string sha256_hash;
    std::string engine_version = "v1.0 (Phase 3.8)";
};

class ReportGenerator {
public:
    ReportGenerator(const CaptureMetadata& meta,
                    const std::vector<FlowRecord>& flows,
                    const std::unordered_map<std::string, EndpointRiskProfile>& endpoints,
                    const NetworkBehavioralStats& stats,
                    const TemporalAnalytics& temporal,
                    const std::vector<DetectionEvent>& detections,
                    const std::vector<SignatureEvent>& signatures,
                    const std::vector<SecurityIncident>& incidents,
                    const std::vector<ThreatMatchEvent>& threat_matches,
                    const std::vector<InvestigationRecord>& investigations = {});

    // Individual JSON Reports
    std::string generateExecutiveJson() const;
    std::string generateTechnicalJson() const;
    std::string generateSecurityJson() const;
    std::string generateIncidentJson() const;
    std::string generateThreatIntelJson() const;

    // Comprehensive Self-Contained HTML Report
    std::string generateHtmlReport() const;

    // File exporters
    bool exportReport(ReportType type, const std::string& filepath) const;
    bool exportHtml(const std::string& filepath) const;
    bool exportAll(const std::string& directory) const;

private:
    CaptureMetadata meta_;
    const std::vector<FlowRecord>& flows_;
    std::unordered_map<std::string, EndpointRiskProfile> endpoints_;
    NetworkBehavioralStats stats_;
    TemporalAnalytics temporal_;
    std::vector<DetectionEvent> detections_;
    std::vector<SignatureEvent> signatures_;
    std::vector<SecurityIncident> incidents_;
    std::vector<ThreatMatchEvent> threat_matches_;
    std::vector<InvestigationRecord> investigations_;
};

} // namespace DPI

#endif // DPI_REPORT_GENERATOR_H
