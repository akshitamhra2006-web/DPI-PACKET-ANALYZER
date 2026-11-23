#include "detection_engine.h"
#include "behavioral_detectors.h"
#include <iomanip>
#include <sstream>
#include <map>
#include <set>

namespace DPI {

DetectionEngine::DetectionEngine() {
    registerDefaultDetectors();
}

DetectionEngine::DetectionEngine(const DetectionConfig& config)
    : config_(config) {
    registerDefaultDetectors();
}

void DetectionEngine::registerDetector(std::unique_ptr<BehavioralDetector> detector) {
    detectors_.push_back(std::move(detector));
}

void DetectionEngine::registerDefaultDetectors() {
    detectors_.clear();
    detectors_.push_back(std::make_unique<PortScanDetector>());
    detectors_.push_back(std::make_unique<ConnectionBurstDetector>());
    detectors_.push_back(std::make_unique<RepeatedAttemptsDetector>());
    detectors_.push_back(std::make_unique<DNSAnomalyDetector>());
    detectors_.push_back(std::make_unique<OutboundAnomalyDetector>());
    detectors_.push_back(std::make_unique<BeaconDetector>());
    detectors_.push_back(std::make_unique<TCPAnomalyDetector>());
}

std::vector<DetectionEvent> DetectionEngine::runDetections(const std::vector<FlowRecord>& flows) {
    std::vector<DetectionEvent> all_events;

    for (const auto& detector : detectors_) {
        if (!config_.isDetectorEnabled(detector->getName())) {
            continue;
        }

        std::vector<DetectionEvent> events = detector->detect(flows, config_);
        all_events.insert(all_events.end(), 
                          std::make_move_iterator(events.begin()), 
                          std::make_move_iterator(events.end()));
    }

    return deduplicate(all_events);
}

std::vector<DetectionEvent> DetectionEngine::deduplicate(const std::vector<DetectionEvent>& events) {
    std::vector<DetectionEvent> deduplicated;
    std::set<std::string> seen_fingerprints;

    for (const auto& ev : events) {
        // Fingerprint consists of detector, category, source IP, destination IP, and window timestamp (1s granularity)
        std::ostringstream ss;
        ss << ev.detector_name << "|"
           << static_cast<int>(ev.category) << "|"
           << ev.source_ip << "|"
           << ev.destination_ip << "|"
           << (ev.timestamp_us / 1000000ULL);

        std::string fp = ss.str();
        if (seen_fingerprints.insert(fp).second) {
            deduplicated.push_back(ev);
        }
    }

    return deduplicated;
}

std::string DetectionEngine::generateReport(const std::vector<DetectionEvent>& events) {
    std::ostringstream ss;

    size_t total_events = events.size();
    size_t critical_count = 0;
    size_t high_count = 0;
    size_t medium_count = 0;
    size_t low_count = 0;
    size_t info_count = 0;

    std::map<DetectionCategory, size_t> category_counts;

    for (const auto& ev : events) {
        switch (ev.severity) {
            case DetectionSeverity::CRITICAL: critical_count++; break;
            case DetectionSeverity::HIGH:     high_count++; break;
            case DetectionSeverity::MEDIUM:   medium_count++; break;
            case DetectionSeverity::LOW:      low_count++; break;
            case DetectionSeverity::INFO:     info_count++; break;
        }
        category_counts[ev.category]++;
    }

    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║          BEHAVIORAL NETWORK DETECTION REPORT                 ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║ Total Detections:     " << std::setw(10) << total_events << "                           ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║                     SEVERITY BREAKDOWN                       ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║ CRITICAL:             " << std::setw(10) << critical_count << "                           ║\n";
    ss << "║ HIGH:                 " << std::setw(10) << high_count << "                           ║\n";
    ss << "║ MEDIUM:               " << std::setw(10) << medium_count << "                           ║\n";
    ss << "║ LOW:                  " << std::setw(10) << low_count << "                           ║\n";
    ss << "║ INFO:                 " << std::setw(10) << info_count << "                           ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║                     CATEGORY BREAKDOWN                       ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";

    for (const auto& pair : category_counts) {
        ss << "║ " << std::setw(30) << std::left << detectionCategoryToString(pair.first)
           << std::setw(8) << std::right << pair.second << "                     ║\n";
    }

    if (total_events > 0) {
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║                  DETECTED BEHAVIORAL EVENTS                  ║\n";
        ss << "╠══════════════════════════════════════════════════════════════╣\n";

        size_t shown = 0;
        for (const auto& ev : events) {
            ss << "║ [" << std::setw(8) << std::left << detectionSeverityToString(ev.severity) << "] "
               << std::setw(25) << std::left << ev.detector_name
               << " " << std::setw(23) << std::right << ev.source_ip_str << "  ║\n";
            ss << "║   -> " << std::setw(55) << std::left << ev.explanation.substr(0, 55) << " ║\n";

            if (++shown >= 10 && events.size() > 10) {
                ss << "║   ... and " << (events.size() - 10) << " more events                                   ║\n";
                break;
            }
        }
    }

    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    return ss.str();
}

void DetectionEngine::exportJson(const std::vector<DetectionEvent>& events, std::ostream& os, int indent) {
    (void)indent;
    os << "[\n";
    for (size_t i = 0; i < events.size(); ++i) {
        os << events[i].toJson(2);
        if (i + 1 < events.size()) {
            os << ",";
        }
        os << "\n";
    }
    os << "]\n";
}

void DetectionEngine::exportCsv(const std::vector<DetectionEvent>& events, std::ostream& os) {
    os << DetectionEvent::csvHeader() << "\n";
    for (const auto& ev : events) {
        os << ev.toCsvRow() << "\n";
    }
}

} // namespace DPI
