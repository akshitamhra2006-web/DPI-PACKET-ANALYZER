#ifndef DPI_DETECTION_ENGINE_H
#define DPI_DETECTION_ENGINE_H

#include "detection_types.h"
#include "detection_config.h"
#include "detector.h"
#include "flow_record.h"
#include <vector>
#include <memory>
#include <iostream>
#include <string>

namespace DPI {

class DetectionEngine {
public:
    DetectionEngine();
    explicit DetectionEngine(const DetectionConfig& config);
    ~DetectionEngine() = default;

    // Configuration accessors
    DetectionConfig& getConfig() { return config_; }
    const DetectionConfig& getConfig() const { return config_; }
    void setConfig(const DetectionConfig& config) { config_ = config; }

    // Detector registry
    void registerDetector(std::unique_ptr<BehavioralDetector> detector);
    void registerDefaultDetectors();
    const std::vector<std::unique_ptr<BehavioralDetector>>& getDetectors() const { return detectors_; }

    // Run detections across collected flow records
    std::vector<DetectionEvent> runDetections(const std::vector<FlowRecord>& flows);

    // Event deduplication
    static std::vector<DetectionEvent> deduplicate(const std::vector<DetectionEvent>& events);

    // Reporting & Serialization
    static std::string generateReport(const std::vector<DetectionEvent>& events);
    static void exportJson(const std::vector<DetectionEvent>& events, std::ostream& os, int indent = 2);
    static void exportCsv(const std::vector<DetectionEvent>& events, std::ostream& os);

private:
    DetectionConfig config_;
    std::vector<std::unique_ptr<BehavioralDetector>> detectors_;
};

} // namespace DPI

#endif // DPI_DETECTION_ENGINE_H
