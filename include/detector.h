#ifndef DPI_DETECTOR_H
#define DPI_DETECTOR_H

#include "detection_types.h"
#include "detection_config.h"
#include "flow_record.h"
#include <string>
#include <vector>

namespace DPI {

class BehavioralDetector {
public:
    virtual ~BehavioralDetector() = default;

    // Unique detector identifier (e.g., "port_scan_detector")
    virtual std::string getName() const = 0;

    // Primary category of alerts produced by this detector
    virtual DetectionCategory getCategory() const = 0;

    // Execute detection over the collection of flow records
    virtual std::vector<DetectionEvent> detect(
        const std::vector<FlowRecord>& flows,
        const DetectionConfig& config) = 0;
};

} // namespace DPI

#endif // DPI_DETECTOR_H
