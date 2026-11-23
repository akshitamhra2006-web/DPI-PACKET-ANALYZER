#ifndef DPI_BEHAVIORAL_DETECTORS_H
#define DPI_BEHAVIORAL_DETECTORS_H

#include "detector.h"

namespace DPI {

// ============================================================================
// A. Port Scan Detector (Vertical scans & Horizontal IP sweeps)
// ============================================================================
class PortScanDetector : public BehavioralDetector {
public:
    std::string getName() const override { return "port_scan_detector"; }
    DetectionCategory getCategory() const override { return DetectionCategory::NETWORK_RECONNAISSANCE; }
    std::vector<DetectionEvent> detect(const std::vector<FlowRecord>& flows, const DetectionConfig& config) override;
};

// ============================================================================
// B. Connection Burst Detector (Sudden surges in connection initiation)
// ============================================================================
class ConnectionBurstDetector : public BehavioralDetector {
public:
    std::string getName() const override { return "connection_burst_detector"; }
    DetectionCategory getCategory() const override { return DetectionCategory::CONNECTION_ANOMALY; }
    std::vector<DetectionEvent> detect(const std::vector<FlowRecord>& flows, const DetectionConfig& config) override;
};

// ============================================================================
// C. Repeated Connection Attempt Detector (Failed / repetitive attempts)
// ============================================================================
class RepeatedAttemptsDetector : public BehavioralDetector {
public:
    std::string getName() const override { return "repeated_attempts_detector"; }
    DetectionCategory getCategory() const override { return DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT; }
    std::vector<DetectionEvent> detect(const std::vector<FlowRecord>& flows, const DetectionConfig& config) override;
};

// ============================================================================
// D. Suspicious DNS Behavior Detector (Tunneling candidates, entropy, bursts)
// ============================================================================
class DNSAnomalyDetector : public BehavioralDetector {
public:
    std::string getName() const override { return "dns_anomaly_detector"; }
    DetectionCategory getCategory() const override { return DetectionCategory::SUSPICIOUS_DNS; }
    std::vector<DetectionEvent> detect(const std::vector<FlowRecord>& flows, const DetectionConfig& config) override;
};

// ============================================================================
// E. Unusual Outbound Traffic Detector (Large outbound volume & high asymmetry)
// ============================================================================
class OutboundAnomalyDetector : public BehavioralDetector {
public:
    std::string getName() const override { return "outbound_anomaly_detector"; }
    DetectionCategory getCategory() const override { return DetectionCategory::UNUSUAL_TRAFFIC_VOLUME; }
    std::vector<DetectionEvent> detect(const std::vector<FlowRecord>& flows, const DetectionConfig& config) override;
};

// ============================================================================
// F. Beacon-Like Communication Detector (Periodic polling / C2 patterns)
// ============================================================================
class BeaconDetector : public BehavioralDetector {
public:
    std::string getName() const override { return "beacon_detector"; }
    DetectionCategory getCategory() const override { return DetectionCategory::COMMAND_AND_CONTROL; }
    std::vector<DetectionEvent> detect(const std::vector<FlowRecord>& flows, const DetectionConfig& config) override;
};

// ============================================================================
// G. TCP Anomaly Detector (SYN flood patterns, abnormal RST ratios)
// ============================================================================
class TCPAnomalyDetector : public BehavioralDetector {
public:
    std::string getName() const override { return "tcp_anomaly_detector"; }
    DetectionCategory getCategory() const override { return DetectionCategory::PROTOCOL_ANOMALY; }
    std::vector<DetectionEvent> detect(const std::vector<FlowRecord>& flows, const DetectionConfig& config) override;
};

} // namespace DPI

#endif // DPI_BEHAVIORAL_DETECTORS_H
