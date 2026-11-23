#ifndef DPI_INVESTIGATION_TYPES_H
#define DPI_INVESTIGATION_TYPES_H

#include <string>
#include <vector>
#include <set>
#include <cstdint>

namespace DPI {

// ============================================================================
// INVESTIGATION STATUS & PRIORITY
// ============================================================================
enum class InvestigationStatus {
    OPEN,
    INVESTIGATING,
    ESCALATED,
    RESOLVED,
    CLOSED
};

std::string investigationStatusToString(InvestigationStatus status);
InvestigationStatus stringToInvestigationStatus(const std::string& str);

enum class InvestigationPriority {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW
};

std::string investigationPriorityToString(InvestigationPriority priority);
InvestigationPriority stringToInvestigationPriority(const std::string& str);

// ============================================================================
// EVIDENCE TYPES
// ============================================================================
enum class EvidenceType {
    FLOW_RECORD,
    SECURITY_INCIDENT,
    BEHAVIORAL_DETECTION,
    SIGNATURE_EVENT,
    THREAT_IOC,
    PACKET_CAPTURE,
    ANALYSIS_ARTIFACT,
    ANALYST_NOTE
};

std::string evidenceTypeToString(EvidenceType type);
EvidenceType stringToEvidenceType(const std::string& str);

// ============================================================================
// INVESTIGATION NOTE
// ============================================================================
struct InvestigationNote {
    std::string note_id;
    uint64_t timestamp_us = 0;
    std::string author;
    std::string content;

    std::string toJson() const;
};

// ============================================================================
// EVIDENCE REFERENCE
// ============================================================================
struct EvidenceReference {
    std::string evidence_id;
    EvidenceType type = EvidenceType::SECURITY_INCIDENT;
    std::string source_id; // e.g. INC-0001, DET-0005, IOC-01
    std::string description;
    std::string integrity_hash; // Content integrity verification
    uint64_t timestamp_us = 0;

    std::string toJson() const;
};

// ============================================================================
// INVESTIGATION RECORD
// ============================================================================
struct InvestigationRecord {
    std::string investigation_id;
    std::string title;
    std::string description;
    uint64_t created_at_us = 0;
    uint64_t updated_at_us = 0;
    InvestigationStatus status = InvestigationStatus::OPEN;
    InvestigationPriority priority = InvestigationPriority::MEDIUM;

    std::vector<std::string> related_incidents;
    std::vector<std::string> related_detections;
    std::vector<uint64_t> related_flows;
    std::vector<std::string> related_endpoints;
    std::vector<std::string> related_iocs;

    std::vector<InvestigationNote> notes;
    std::vector<EvidenceReference> evidence_list;
    std::vector<std::string> tags;

    std::string toJson() const;
    std::string toMarkdown() const;
};

} // namespace DPI

#endif // DPI_INVESTIGATION_TYPES_H
