#include "investigation_types.h"
#include <sstream>
#include <iomanip>

namespace DPI {

std::string investigationStatusToString(InvestigationStatus status) {
    switch (status) {
        case InvestigationStatus::OPEN:          return "OPEN";
        case InvestigationStatus::INVESTIGATING: return "INVESTIGATING";
        case InvestigationStatus::ESCALATED:     return "ESCALATED";
        case InvestigationStatus::RESOLVED:      return "RESOLVED";
        case InvestigationStatus::CLOSED:        return "CLOSED";
        default:                                 return "OPEN";
    }
}

InvestigationStatus stringToInvestigationStatus(const std::string& str) {
    if (str == "INVESTIGATING") return InvestigationStatus::INVESTIGATING;
    if (str == "ESCALATED")     return InvestigationStatus::ESCALATED;
    if (str == "RESOLVED")      return InvestigationStatus::RESOLVED;
    if (str == "CLOSED")        return InvestigationStatus::CLOSED;
    return InvestigationStatus::OPEN;
}

std::string investigationPriorityToString(InvestigationPriority priority) {
    switch (priority) {
        case InvestigationPriority::CRITICAL: return "CRITICAL";
        case InvestigationPriority::HIGH:     return "HIGH";
        case InvestigationPriority::MEDIUM:   return "MEDIUM";
        case InvestigationPriority::LOW:      return "LOW";
        default:                              return "MEDIUM";
    }
}

InvestigationPriority stringToInvestigationPriority(const std::string& str) {
    if (str == "CRITICAL") return InvestigationPriority::CRITICAL;
    if (str == "HIGH")     return InvestigationPriority::HIGH;
    if (str == "LOW")      return InvestigationPriority::LOW;
    return InvestigationPriority::MEDIUM;
}

std::string evidenceTypeToString(EvidenceType type) {
    switch (type) {
        case EvidenceType::FLOW_RECORD:          return "FLOW_RECORD";
        case EvidenceType::SECURITY_INCIDENT:     return "SECURITY_INCIDENT";
        case EvidenceType::BEHAVIORAL_DETECTION: return "BEHAVIORAL_DETECTION";
        case EvidenceType::SIGNATURE_EVENT:      return "SIGNATURE_EVENT";
        case EvidenceType::THREAT_IOC:           return "THREAT_IOC";
        case EvidenceType::PACKET_CAPTURE:       return "PACKET_CAPTURE";
        case EvidenceType::ANALYSIS_ARTIFACT:    return "ANALYSIS_ARTIFACT";
        case EvidenceType::ANALYST_NOTE:         return "ANALYST_NOTE";
        default:                                 return "ANALYSIS_ARTIFACT";
    }
}

EvidenceType stringToEvidenceType(const std::string& str) {
    if (str == "FLOW_RECORD")          return EvidenceType::FLOW_RECORD;
    if (str == "SECURITY_INCIDENT")     return EvidenceType::SECURITY_INCIDENT;
    if (str == "BEHAVIORAL_DETECTION") return EvidenceType::BEHAVIORAL_DETECTION;
    if (str == "SIGNATURE_EVENT")      return EvidenceType::SIGNATURE_EVENT;
    if (str == "THREAT_IOC")           return EvidenceType::THREAT_IOC;
    if (str == "PACKET_CAPTURE")       return EvidenceType::PACKET_CAPTURE;
    if (str == "ANALYST_NOTE")         return EvidenceType::ANALYST_NOTE;
    return EvidenceType::ANALYSIS_ARTIFACT;
}

std::string InvestigationNote::toJson() const {
    std::ostringstream ss;
    ss << "{"
       << "\"note_id\":\"" << note_id << "\","
       << "\"timestamp_us\":" << timestamp_us << ","
       << "\"author\":\"" << author << "\","
       << "\"content\":\"" << content << "\""
       << "}";
    return ss.str();
}

std::string EvidenceReference::toJson() const {
    std::ostringstream ss;
    ss << "{"
       << "\"evidence_id\":\"" << evidence_id << "\","
       << "\"type\":\"" << evidenceTypeToString(type) << "\","
       << "\"source_id\":\"" << source_id << "\","
       << "\"description\":\"" << description << "\","
       << "\"integrity_hash\":\"" << integrity_hash << "\","
       << "\"timestamp_us\":" << timestamp_us
       << "}";
    return ss.str();
}

std::string InvestigationRecord::toJson() const {
    std::ostringstream ss;
    ss << "{\n"
       << "  \"investigation_id\": \"" << investigation_id << "\",\n"
       << "  \"title\": \"" << title << "\",\n"
       << "  \"description\": \"" << description << "\",\n"
       << "  \"created_at_us\": " << created_at_us << ",\n"
       << "  \"updated_at_us\": " << updated_at_us << ",\n"
       << "  \"status\": \"" << investigationStatusToString(status) << "\",\n"
       << "  \"priority\": \"" << investigationPriorityToString(priority) << "\",\n"
       << "  \"tags\": [";
    for (size_t i = 0; i < tags.size(); ++i) {
        if (i > 0) ss << ", ";
        ss << "\"" << tags[i] << "\"";
    }
    ss << "],\n  \"related_incidents\": [";
    for (size_t i = 0; i < related_incidents.size(); ++i) {
        if (i > 0) ss << ", ";
        ss << "\"" << related_incidents[i] << "\"";
    }
    ss << "],\n  \"related_detections\": [";
    for (size_t i = 0; i < related_detections.size(); ++i) {
        if (i > 0) ss << ", ";
        ss << "\"" << related_detections[i] << "\"";
    }
    ss << "],\n  \"related_flows\": [";
    for (size_t i = 0; i < related_flows.size(); ++i) {
        if (i > 0) ss << ", ";
        ss << related_flows[i];
    }
    ss << "],\n  \"related_endpoints\": [";
    for (size_t i = 0; i < related_endpoints.size(); ++i) {
        if (i > 0) ss << ", ";
        ss << "\"" << related_endpoints[i] << "\"";
    }
    ss << "],\n  \"related_iocs\": [";
    for (size_t i = 0; i < related_iocs.size(); ++i) {
        if (i > 0) ss << ", ";
        ss << "\"" << related_iocs[i] << "\"";
    }
    ss << "],\n  \"notes\": [\n";
    for (size_t i = 0; i < notes.size(); ++i) {
        if (i > 0) ss << ",\n";
        ss << "    " << notes[i].toJson();
    }
    ss << "\n  ],\n  \"evidence_list\": [\n";
    for (size_t i = 0; i < evidence_list.size(); ++i) {
        if (i > 0) ss << ",\n";
        ss << "    " << evidence_list[i].toJson();
    }
    ss << "\n  ]\n}";
    return ss.str();
}

std::string InvestigationRecord::toMarkdown() const {
    std::ostringstream ss;
    ss << "# Investigation: " << title << " (" << investigation_id << ")\n\n"
       << "**Status:** " << investigationStatusToString(status) << "  \n"
       << "**Priority:** " << investigationPriorityToString(priority) << "  \n"
       << "**Created:** " << created_at_us << " us  \n"
       << "**Updated:** " << updated_at_us << " us  \n\n"
       << "## Description\n" << description << "\n\n"
       << "## Linked Entities\n"
       << "- **Incidents:** " << related_incidents.size() << "\n"
       << "- **Detections:** " << related_detections.size() << "\n"
       << "- **Flows:** " << related_flows.size() << "\n"
       << "- **Endpoints:** " << related_endpoints.size() << "\n"
       << "- **Threat IOCs:** " << related_iocs.size() << "\n\n"
       << "## Evidence Items (" << evidence_list.size() << ")\n";

    for (const auto& ev : evidence_list) {
        ss << "- `[" << ev.evidence_id << "]` **" << evidenceTypeToString(ev.type) << "** (" << ev.source_id << "): "
           << ev.description << " (Integrity: `" << ev.integrity_hash.substr(0, 12) << "...`)\n";
    }

    ss << "\n## Analyst Notes (" << notes.size() << ")\n";
    for (const auto& n : notes) {
        ss << "### Note by @" << n.author << " (" << n.timestamp_us << " us)\n"
           << n.content << "\n\n";
    }

    return ss.str();
}

} // namespace DPI
