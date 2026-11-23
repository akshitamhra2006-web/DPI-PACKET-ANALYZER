#ifndef DPI_INVESTIGATION_MANAGER_H
#define DPI_INVESTIGATION_MANAGER_H

#include "investigation_types.h"
#include <unordered_map>
#include <mutex>
#include <memory>

namespace DPI {

class InvestigationManager {
public:
    InvestigationManager() = default;

    // Create a new investigation
    std::string createInvestigation(const std::string& title,
                                    const std::string& description,
                                    InvestigationPriority priority = InvestigationPriority::MEDIUM,
                                    const std::vector<std::string>& tags = {});

    // Update existing investigation metadata
    bool updateInvestigation(const std::string& id,
                             const std::string& title,
                             const std::string& description,
                             InvestigationStatus status,
                             InvestigationPriority priority,
                             const std::vector<std::string>& tags);

    // Add note to investigation
    bool addNote(const std::string& inv_id,
                 const std::string& author,
                 const std::string& content);

    // Add evidence with integrity verification
    std::string addEvidence(const std::string& inv_id,
                            EvidenceType type,
                            const std::string& source_id,
                            const std::string& description,
                            const std::string& raw_content_for_hash);

    // Remove evidence safely
    bool removeEvidence(const std::string& inv_id, const std::string& evidence_id);

    // Link associations
    bool linkIncident(const std::string& inv_id, const std::string& incident_id);
    bool linkDetection(const std::string& inv_id, const std::string& detection_id);
    bool linkFlow(const std::string& inv_id, uint64_t flow_id);
    bool linkEndpoint(const std::string& inv_id, const std::string& ip);
    bool linkIOC(const std::string& inv_id, const std::string& ioc_id);

    // Status transitions
    bool setStatus(const std::string& inv_id, InvestigationStatus status);

    // Queries
    const InvestigationRecord* getInvestigation(const std::string& id) const;
    InvestigationRecord* getInvestigationMutable(const std::string& id);
    std::vector<InvestigationRecord> getAllInvestigations() const;
    size_t getInvestigationCount() const;

    // Persistence & Export
    bool saveToFile(const std::string& filepath) const;
    bool loadFromFile(const std::string& filepath);
    std::string toJson() const;

    // Hash utility for integrity checks
    static std::string calculateHash(const std::string& content);

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, InvestigationRecord> investigations_;
    uint32_t next_inv_id_ = 1;
    uint32_t next_note_id_ = 1;
    uint32_t next_evidence_id_ = 1;
};

} // namespace DPI

#endif // DPI_INVESTIGATION_MANAGER_H
