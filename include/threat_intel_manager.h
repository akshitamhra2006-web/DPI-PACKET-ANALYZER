#ifndef DPI_THREAT_INTEL_MANAGER_H
#define DPI_THREAT_INTEL_MANAGER_H

#include "threat_intel_types.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <memory>

namespace DPI {

class ThreatIntelManager {
public:
    ThreatIntelManager() = default;
    ~ThreatIntelManager() = default;

    // Dataset Management
    bool addDataset(const ThreatDataset& dataset, std::string& err);
    bool loadDatasetFile(const std::string& filepath, std::vector<std::string>& errors);
    bool loadDatasetDirectory(const std::string& dirpath, std::vector<std::string>& errors);
    bool setDatasetEnabled(const std::string& dataset_id, bool enabled);

    const std::vector<ThreatDataset>& getDatasets() const { return datasets_; }
    const ThreatDataset* getDataset(const std::string& dataset_id) const;

    // Fast Lookups
    std::vector<const ThreatIOC*> matchIPv4(uint32_t ip, uint64_t current_time_us = 0, bool allow_expired = false) const;
    std::vector<const ThreatIOC*> matchDomain(const std::string& domain, uint64_t current_time_us = 0, bool allow_expired = false) const;
    std::vector<const ThreatIOC*> matchURL(const std::string& host, const std::string& uri, uint64_t current_time_us = 0, bool allow_expired = false) const;

    // Telemetry & Statistics
    size_t totalDatasets() const { return datasets_.size(); }
    size_t activeDatasets() const;
    size_t totalIOCs() const;
    size_t activeIOCs() const;
    size_t expiredIOCs(uint64_t current_time_us = 0) const;
    std::map<IOCType, size_t> iocCountsByType() const;
    std::map<IOCSeverity, size_t> iocCountsBySeverity() const;

    void rebuildIndexes();

private:
    std::vector<ThreatDataset> datasets_;
    std::unordered_map<std::string, size_t> dataset_index_by_id_;

    // Lookup indexes
    std::unordered_map<uint32_t, std::vector<const ThreatIOC*>> exact_ipv4_index_;
    std::vector<const ThreatIOC*> cidr_ipv4_index_;
    std::unordered_map<std::string, std::vector<const ThreatIOC*>> domain_index_;
    std::unordered_map<std::string, std::vector<const ThreatIOC*>> url_index_by_host_;

    void indexIOC(const ThreatIOC& ioc);
};

} // namespace DPI

#endif // DPI_THREAT_INTEL_MANAGER_H
