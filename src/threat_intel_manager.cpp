#include "threat_intel_manager.h"
#include "threat_intel_parser.h"
#include <algorithm>
#include <cctype>

namespace DPI {

static inline std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

static inline std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

bool ThreatIntelManager::addDataset(const ThreatDataset& dataset, std::string& err) {
    if (dataset.dataset_id.empty()) {
        err = "Dataset ID cannot be empty";
        return false;
    }
    if (dataset_index_by_id_.find(dataset.dataset_id) != dataset_index_by_id_.end()) {
        err = "Duplicate dataset ID: '" + dataset.dataset_id + "'";
        return false;
    }

    size_t idx = datasets_.size();
    datasets_.push_back(dataset);
    dataset_index_by_id_[dataset.dataset_id] = idx;
    rebuildIndexes();
    return true;
}

bool ThreatIntelManager::loadDatasetFile(const std::string& filepath, std::vector<std::string>& errors) {
    std::vector<ThreatDataset> parsed;
    if (!ThreatIntelParser::loadDatasetFile(filepath, parsed, errors)) {
        return false;
    }

    bool all_ok = true;
    for (const auto& ds : parsed) {
        std::string err;
        if (!addDataset(ds, err)) {
            errors.push_back("Failed to add dataset " + ds.dataset_id + ": " + err);
            all_ok = false;
        }
    }
    return all_ok;
}

bool ThreatIntelManager::loadDatasetDirectory(const std::string& dirpath, std::vector<std::string>& errors) {
    std::vector<ThreatDataset> parsed;
    if (!ThreatIntelParser::loadDatasetDirectory(dirpath, parsed, errors)) {
        return false;
    }

    bool all_ok = true;
    for (const auto& ds : parsed) {
        std::string err;
        if (!addDataset(ds, err)) {
            errors.push_back("Failed to add dataset " + ds.dataset_id + ": " + err);
            all_ok = false;
        }
    }
    return all_ok;
}

bool ThreatIntelManager::setDatasetEnabled(const std::string& dataset_id, bool enabled) {
    auto it = dataset_index_by_id_.find(dataset_id);
    if (it == dataset_index_by_id_.end()) return false;
    datasets_[it->second].enabled = enabled;
    rebuildIndexes();
    return true;
}

const ThreatDataset* ThreatIntelManager::getDataset(const std::string& dataset_id) const {
    auto it = dataset_index_by_id_.find(dataset_id);
    if (it == dataset_index_by_id_.end()) return nullptr;
    return &datasets_[it->second];
}

void ThreatIntelManager::rebuildIndexes() {
    exact_ipv4_index_.clear();
    cidr_ipv4_index_.clear();
    domain_index_.clear();
    url_index_by_host_.clear();

    for (const auto& ds : datasets_) {
        if (!ds.enabled) continue;
        for (const auto& ioc : ds.iocs) {
            if (!ioc.enabled) continue;
            switch (ioc.type) {
                case IOCType::IPV4:
                    exact_ipv4_index_[ioc.parsed_ip].push_back(&ioc);
                    break;
                case IOCType::IPV4_CIDR:
                    cidr_ipv4_index_.push_back(&ioc);
                    break;
                case IOCType::DOMAIN_NAME:
                case IOCType::DNS_NAME:
                case IOCType::TLS_SNI:
                    domain_index_[ioc.normalized_domain].push_back(&ioc);
                    break;
                case IOCType::URL:
                    if (!ioc.url_host.empty()) {
                        url_index_by_host_[ioc.url_host].push_back(&ioc);
                    } else {
                        url_index_by_host_["*"].push_back(&ioc);
                    }
                    break;
                case IOCType::FILE_HASH:
                case IOCType::UNKNOWN:
                default:
                    break;
            }
        }
    }

    // Sort CIDRs by prefix length descending for longest-prefix match precedence
    std::sort(cidr_ipv4_index_.begin(), cidr_ipv4_index_.end(),
              [](const ThreatIOC* a, const ThreatIOC* b) {
                  return a->prefix_len > b->prefix_len;
              });
}

std::vector<const ThreatIOC*> ThreatIntelManager::matchIPv4(uint32_t ip, uint64_t current_time_us, bool allow_expired) const {
    std::vector<const ThreatIOC*> res;

    // 1. Exact match
    auto it = exact_ipv4_index_.find(ip);
    if (it != exact_ipv4_index_.end()) {
        for (const auto* ioc : it->second) {
            if (!allow_expired && ioc->isExpired(current_time_us)) continue;
            res.push_back(ioc);
        }
    }

    // 2. CIDR matches
    for (const auto* ioc : cidr_ipv4_index_) {
        if (!allow_expired && ioc->isExpired(current_time_us)) continue;
        if (ioc->matchesIPv4(ip)) {
            res.push_back(ioc);
        }
    }

    return res;
}

std::vector<const ThreatIOC*> ThreatIntelManager::matchDomain(const std::string& domain, uint64_t current_time_us, bool allow_expired) const {
    std::vector<const ThreatIOC*> res;
    std::string cand = toLower(trim(domain));
    if (!cand.empty() && cand.back() == '.') cand.pop_back();
    if (cand.empty()) return res;

    // 1. Exact match
    auto it = domain_index_.find(cand);
    if (it != domain_index_.end()) {
        for (const auto* ioc : it->second) {
            if (!allow_expired && ioc->isExpired(current_time_us)) continue;
            res.push_back(ioc);
        }
    }

    // 2. Subdomain boundary matches (iteratively strip leftmost label)
    size_t dot_pos = cand.find('.');
    while (dot_pos != std::string::npos) {
        std::string parent = cand.substr(dot_pos + 1);
        if (parent.empty()) break;
        auto pit = domain_index_.find(parent);
        if (pit != domain_index_.end()) {
            for (const auto* ioc : pit->second) {
                if (!allow_expired && ioc->isExpired(current_time_us)) continue;
                if (std::find(res.begin(), res.end(), ioc) == res.end()) {
                    res.push_back(ioc);
                }
            }
        }
        dot_pos = cand.find('.', dot_pos + 1);
    }

    return res;
}

std::vector<const ThreatIOC*> ThreatIntelManager::matchURL(const std::string& host, const std::string& uri, uint64_t current_time_us, bool allow_expired) const {
    std::vector<const ThreatIOC*> res;
    std::string h = toLower(trim(host));
    if (!h.empty() && h.back() == '.') h.pop_back();
    std::string u = trim(uri);

    auto checkHost = [&](const std::string& query_host) {
        auto it = url_index_by_host_.find(query_host);
        if (it != url_index_by_host_.end()) {
            for (const auto* ioc : it->second) {
                if (!allow_expired && ioc->isExpired(current_time_us)) continue;
                if (ioc->matchesURL(h, u)) {
                    if (std::find(res.begin(), res.end(), ioc) == res.end()) {
                        res.push_back(ioc);
                    }
                }
            }
        }
    };

    checkHost(h);

    size_t dot_pos = h.find('.');
    while (dot_pos != std::string::npos) {
        std::string parent = h.substr(dot_pos + 1);
        if (parent.empty()) break;
        checkHost(parent);
        dot_pos = h.find('.', dot_pos + 1);
    }

    checkHost("*");
    return res;
}

size_t ThreatIntelManager::activeDatasets() const {
    size_t c = 0;
    for (const auto& ds : datasets_) {
        if (ds.enabled) c++;
    }
    return c;
}

size_t ThreatIntelManager::totalIOCs() const {
    size_t c = 0;
    for (const auto& ds : datasets_) {
        c += ds.iocs.size();
    }
    return c;
}

size_t ThreatIntelManager::activeIOCs() const {
    size_t c = 0;
    for (const auto& ds : datasets_) {
        if (!ds.enabled) continue;
        for (const auto& ioc : ds.iocs) {
            if (ioc.enabled) c++;
        }
    }
    return c;
}

size_t ThreatIntelManager::expiredIOCs(uint64_t current_time_us) const {
    size_t c = 0;
    for (const auto& ds : datasets_) {
        for (const auto& ioc : ds.iocs) {
            if (ioc.isExpired(current_time_us)) c++;
        }
    }
    return c;
}

std::map<IOCType, size_t> ThreatIntelManager::iocCountsByType() const {
    std::map<IOCType, size_t> counts;
    for (const auto& ds : datasets_) {
        for (const auto& ioc : ds.iocs) {
            counts[ioc.type]++;
        }
    }
    return counts;
}

std::map<IOCSeverity, size_t> ThreatIntelManager::iocCountsBySeverity() const {
    std::map<IOCSeverity, size_t> counts;
    for (const auto& ds : datasets_) {
        for (const auto& ioc : ds.iocs) {
            counts[ioc.severity]++;
        }
    }
    return counts;
}

} // namespace DPI
