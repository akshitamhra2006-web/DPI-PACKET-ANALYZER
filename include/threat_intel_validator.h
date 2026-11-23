#ifndef DPI_THREAT_INTEL_VALIDATOR_H
#define DPI_THREAT_INTEL_VALIDATOR_H

#include "threat_intel_types.h"
#include <string>
#include <vector>

namespace DPI {

struct ThreatValidationResult {
    bool valid = true;
    std::string error_message;

    static ThreatValidationResult ok() {
        return {true, ""};
    }

    static ThreatValidationResult error(const std::string& msg) {
        return {false, msg};
    }
};

class ThreatIntelValidator {
public:
    static ThreatValidationResult validateDataset(ThreatDataset& dataset);
    static ThreatValidationResult validateIOC(ThreatIOC& ioc);

    // Helpers
    static bool isValidIPv4(const std::string& str, uint32_t& out_ip);
    static bool isValidCIDR(const std::string& str, uint32_t& out_ip, uint8_t& out_prefix, uint32_t& out_mask);
    static bool isValidDomain(const std::string& str, std::string& out_norm_domain, bool& out_is_wildcard);
    static bool isValidURL(const std::string& str, std::string& out_host, std::string& out_path);
    static bool isValidFileHash(const std::string& str, std::string& out_algo);
};

} // namespace DPI

#endif // DPI_THREAT_INTEL_VALIDATOR_H
