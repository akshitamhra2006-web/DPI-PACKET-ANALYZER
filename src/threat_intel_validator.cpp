#include "threat_intel_validator.h"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <set>

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

bool ThreatIntelValidator::isValidIPv4(const std::string& str, uint32_t& out_ip) {
    std::string s = trim(str);
    if (s.empty()) return false;

    std::vector<std::string> octets;
    std::string cur;
    for (char c : s) {
        if (c == '.') {
            octets.push_back(cur);
            cur.clear();
        } else if (std::isdigit(static_cast<unsigned char>(c))) {
            cur += c;
        } else {
            return false;
        }
    }
    octets.push_back(cur);

    if (octets.size() != 4) return false;

    uint32_t ip = 0;
    int shift = 0;
    for (const auto& oct : octets) {
        if (oct.empty() || oct.size() > 3) return false;
        int val = std::stoi(oct);
        if (val < 0 || val > 255) return false;
        if (oct.size() > 1 && oct[0] == '0') {
            // Disallow leading zeros in octets for canonical safety
            return false;
        }
        ip |= (static_cast<uint32_t>(val) << shift);
        shift += 8;
    }

    out_ip = ip;
    return true;
}

bool ThreatIntelValidator::isValidCIDR(const std::string& str, uint32_t& out_ip, uint8_t& out_prefix, uint32_t& out_mask) {
    std::string s = trim(str);
    size_t slash = s.find('/');
    if (slash == std::string::npos) {
        // Allow standalone IP as /32 CIDR
        if (!isValidIPv4(s, out_ip)) return false;
        out_prefix = 32;
        out_mask = 0xFFFFFFFFU;
        return true;
    }

    std::string ip_part = s.substr(0, slash);
    std::string prefix_part = s.substr(slash + 1);

    if (!isValidIPv4(ip_part, out_ip)) return false;
    if (prefix_part.empty() || prefix_part.size() > 2) return false;

    for (char c : prefix_part) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }

    int p = std::stoi(prefix_part);
    if (p < 0 || p > 32) return false;

    out_prefix = static_cast<uint8_t>(p);
    out_mask = (out_prefix == 32) ? 0xFFFFFFFFU : (out_prefix == 0 ? 0U : (~0U << (32 - out_prefix)));
    return true;
}

bool ThreatIntelValidator::isValidDomain(const std::string& str, std::string& out_norm_domain, bool& out_is_wildcard) {
    std::string s = toLower(trim(str));
    out_is_wildcard = false;

    if (s.empty() || s.size() > 253) return false;

    if (s.size() > 2 && s[0] == '*' && s[1] == '.') {
        out_is_wildcard = true;
        s = s.substr(2);
    }

    if (!s.empty() && s.back() == '.') {
        s.pop_back();
    }
    if (s.empty()) return false;

    // Check each label
    std::vector<std::string> labels;
    std::string cur;
    for (char c : s) {
        if (c == '.') {
            if (cur.empty()) return false; // Double dot
            labels.push_back(cur);
            cur.clear();
        } else if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_') {
            cur += c;
        } else {
            return false;
        }
    }
    if (cur.empty()) return false;
    labels.push_back(cur);

    for (const auto& label : labels) {
        if (label.empty() || label.size() > 63) return false;
        if (label.front() == '-' || label.back() == '-') return false;
    }

    out_norm_domain = s;
    return true;
}

bool ThreatIntelValidator::isValidURL(const std::string& str, std::string& out_host, std::string& out_path) {
    std::string s = trim(str);
    if (s.empty()) return false;

    // Strip scheme if present
    if (s.compare(0, 7, "http://") == 0) {
        s = s.substr(7);
    } else if (s.compare(0, 8, "https://") == 0) {
        s = s.substr(8);
    }

    size_t slash = s.find('/');
    std::string host_part;
    std::string path_part = "/";

    if (slash != std::string::npos) {
        host_part = s.substr(0, slash);
        path_part = s.substr(slash);
    } else {
        host_part = s;
    }

    // Strip port if present
    size_t colon = host_part.find(':');
    if (colon != std::string::npos) {
        host_part = host_part.substr(0, colon);
    }

    std::string norm_host;
    bool wildcard = false;
    uint32_t dummy_ip = 0;
    if (!isValidDomain(host_part, norm_host, wildcard) && !isValidIPv4(host_part, dummy_ip)) {
        return false;
    }

    out_host = norm_host.empty() ? host_part : norm_host;
    out_path = path_part.empty() ? "/" : path_part;
    return true;
}

bool ThreatIntelValidator::isValidFileHash(const std::string& str, std::string& out_algo) {
    std::string s = toLower(trim(str));
    if (s.empty()) return false;

    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }

    if (s.size() == 32) {
        out_algo = "MD5";
        return true;
    } else if (s.size() == 40) {
        out_algo = "SHA1";
        return true;
    } else if (s.size() == 64) {
        out_algo = "SHA256";
        return true;
    }
    return false;
}

ThreatValidationResult ThreatIntelValidator::validateIOC(ThreatIOC& ioc) {
    if (ioc.ioc_id.empty()) {
        return ThreatValidationResult::error("IOC ID cannot be empty");
    }
    for (char c : ioc.ioc_id) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_' && c != '.') {
            return ThreatValidationResult::error("IOC ID contains invalid character: '" + std::string(1, c) + "'");
        }
    }

    if (ioc.value.empty()) {
        return ThreatValidationResult::error("IOC value cannot be empty for IOC " + ioc.ioc_id);
    }

    ioc.raw_value = ioc.value;

    switch (ioc.type) {
        case IOCType::IPV4: {
            uint32_t ip = 0;
            if (!isValidIPv4(ioc.value, ip)) {
                return ThreatValidationResult::error("Invalid IPv4 address '" + ioc.value + "' in IOC " + ioc.ioc_id);
            }
            ioc.parsed_ip = ip;
            break;
        }
        case IOCType::IPV4_CIDR: {
            uint32_t ip = 0;
            uint8_t prefix = 32;
            uint32_t mask = 0xFFFFFFFFU;
            if (!isValidCIDR(ioc.value, ip, prefix, mask)) {
                return ThreatValidationResult::error("Invalid IPv4 CIDR '" + ioc.value + "' in IOC " + ioc.ioc_id);
            }
            ioc.parsed_ip = ip;
            ioc.prefix_len = prefix;
            ioc.net_mask = mask;
            break;
        }
        case IOCType::DOMAIN_NAME:
        case IOCType::DNS_NAME:
        case IOCType::TLS_SNI: {
            std::string norm;
            bool wildcard = false;
            if (!isValidDomain(ioc.value, norm, wildcard)) {
                return ThreatValidationResult::error("Invalid domain name '" + ioc.value + "' in IOC " + ioc.ioc_id);
            }
            ioc.normalized_domain = norm;
            ioc.is_wildcard_domain = wildcard;
            ioc.value = norm;
            break;
        }
        case IOCType::URL: {
            std::string host, path;
            if (!isValidURL(ioc.value, host, path)) {
                return ThreatValidationResult::error("Invalid URL '" + ioc.value + "' in IOC " + ioc.ioc_id);
            }
            ioc.url_host = host;
            ioc.url_path = path;
            break;
        }
        case IOCType::FILE_HASH: {
            std::string algo;
            if (!isValidFileHash(ioc.value, algo)) {
                return ThreatValidationResult::error("Invalid file hash '" + ioc.value + "' in IOC " + ioc.ioc_id);
            }
            ioc.analyst_notes += (ioc.analyst_notes.empty() ? "" : "; ") + std::string("Algo: ") + algo +
                                 " [Note: Packet analyzer operates on offline streams; packet fragments are not hashed]";
            break;
        }
        case IOCType::UNKNOWN:
        default:
            return ThreatValidationResult::error("Unknown or unsupported IOC type for IOC " + ioc.ioc_id);
    }

    return ThreatValidationResult::ok();
}

ThreatValidationResult ThreatIntelValidator::validateDataset(ThreatDataset& dataset) {
    if (dataset.dataset_id.empty()) {
        return ThreatValidationResult::error("Dataset ID cannot be empty");
    }
    for (char c : dataset.dataset_id) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_' && c != '.') {
            return ThreatValidationResult::error("Dataset ID contains invalid character: '" + std::string(1, c) + "'");
        }
    }

    if (dataset.name.empty()) {
        return ThreatValidationResult::error("Dataset name cannot be empty for dataset " + dataset.dataset_id);
    }

    std::set<std::string> seen_ioc_ids;
    for (auto& ioc : dataset.iocs) {
        ioc.dataset_id = dataset.dataset_id;
        if (seen_ioc_ids.count(ioc.ioc_id)) {
            return ThreatValidationResult::error("Duplicate IOC ID '" + ioc.ioc_id + "' in dataset " + dataset.dataset_id);
        }
        seen_ioc_ids.insert(ioc.ioc_id);

        auto res = validateIOC(ioc);
        if (!res.valid) {
            return res;
        }
    }

    return ThreatValidationResult::ok();
}

} // namespace DPI
