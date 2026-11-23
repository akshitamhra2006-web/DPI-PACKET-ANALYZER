#include "signature_validator.h"
#include <cctype>
#include <sstream>

namespace DPI {

ValidationResult SignatureValidator::validateCIDR(const std::string& cidr) {
    if (cidr.empty() || cidr == "any" || cidr == "*") {
        return ValidationResult::ok();
    }
    size_t slash = cidr.find('/');
    std::string ip_part = (slash != std::string::npos) ? cidr.substr(0, slash) : cidr;
    
    // Check IPv4 format: 4 octets separated by dots
    int octets = 0;
    int val = 0;
    bool has_digit = false;
    for (char c : ip_part) {
        if (c == '.') {
            if (!has_digit || val < 0 || val > 255) {
                return ValidationResult::error("Invalid IPv4 octet in CIDR: " + cidr);
            }
            octets++;
            val = 0;
            has_digit = false;
        } else if (std::isdigit(static_cast<unsigned char>(c))) {
            val = val * 10 + (c - '0');
            has_digit = true;
        } else {
            return ValidationResult::error("Invalid character in IPv4 address: " + cidr);
        }
    }
    if (!has_digit || val < 0 || val > 255) {
        return ValidationResult::error("Invalid final IPv4 octet in CIDR: " + cidr);
    }
    octets++;
    if (octets != 4) {
        return ValidationResult::error("IPv4 address must have 4 octets: " + cidr);
    }

    if (slash != std::string::npos) {
        std::string mask_str = cidr.substr(slash + 1);
        try {
            int prefix = std::stoi(mask_str);
            if (prefix < 0 || prefix > 32) {
                return ValidationResult::error("CIDR prefix must be between 0 and 32: " + cidr);
            }
        } catch (...) {
            return ValidationResult::error("Malformed CIDR prefix: " + cidr);
        }
    }
    return ValidationResult::ok();
}

ValidationResult SignatureValidator::validatePortRange(const std::string& range_str) {
    if (range_str.empty() || range_str == "any" || range_str == "*") {
        return ValidationResult::ok();
    }
    size_t dash = range_str.find('-');
    if (dash != std::string::npos) {
        try {
            int p1 = std::stoi(range_str.substr(0, dash));
            int p2 = std::stoi(range_str.substr(dash + 1));
            if (p1 < 1 || p1 > 65535 || p2 < 1 || p2 > 65535) {
                return ValidationResult::error("Port range numbers must be between 1 and 65535: " + range_str);
            }
            if (p1 > p2) {
                return ValidationResult::error("Port range min must be <= max: " + range_str);
            }
        } catch (...) {
            return ValidationResult::error("Malformed port range: " + range_str);
        }
    } else {
        try {
            int p = std::stoi(range_str);
            if (p < 1 || p > 65535) {
                return ValidationResult::error("Port must be between 1 and 65535: " + range_str);
            }
        } catch (...) {
            return ValidationResult::error("Malformed port number: " + range_str);
        }
    }
    return ValidationResult::ok();
}

ValidationResult SignatureValidator::validateHexPattern(const std::string& hex_str) {
    std::string s = hex_str;
    if (s.rfind("hex:", 0) == 0) s = s.substr(4);
    if (!s.empty() && s.front() == '|' && s.back() == '|') {
        s = s.substr(1, s.size() - 2);
    }
    std::string digits;
    for (char c : s) {
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            digits += c;
        } else if (!std::isspace(static_cast<unsigned char>(c))) {
            return ValidationResult::error("Non-hexadecimal character in pattern: '" + std::string(1, c) + "'");
        }
    }
    if (digits.empty()) {
        return ValidationResult::error("Hex pattern cannot be empty");
    }
    if (digits.size() % 2 != 0) {
        return ValidationResult::error("Hex pattern length must be even (full bytes)");
    }
    return ValidationResult::ok();
}

ValidationResult SignatureValidator::validateRule(SignatureRule& rule) {
    if (rule.rule_id.empty()) {
        return ValidationResult::error("Rule ID cannot be empty");
    }
    for (char c : rule.rule_id) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_' && c != '.') {
            return ValidationResult::error("Rule ID contains invalid character: '" + std::string(1, c) + "'");
        }
    }
    if (rule.name.empty()) {
        return ValidationResult::error("Rule name cannot be empty for rule " + rule.rule_id);
    }

    if (!rule.hasCriteria()) {
        return ValidationResult::error("Rule " + rule.rule_id + " has no criteria blocks defined");
    }

    // Validate network criteria
    for (const auto& ip : rule.network.src_ips) {
        if (ip.prefix_len > 32) {
            return ValidationResult::error("Source IP prefix length > 32 in rule " + rule.rule_id);
        }
    }
    for (const auto& ip : rule.network.dst_ips) {
        if (ip.prefix_len > 32) {
            return ValidationResult::error("Destination IP prefix length > 32 in rule " + rule.rule_id);
        }
    }
    for (const auto& pr : rule.network.src_ports) {
        if (pr.min_port < 1 || pr.max_port > 65535 || pr.min_port > pr.max_port) {
            return ValidationResult::error("Invalid source port range in rule " + rule.rule_id);
        }
    }
    for (const auto& pr : rule.network.dst_ports) {
        if (pr.min_port < 1 || pr.max_port > 65535 || pr.min_port > pr.max_port) {
            return ValidationResult::error("Invalid destination port range in rule " + rule.rule_id);
        }
    }
    if (rule.network.packet_size_max > 0 && rule.network.packet_size_min > rule.network.packet_size_max) {
        return ValidationResult::error("packet_size_min > packet_size_max in rule " + rule.rule_id);
    }

    // Validate flow criteria
    if (rule.flow.max_bytes > 0 && rule.flow.min_bytes > rule.flow.max_bytes) {
        return ValidationResult::error("min_bytes > max_bytes in rule " + rule.rule_id);
    }
    if (rule.flow.max_packets > 0 && rule.flow.min_packets > rule.flow.max_packets) {
        return ValidationResult::error("min_packets > max_packets in rule " + rule.rule_id);
    }
    if (rule.flow.max_duration_sec > 0.0 && rule.flow.min_duration_sec > rule.flow.max_duration_sec) {
        return ValidationResult::error("min_duration_sec > max_duration_sec in rule " + rule.rule_id);
    }

    // Validate stream content criteria
    for (size_t i = 0; i < rule.stream_content.patterns.size(); ++i) {
        auto& p = rule.stream_content.patterns[i];
        if (p.pattern.empty()) {
            return ValidationResult::error("Empty pattern in stream_content condition #" + std::to_string(i) + " in rule " + rule.rule_id);
        }
        if (p.is_hex) {
            auto hex_res = validateHexPattern(p.pattern);
            if (!hex_res.valid) {
                return ValidationResult::error("Hex pattern error in rule " + rule.rule_id + ": " + hex_res.error_message);
            }
            if (!p.decodeHex()) {
                return ValidationResult::error("Failed to decode hex pattern in rule " + rule.rule_id);
            }
        } else {
            p.bytes.assign(p.pattern.begin(), p.pattern.end());
        }
        if (p.offset < -1) {
            return ValidationResult::error("Offset cannot be < -1 in rule " + rule.rule_id);
        }
        if (p.depth < 0) {
            return ValidationResult::error("Depth cannot be < 0 in rule " + rule.rule_id);
        }
        if (i == 0 && (p.relative_distance >= 0 || p.relative_within > 0)) {
            return ValidationResult::error("Initial pattern cannot have relative distance or within in rule " + rule.rule_id);
        }
        if (p.relative_distance < -1) {
            return ValidationResult::error("Relative distance cannot be < -1 in rule " + rule.rule_id);
        }
        if (p.relative_within < 0) {
            return ValidationResult::error("Relative within cannot be < 0 in rule " + rule.rule_id);
        }
    }

    return ValidationResult::ok();
}

} // namespace DPI
