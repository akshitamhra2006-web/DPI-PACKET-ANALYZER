#ifndef DPI_SIGNATURE_VALIDATOR_H
#define DPI_SIGNATURE_VALIDATOR_H

#include "signature_types.h"
#include <string>
#include <vector>

namespace DPI {

struct ValidationResult {
    bool valid = true;
    std::string error_message;

    static ValidationResult ok() {
        return {true, ""};
    }

    static ValidationResult error(const std::string& msg) {
        return {false, msg};
    }
};

class SignatureValidator {
public:
    static ValidationResult validateRule(SignatureRule& rule);
    static ValidationResult validateCIDR(const std::string& cidr);
    static ValidationResult validatePortRange(const std::string& range_str);
    static ValidationResult validateHexPattern(const std::string& hex_str);
};

} // namespace DPI

#endif // DPI_SIGNATURE_VALIDATOR_H
