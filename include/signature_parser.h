#ifndef DPI_SIGNATURE_PARSER_H
#define DPI_SIGNATURE_PARSER_H

#include "signature_types.h"
#include <string>
#include <vector>

namespace DPI {

struct ParseResult {
    bool success = true;
    std::vector<SignatureRule> rules;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
};

class SignatureParser {
public:
    // Parse rules from a JSON string
    static ParseResult parseString(const std::string& json_str);

    // Parse rules from a single file
    static ParseResult parseFile(const std::string& filepath);

    // Parse rules from all .json files in a directory
    static ParseResult parseDirectory(const std::string& dirpath);
};

} // namespace DPI

#endif // DPI_SIGNATURE_PARSER_H
