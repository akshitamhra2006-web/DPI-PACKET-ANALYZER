#ifndef DPI_THREAT_INTEL_PARSER_H
#define DPI_THREAT_INTEL_PARSER_H

#include "threat_intel_types.h"
#include <string>
#include <vector>

namespace DPI {

class ThreatIntelParser {
public:
    // Parses a single dataset or dataset wrapper from JSON string
    static bool parseDatasetString(const std::string& json_str,
                                   std::vector<ThreatDataset>& out_datasets,
                                   std::vector<std::string>& out_errors);

    // Loads a dataset file (.json)
    static bool loadDatasetFile(const std::string& filepath,
                                std::vector<ThreatDataset>& out_datasets,
                                std::vector<std::string>& out_errors);

    // Loads all .json dataset files from a directory
    static bool loadDatasetDirectory(const std::string& dirpath,
                                     std::vector<ThreatDataset>& out_datasets,
                                     std::vector<std::string>& out_errors);
};

} // namespace DPI

#endif // DPI_THREAT_INTEL_PARSER_H
