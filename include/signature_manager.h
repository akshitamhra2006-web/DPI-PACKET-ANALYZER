#ifndef DPI_SIGNATURE_MANAGER_H
#define DPI_SIGNATURE_MANAGER_H

#include "signature_types.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <map>

namespace DPI {

struct SignatureRuleStats {
    size_t total_loaded = 0;
    size_t active_rules = 0;
    size_t disabled_rules = 0;
    uint64_t evaluations = 0;
    uint64_t total_matches = 0;
    std::map<std::string, uint64_t> matches_by_rule;
    std::map<std::string, uint64_t> matches_by_category;
    std::map<std::string, uint64_t> matches_by_severity;
};

class SignatureManager {
public:
    SignatureManager() = default;
    ~SignatureManager() = default;

    // Add a single validated rule; rejects duplicate rule IDs
    bool addRule(const SignatureRule& rule, std::string& err);

    // Load rules from a file
    bool loadRuleFile(const std::string& filepath, std::vector<std::string>& errors);

    // Load rules from a directory (.json files)
    bool loadRuleDirectory(const std::string& dirpath, std::vector<std::string>& errors);

    // Rule management controls
    bool enableRule(const std::string& rule_id);
    bool disableRule(const std::string& rule_id);
    bool hasRule(const std::string& rule_id) const;
    const SignatureRule* getRule(const std::string& rule_id) const;

    // Accessors
    const std::vector<SignatureRule>& getRules() const { return rules_; }
    size_t getRuleCount() const { return rules_.size(); }
    size_t getActiveRuleCount() const;

    // Telemetry and statistics
    void recordEvaluation();
    void recordMatch(const std::string& rule_id, SignatureCategory cat, SignatureSeverity sev);
    const SignatureRuleStats& getStats() const { return stats_; }
    void resetStats();

    // Clear all rules
    void clear();

private:
    std::vector<SignatureRule> rules_;
    std::unordered_map<std::string, size_t> rule_index_; // rule_id -> index in rules_
    SignatureRuleStats stats_;
};

} // namespace DPI

#endif // DPI_SIGNATURE_MANAGER_H
