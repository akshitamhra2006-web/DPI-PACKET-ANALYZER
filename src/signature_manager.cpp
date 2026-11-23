#include "signature_manager.h"
#include "signature_parser.h"
#include "signature_validator.h"

namespace DPI {

bool SignatureManager::addRule(const SignatureRule& rule, std::string& err) {
    if (rule.rule_id.empty()) {
        err = "Rule ID cannot be empty";
        return false;
    }
    if (rule_index_.find(rule.rule_id) != rule_index_.end()) {
        err = "Duplicate rule ID rejected: " + rule.rule_id;
        return false;
    }

    SignatureRule validated_rule = rule;
    auto val_res = SignatureValidator::validateRule(validated_rule);
    if (!val_res.valid) {
        err = val_res.error_message;
        return false;
    }

    size_t idx = rules_.size();
    rules_.push_back(std::move(validated_rule));
    rule_index_[rule.rule_id] = idx;

    stats_.total_loaded = rules_.size();
    if (rule.enabled) stats_.active_rules++;
    else stats_.disabled_rules++;

    return true;
}

bool SignatureManager::loadRuleFile(const std::string& filepath, std::vector<std::string>& errors) {
    auto res = SignatureParser::parseFile(filepath);
    for (const auto& err : res.errors) {
        errors.push_back(err);
    }
    bool any_added = false;
    for (const auto& r : res.rules) {
        std::string add_err;
        if (addRule(r, add_err)) {
            any_added = true;
        } else {
            errors.push_back(add_err);
        }
    }
    return any_added;
}

bool SignatureManager::loadRuleDirectory(const std::string& dirpath, std::vector<std::string>& errors) {
    auto res = SignatureParser::parseDirectory(dirpath);
    for (const auto& err : res.errors) {
        errors.push_back(err);
    }
    bool any_added = false;
    for (const auto& r : res.rules) {
        std::string add_err;
        if (addRule(r, add_err)) {
            any_added = true;
        } else {
            errors.push_back(add_err);
        }
    }
    return any_added;
}

bool SignatureManager::enableRule(const std::string& rule_id) {
    auto it = rule_index_.find(rule_id);
    if (it == rule_index_.end()) return false;
    if (!rules_[it->second].enabled) {
        rules_[it->second].enabled = true;
        stats_.active_rules++;
        if (stats_.disabled_rules > 0) stats_.disabled_rules--;
    }
    return true;
}

bool SignatureManager::disableRule(const std::string& rule_id) {
    auto it = rule_index_.find(rule_id);
    if (it == rule_index_.end()) return false;
    if (rules_[it->second].enabled) {
        rules_[it->second].enabled = false;
        if (stats_.active_rules > 0) stats_.active_rules--;
        stats_.disabled_rules++;
    }
    return true;
}

bool SignatureManager::hasRule(const std::string& rule_id) const {
    return rule_index_.find(rule_id) != rule_index_.end();
}

const SignatureRule* SignatureManager::getRule(const std::string& rule_id) const {
    auto it = rule_index_.find(rule_id);
    if (it == rule_index_.end()) return nullptr;
    return &rules_[it->second];
}

size_t SignatureManager::getActiveRuleCount() const {
    size_t count = 0;
    for (const auto& r : rules_) {
        if (r.enabled) count++;
    }
    return count;
}

void SignatureManager::recordEvaluation() {
    stats_.evaluations++;
}

void SignatureManager::recordMatch(const std::string& rule_id, SignatureCategory cat, SignatureSeverity sev) {
    stats_.total_matches++;
    stats_.matches_by_rule[rule_id]++;
    stats_.matches_by_category[signatureCategoryToString(cat)]++;
    stats_.matches_by_severity[signatureSeverityToString(sev)]++;
}

void SignatureManager::resetStats() {
    stats_.evaluations = 0;
    stats_.total_matches = 0;
    stats_.matches_by_rule.clear();
    stats_.matches_by_category.clear();
    stats_.matches_by_severity.clear();
}

void SignatureManager::clear() {
    rules_.clear();
    rule_index_.clear();
    stats_ = SignatureRuleStats{};
}

} // namespace DPI
