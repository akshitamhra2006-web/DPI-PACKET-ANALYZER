#include "threat_intel_parser.h"
#include "threat_intel_validator.h"
#include <fstream>
#include <sstream>
#include <cctype>
#include <stdexcept>
#include <iostream>
#include <dirent.h>
#include <sys/stat.h>
#include <algorithm>

namespace DPI {

// ============================================================================
// Lightweight In-Memory JSON AST
// ============================================================================

enum class JSONType {
    NULL_TYPE,
    BOOL,
    NUMBER,
    STRING,
    ARRAY,
    OBJECT
};

struct JSONVal {
    JSONType type = JSONType::NULL_TYPE;
    bool bool_val = false;
    double num_val = 0.0;
    std::string str_val;
    std::vector<JSONVal> arr_val;
    std::map<std::string, JSONVal> obj_val;

    bool asBool(bool def = false) const {
        return (type == JSONType::BOOL) ? bool_val : def;
    }

    double asNumber(double def = 0.0) const {
        return (type == JSONType::NUMBER) ? num_val : def;
    }

    int64_t asInt(int64_t def = 0) const {
        return (type == JSONType::NUMBER) ? static_cast<int64_t>(num_val) : def;
    }

    std::string asString(const std::string& def = "") const {
        return (type == JSONType::STRING) ? str_val : def;
    }

    const std::vector<JSONVal>& asArray() const {
        static const std::vector<JSONVal> empty_arr;
        return (type == JSONType::ARRAY) ? arr_val : empty_arr;
    }

    const std::map<std::string, JSONVal>& asObject() const {
        static const std::map<std::string, JSONVal> empty_obj;
        return (type == JSONType::OBJECT) ? obj_val : empty_obj;
    }

    bool hasKey(const std::string& k) const {
        return type == JSONType::OBJECT && obj_val.find(k) != obj_val.end();
    }

    const JSONVal& get(const std::string& k) const {
        static const JSONVal null_val{};
        if (type == JSONType::OBJECT) {
            auto it = obj_val.find(k);
            if (it != obj_val.end()) return it->second;
        }
        return null_val;
    }
};

class MiniJSONParser {
public:
    static JSONVal parse(const std::string& text) {
        size_t pos = 0;
        skipWhitespace(text, pos);
        if (pos >= text.size()) {
            throw std::runtime_error("Empty JSON input");
        }
        JSONVal val = parseValue(text, pos);
        skipWhitespace(text, pos);
        if (pos < text.size()) {
            throw std::runtime_error("Unexpected trailing characters in JSON at pos " + std::to_string(pos));
        }
        return val;
    }

private:
    static void skipWhitespace(const std::string& text, size_t& pos) {
        while (pos < text.size()) {
            char c = text[pos];
            if (std::isspace(static_cast<unsigned char>(c))) {
                pos++;
            } else if (c == '/' && pos + 1 < text.size() && text[pos + 1] == '/') {
                pos += 2;
                while (pos < text.size() && text[pos] != '\n') pos++;
            } else {
                break;
            }
        }
    }

    static JSONVal parseValue(const std::string& text, size_t& pos) {
        skipWhitespace(text, pos);
        if (pos >= text.size()) throw std::runtime_error("Unexpected EOF parsing value");

        char c = text[pos];
        if (c == '{') return parseObject(text, pos);
        if (c == '[') return parseArray(text, pos);
        if (c == '"') return parseString(text, pos);
        if (c == 't' || c == 'f') return parseBool(text, pos);
        if (c == 'n') return parseNull(text, pos);
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) return parseNumber(text, pos);

        throw std::runtime_error("Invalid JSON character '" + std::string(1, c) + "' at pos " + std::to_string(pos));
    }

    static JSONVal parseObject(const std::string& text, size_t& pos) {
        pos++; // skip '{'
        JSONVal val;
        val.type = JSONType::OBJECT;
        skipWhitespace(text, pos);
        if (pos < text.size() && text[pos] == '}') {
            pos++;
            return val;
        }

        while (pos < text.size()) {
            skipWhitespace(text, pos);
            if (pos >= text.size() || text[pos] != '"') {
                throw std::runtime_error("Expected string key in object at pos " + std::to_string(pos));
            }
            std::string key = parseRawString(text, pos);
            skipWhitespace(text, pos);
            if (pos >= text.size() || text[pos] != ':') {
                throw std::runtime_error("Expected ':' after key '" + key + "' at pos " + std::to_string(pos));
            }
            pos++; // skip ':'
            JSONVal v = parseValue(text, pos);
            val.obj_val[key] = v;

            skipWhitespace(text, pos);
            if (pos < text.size() && text[pos] == ',') {
                pos++;
                continue;
            } else if (pos < text.size() && text[pos] == '}') {
                pos++;
                break;
            } else {
                throw std::runtime_error("Expected ',' or '}' in object at pos " + std::to_string(pos));
            }
        }
        return val;
    }

    static JSONVal parseArray(const std::string& text, size_t& pos) {
        pos++; // skip '['
        JSONVal val;
        val.type = JSONType::ARRAY;
        skipWhitespace(text, pos);
        if (pos < text.size() && text[pos] == ']') {
            pos++;
            return val;
        }

        while (pos < text.size()) {
            JSONVal item = parseValue(text, pos);
            val.arr_val.push_back(item);

            skipWhitespace(text, pos);
            if (pos < text.size() && text[pos] == ',') {
                pos++;
                continue;
            } else if (pos < text.size() && text[pos] == ']') {
                pos++;
                break;
            } else {
                throw std::runtime_error("Expected ',' or ']' in array at pos " + std::to_string(pos));
            }
        }
        return val;
    }

    static std::string parseRawString(const std::string& text, size_t& pos) {
        pos++; // skip '"'
        std::string s;
        while (pos < text.size()) {
            char c = text[pos++];
            if (c == '"') return s;
            if (c == '\\') {
                if (pos >= text.size()) throw std::runtime_error("Unexpected EOF after escape");
                char esc = text[pos++];
                if (esc == '"') s += '"';
                else if (esc == '\\') s += '\\';
                else if (esc == '/') s += '/';
                else if (esc == 'b') s += '\b';
                else if (esc == 'f') s += '\f';
                else if (esc == 'n') s += '\n';
                else if (esc == 'r') s += '\r';
                else if (esc == 't') s += '\t';
                else if (esc == 'u') {
                    if (pos + 4 > text.size()) throw std::runtime_error("Incomplete unicode escape");
                    pos += 4;
                    s += '?';
                } else s += esc;
            } else {
                s += c;
            }
        }
        throw std::runtime_error("Unterminated string");
    }

    static JSONVal parseString(const std::string& text, size_t& pos) {
        JSONVal val;
        val.type = JSONType::STRING;
        val.str_val = parseRawString(text, pos);
        return val;
    }

    static JSONVal parseBool(const std::string& text, size_t& pos) {
        JSONVal val;
        val.type = JSONType::BOOL;
        if (text.compare(pos, 4, "true") == 0) {
            val.bool_val = true;
            pos += 4;
            return val;
        } else if (text.compare(pos, 5, "false") == 0) {
            val.bool_val = false;
            pos += 5;
            return val;
        }
        throw std::runtime_error("Invalid boolean at pos " + std::to_string(pos));
    }

    static JSONVal parseNull(const std::string& text, size_t& pos) {
        if (text.compare(pos, 4, "null") == 0) {
            pos += 4;
            JSONVal val;
            val.type = JSONType::NULL_TYPE;
            return val;
        }
        throw std::runtime_error("Invalid null at pos " + std::to_string(pos));
    }

    static JSONVal parseNumber(const std::string& text, size_t& pos) {
        size_t start = pos;
        if (text[pos] == '-') pos++;
        while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) pos++;
        if (pos < text.size() && text[pos] == '.') {
            pos++;
            while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) pos++;
        }
        if (pos < text.size() && (text[pos] == 'e' || text[pos] == 'E')) {
            pos++;
            if (pos < text.size() && (text[pos] == '+' || text[pos] == '-')) pos++;
            while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) pos++;
        }
        std::string num_str = text.substr(start, pos - start);
        JSONVal val;
        val.type = JSONType::NUMBER;
        try {
            val.num_val = std::stod(num_str);
        } catch (...) {
            val.num_val = 0.0;
        }
        return val;
    }
};

// ============================================================================
// Threat Dataset Deserializer
// ============================================================================

static bool parseIOCFromJSON(const JSONVal& obj, ThreatIOC& ioc, std::string& err) {
    if (obj.type != JSONType::OBJECT) {
        err = "IOC must be a JSON object";
        return false;
    }

    ioc.ioc_id = obj.get("ioc_id").asString();
    if (ioc.ioc_id.empty()) ioc.ioc_id = obj.get("id").asString();

    ioc.type = stringToIOCType(obj.get("type").asString());
    ioc.value = obj.get("value").asString();
    ioc.confidence = stringToIOCConfidence(obj.get("confidence").asString("MEDIUM"));
    ioc.severity = stringToIOCSeverity(obj.get("severity").asString("MEDIUM"));
    ioc.category = obj.get("category").asString("SUSPICIOUS");
    ioc.description = obj.get("description").asString();
    ioc.enabled = obj.get("enabled").asBool(true);

    for (const auto& t : obj.get("tags").asArray()) {
        std::string s = t.asString();
        if (!s.empty()) ioc.tags.push_back(s);
    }
    for (const auto& r : obj.get("references").asArray()) {
        std::string s = r.asString();
        if (!s.empty()) ioc.reference_metadata.push_back(s);
    }

    ioc.first_seen_timestamp = static_cast<uint64_t>(obj.get("first_seen_timestamp").asInt(0));
    ioc.last_seen_timestamp = static_cast<uint64_t>(obj.get("last_seen_timestamp").asInt(0));
    ioc.expiration_timestamp = static_cast<uint64_t>(obj.get("expiration_timestamp").asInt(0));
    ioc.analyst_notes = obj.get("analyst_notes").asString();

    return true;
}

static bool parseDatasetFromJSON(const JSONVal& obj, ThreatDataset& ds, std::string& err) {
    if (obj.type != JSONType::OBJECT) {
        err = "Dataset must be a JSON object";
        return false;
    }

    ds.dataset_id = obj.get("dataset_id").asString();
    if (ds.dataset_id.empty()) ds.dataset_id = obj.get("id").asString();
    ds.name = obj.get("name").asString();
    ds.version = obj.get("version").asString("1.0");
    ds.schema_version = obj.get("schema_version").asString("1.0");
    ds.source_description = obj.get("source_description").asString();
    ds.source_url = obj.get("source_url").asString();
    ds.created_timestamp = static_cast<uint64_t>(obj.get("created_timestamp").asInt(0));
    ds.expiration_timestamp = static_cast<uint64_t>(obj.get("expiration_timestamp").asInt(0));
    ds.enabled = obj.get("enabled").asBool(true);

    const auto& iocs_arr = obj.get("iocs").asArray();
    for (const auto& ioc_val : iocs_arr) {
        ThreatIOC ioc;
        std::string ioc_err;
        if (!parseIOCFromJSON(ioc_val, ioc, ioc_err)) {
            err = "Failed to parse IOC in dataset " + ds.dataset_id + ": " + ioc_err;
            return false;
        }
        ds.iocs.push_back(ioc);
    }

    return true;
}

// ============================================================================
// Public Parser API
// ============================================================================

bool ThreatIntelParser::parseDatasetString(const std::string& json_str,
                                           std::vector<ThreatDataset>& out_datasets,
                                           std::vector<std::string>& out_errors) {
    JSONVal root;
    try {
        root = MiniJSONParser::parse(json_str);
    } catch (const std::exception& e) {
        out_errors.push_back(std::string("JSON parse error: ") + e.what());
        return false;
    }

    bool all_ok = true;

    if (root.type == JSONType::OBJECT) {
        if (root.hasKey("datasets") && root.get("datasets").type == JSONType::ARRAY) {
            // Wrapper: {"datasets": [...]}
            for (const auto& ds_val : root.get("datasets").asArray()) {
                ThreatDataset ds;
                std::string err;
                if (!parseDatasetFromJSON(ds_val, ds, err)) {
                    out_errors.push_back(err);
                    all_ok = false;
                    continue;
                }
                auto v_res = ThreatIntelValidator::validateDataset(ds);
                if (!v_res.valid) {
                    out_errors.push_back("Validation error: " + v_res.error_message);
                    all_ok = false;
                    continue;
                }
                out_datasets.push_back(ds);
            }
        } else {
            // Single dataset object
            ThreatDataset ds;
            std::string err;
            if (!parseDatasetFromJSON(root, ds, err)) {
                out_errors.push_back(err);
                return false;
            }
            auto v_res = ThreatIntelValidator::validateDataset(ds);
            if (!v_res.valid) {
                out_errors.push_back("Validation error: " + v_res.error_message);
                return false;
            }
            out_datasets.push_back(ds);
        }
    } else if (root.type == JSONType::ARRAY) {
        // Direct array of datasets: [{...}, {...}]
        for (const auto& ds_val : root.asArray()) {
            ThreatDataset ds;
            std::string err;
            if (!parseDatasetFromJSON(ds_val, ds, err)) {
                out_errors.push_back(err);
                all_ok = false;
                continue;
            }
            auto v_res = ThreatIntelValidator::validateDataset(ds);
            if (!v_res.valid) {
                out_errors.push_back("Validation error: " + v_res.error_message);
                all_ok = false;
                continue;
            }
            out_datasets.push_back(ds);
        }
    } else {
        out_errors.push_back("Top-level JSON must be an object or array");
        return false;
    }

    return all_ok && !out_datasets.empty();
}

bool ThreatIntelParser::loadDatasetFile(const std::string& filepath,
                                       std::vector<ThreatDataset>& out_datasets,
                                       std::vector<std::string>& out_errors) {
    std::ifstream ifs(filepath);
    if (!ifs.is_open()) {
        out_errors.push_back("Cannot open dataset file: " + filepath);
        return false;
    }
    std::string content((std::istreambuf_iterator<char>(ifs)),
                         std::istreambuf_iterator<char>());
    ifs.close();

    size_t before_count = out_datasets.size();
    bool ok = parseDatasetString(content, out_datasets, out_errors);
    for (size_t i = before_count; i < out_datasets.size(); ++i) {
        out_datasets[i].filepath = filepath;
    }
    return ok;
}

bool ThreatIntelParser::loadDatasetDirectory(const std::string& dirpath,
                                            std::vector<ThreatDataset>& out_datasets,
                                            std::vector<std::string>& out_errors) {
    DIR* dir = opendir(dirpath.c_str());
    if (!dir) {
        out_errors.push_back("Cannot open threat intel directory: " + dirpath);
        return false;
    }

    std::vector<std::string> files;
    struct dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        std::string fname = entry->d_name;
        if (fname.size() > 5 && fname.substr(fname.size() - 5) == ".json") {
            std::string full_path = dirpath;
            if (!full_path.empty() && full_path.back() != '/') full_path += '/';
            full_path += fname;
            files.push_back(full_path);
        }
    }
    closedir(dir);

    std::sort(files.begin(), files.end()); // Deterministic order

    bool any_loaded = false;
    for (const auto& fp : files) {
        std::vector<std::string> file_errors;
        if (loadDatasetFile(fp, out_datasets, file_errors)) {
            any_loaded = true;
        } else {
            for (const auto& err : file_errors) {
                out_errors.push_back(fp + ": " + err);
            }
        }
    }
    return any_loaded;
}

} // namespace DPI
