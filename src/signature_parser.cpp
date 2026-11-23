#include "signature_parser.h"
#include "signature_validator.h"
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
                // Line comment
                pos += 2;
                while (pos < text.size() && text[pos] != '\n') pos++;
            } else if (c == '/' && pos + 1 < text.size() && text[pos + 1] == '*') {
                // Block comment
                pos += 2;
                while (pos + 1 < text.size() && !(text[pos] == '*' && text[pos + 1] == '/')) pos++;
                if (pos + 1 < text.size()) pos += 2;
            } else {
                break;
            }
        }
    }

    static JSONVal parseValue(const std::string& text, size_t& pos) {
        skipWhitespace(text, pos);
        if (pos >= text.size()) throw std::runtime_error("Unexpected end of JSON");

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
        pos++; // Skip '{'
        JSONVal obj;
        obj.type = JSONType::OBJECT;
        skipWhitespace(text, pos);

        if (pos < text.size() && text[pos] == '}') {
            pos++;
            return obj;
        }

        while (pos < text.size()) {
            skipWhitespace(text, pos);
            if (pos >= text.size() || text[pos] != '"') {
                throw std::runtime_error("Expected string key in object at pos " + std::to_string(pos));
            }
            std::string key = parseString(text, pos).str_val;
            skipWhitespace(text, pos);
            if (pos >= text.size() || text[pos] != ':') {
                throw std::runtime_error("Expected ':' after key '" + key + "' at pos " + std::to_string(pos));
            }
            pos++; // Skip ':'
            JSONVal val = parseValue(text, pos);
            obj.obj_val[key] = std::move(val);

            skipWhitespace(text, pos);
            if (pos < text.size() && text[pos] == '}') {
                pos++;
                return obj;
            }
            if (pos >= text.size() || text[pos] != ',') {
                throw std::runtime_error("Expected ',' or '}' in object at pos " + std::to_string(pos));
            }
            pos++; // Skip ','
        }
        throw std::runtime_error("Unterminated object in JSON");
    }

    static JSONVal parseArray(const std::string& text, size_t& pos) {
        pos++; // Skip '['
        JSONVal arr;
        arr.type = JSONType::ARRAY;
        skipWhitespace(text, pos);

        if (pos < text.size() && text[pos] == ']') {
            pos++;
            return arr;
        }

        while (pos < text.size()) {
            JSONVal val = parseValue(text, pos);
            arr.arr_val.push_back(std::move(val));

            skipWhitespace(text, pos);
            if (pos < text.size() && text[pos] == ']') {
                pos++;
                return arr;
            }
            if (pos >= text.size() || text[pos] != ',') {
                throw std::runtime_error("Expected ',' or ']' in array at pos " + std::to_string(pos));
            }
            pos++; // Skip ','
        }
        throw std::runtime_error("Unterminated array in JSON");
    }

    static JSONVal parseString(const std::string& text, size_t& pos) {
        pos++; // Skip '"'
        std::string s;
        while (pos < text.size()) {
            char c = text[pos++];
            if (c == '"') {
                JSONVal val;
                val.type = JSONType::STRING;
                val.str_val = s;
                return val;
            }
            if (c == '\\') {
                if (pos >= text.size()) throw std::runtime_error("Unterminated escape sequence in string");
                char esc = text[pos++];
                switch (esc) {
                    case '"': s += '"'; break;
                    case '\\': s += '\\'; break;
                    case '/': s += '/'; break;
                    case 'b': s += '\b'; break;
                    case 'f': s += '\f'; break;
                    case 'n': s += '\n'; break;
                    case 'r': s += '\r'; break;
                    case 't': s += '\t'; break;
                    case 'u': {
                        if (pos + 4 > text.size()) throw std::runtime_error("Truncated unicode escape in string");
                        std::string hex_str = text.substr(pos, 4);
                        pos += 4;
                        try {
                            unsigned long code = std::stoul(hex_str, nullptr, 16);
                            if (code < 128) s += static_cast<char>(code);
                            else s += '?';
                        } catch (...) {
                            s += '?';
                        }
                        break;
                    }
                    default: s += esc; break;
                }
            } else {
                s += c;
            }
        }
        throw std::runtime_error("Unterminated string in JSON");
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
        val.num_val = std::stod(num_str);
        return val;
    }

    static JSONVal parseBool(const std::string& text, size_t& pos) {
        if (text.compare(pos, 4, "true") == 0) {
            pos += 4;
            JSONVal val;
            val.type = JSONType::BOOL;
            val.bool_val = true;
            return val;
        }
        if (text.compare(pos, 5, "false") == 0) {
            pos += 5;
            JSONVal val;
            val.type = JSONType::BOOL;
            val.bool_val = false;
            return val;
        }
        throw std::runtime_error("Invalid boolean literal at pos " + std::to_string(pos));
    }

    static JSONVal parseNull(const std::string& text, size_t& pos) {
        if (text.compare(pos, 4, "null") == 0) {
            pos += 4;
            JSONVal val;
            val.type = JSONType::NULL_TYPE;
            return val;
        }
        throw std::runtime_error("Invalid null literal at pos " + std::to_string(pos));
    }
};

// ============================================================================
// Rule Mapping from JSON Object
// ============================================================================

static bool parseSingleRule(const JSONVal& obj, SignatureRule& rule, std::string& err) {
    if (obj.type != JSONType::OBJECT) {
        err = "Rule entry must be a JSON object";
        return false;
    }

    // Identifiers
    rule.rule_id = obj.hasKey("id") ? obj.get("id").asString() : obj.get("rule_id").asString();
    rule.name = obj.hasKey("name") ? obj.get("name").asString() : obj.get("rule_name").asString();
    rule.schema_version = obj.get("schema_version").asString("1.0");
    rule.revision = static_cast<uint32_t>(obj.get("revision").asInt(1));
    rule.description = obj.get("description").asString("");
    rule.enabled = obj.get("enabled").asBool(true);
    rule.match_limit = static_cast<uint32_t>(obj.get("match_limit").asInt(0));

    if (obj.hasKey("category")) {
        rule.category = stringToSignatureCategory(obj.get("category").asString());
    }
    if (obj.hasKey("severity")) {
        rule.severity = stringToSignatureSeverity(obj.get("severity").asString());
    }

    // Tags & references
    if (obj.hasKey("tags")) {
        for (const auto& t : obj.get("tags").asArray()) {
            rule.tags.push_back(t.asString());
        }
    }
    if (obj.hasKey("references")) {
        for (const auto& r : obj.get("references").asArray()) {
            rule.references.push_back(r.asString());
        }
    }
    if (obj.hasKey("metadata") && obj.get("metadata").type == JSONType::OBJECT) {
        for (const auto& pair : obj.get("metadata").asObject()) {
            rule.metadata[pair.first] = pair.second.asString();
        }
    }

    // Network Criteria
    if (obj.hasKey("network") && obj.get("network").type == JSONType::OBJECT) {
        const auto& net = obj.get("network");
        if (net.hasKey("protocol")) {
            rule.network.protocol = stringToRuleProtocol(net.get("protocol").asString());
        }
        if (net.hasKey("direction")) {
            rule.network.direction = stringToRuleDirection(net.get("direction").asString());
        }
        // Source IPs
        if (net.hasKey("src_ip")) {
            rule.network.src_ips.push_back(IPNet::parse(net.get("src_ip").asString()));
        }
        if (net.hasKey("src_ips")) {
            for (const auto& item : net.get("src_ips").asArray()) {
                rule.network.src_ips.push_back(IPNet::parse(item.asString()));
            }
        }
        // Destination IPs
        if (net.hasKey("dst_ip")) {
            rule.network.dst_ips.push_back(IPNet::parse(net.get("dst_ip").asString()));
        }
        if (net.hasKey("dst_ips")) {
            for (const auto& item : net.get("dst_ips").asArray()) {
                rule.network.dst_ips.push_back(IPNet::parse(item.asString()));
            }
        }
        // Source Ports
        if (net.hasKey("src_port")) {
            rule.network.src_ports.push_back(PortRange::parse(net.get("src_port").type == JSONType::NUMBER ?
                std::to_string(net.get("src_port").asInt()) : net.get("src_port").asString()));
        }
        if (net.hasKey("src_ports")) {
            for (const auto& item : net.get("src_ports").asArray()) {
                rule.network.src_ports.push_back(PortRange::parse(item.type == JSONType::NUMBER ?
                    std::to_string(item.asInt()) : item.asString()));
            }
        }
        // Destination Ports
        if (net.hasKey("dst_port")) {
            rule.network.dst_ports.push_back(PortRange::parse(net.get("dst_port").type == JSONType::NUMBER ?
                std::to_string(net.get("dst_port").asInt()) : net.get("dst_port").asString()));
        }
        if (net.hasKey("dst_ports")) {
            for (const auto& item : net.get("dst_ports").asArray()) {
                rule.network.dst_ports.push_back(PortRange::parse(item.type == JSONType::NUMBER ?
                    std::to_string(item.asInt()) : item.asString()));
            }
        }
        // TCP Flags
        if (net.hasKey("tcp_flags")) {
            std::string fl = net.get("tcp_flags").asString();
            std::transform(fl.begin(), fl.end(), fl.begin(), [](unsigned char c) { return std::toupper(c); });
            uint8_t f = 0;
            if (fl.find("FIN") != std::string::npos) f |= 0x01;
            if (fl.find("SYN") != std::string::npos) f |= 0x02;
            if (fl.find("RST") != std::string::npos) f |= 0x04;
            if (fl.find("PSH") != std::string::npos) f |= 0x08;
            if (fl.find("ACK") != std::string::npos) f |= 0x10;
            if (fl.find("URG") != std::string::npos) f |= 0x20;
            rule.network.tcp_flags_mask = f;
            rule.network.tcp_flags_value = f;
        }
        if (net.hasKey("packet_size_min")) {
            rule.network.packet_size_min = static_cast<uint32_t>(net.get("packet_size_min").asInt());
        }
        if (net.hasKey("packet_size_max")) {
            rule.network.packet_size_max = static_cast<uint32_t>(net.get("packet_size_max").asInt());
        }
    }

    // Flow Criteria
    if (obj.hasKey("flow") && obj.get("flow").type == JSONType::OBJECT) {
        const auto& fl = obj.get("flow");
        if (fl.hasKey("flow_state")) {
            rule.flow.flow_state = stringToFlowStateCriteria(fl.get("flow_state").asString());
        }
        rule.flow.min_bytes = static_cast<uint64_t>(fl.get("min_bytes").asInt());
        rule.flow.max_bytes = static_cast<uint64_t>(fl.get("max_bytes").asInt());
        rule.flow.min_packets = static_cast<uint64_t>(fl.get("min_packets").asInt());
        rule.flow.max_packets = static_cast<uint64_t>(fl.get("max_packets").asInt());
        rule.flow.min_duration_sec = fl.get("min_duration_sec").asNumber();
        rule.flow.max_duration_sec = fl.get("max_duration_sec").asNumber();
        rule.flow.min_asymmetry_ratio = fl.get("min_asymmetry_ratio").asNumber();
    }

    // Stream Content Criteria
    if (obj.hasKey("stream_content") && obj.get("stream_content").type == JSONType::ARRAY) {
        for (const auto& item : obj.get("stream_content").asArray()) {
            PatternCondition p;
            p.pattern = item.get("pattern").asString();
            p.is_hex = item.get("is_hex").asBool(false);
            p.nocase = item.get("nocase").asBool(false);
            p.offset = static_cast<int32_t>(item.get("offset").asInt(-1));
            p.depth = static_cast<int32_t>(item.get("depth").asInt(0));
            p.relative_distance = static_cast<int32_t>(item.get("relative_distance").asInt(-1));
            p.relative_within = static_cast<int32_t>(item.get("relative_within").asInt(0));
            p.negated = item.get("negated").asBool(false);
            if (item.hasKey("direction")) {
                p.direction = stringToStreamDirection(item.get("direction").asString());
            }
            rule.stream_content.patterns.push_back(std::move(p));
        }
    }

    // HTTP Criteria
    if (obj.hasKey("http") && obj.get("http").type == JSONType::OBJECT) {
        const auto& h = obj.get("http");
        rule.http.method = h.get("method").asString();
        rule.http.host = h.get("host").asString();
        rule.http.uri = h.get("uri").asString();
        rule.http.user_agent = h.get("user_agent").asString();
        rule.http.status_code = static_cast<int>(h.get("status_code").asInt(0));
        if (h.hasKey("headers") && h.get("headers").type == JSONType::OBJECT) {
            for (const auto& pair : h.get("headers").asObject()) {
                rule.http.headers[pair.first] = pair.second.asString();
            }
        }
    }

    // TLS Criteria
    if (obj.hasKey("tls") && obj.get("tls").type == JSONType::OBJECT) {
        const auto& t = obj.get("tls");
        rule.tls.sni = t.get("sni").asString();
        rule.tls.alpn = t.get("alpn").asString();
        rule.tls.version = t.get("version").asString();
        rule.tls.cipher_suite = static_cast<uint16_t>(t.get("cipher_suite").asInt(0));
    }

    // DNS Criteria
    if (obj.hasKey("dns") && obj.get("dns").type == JSONType::OBJECT) {
        const auto& d = obj.get("dns");
        rule.dns.query_name = d.get("query_name").asString();
        rule.dns.query_type = static_cast<uint16_t>(d.get("query_type").asInt(0));
        rule.dns.rcode = static_cast<int>(d.get("rcode").asInt(-1));
        if (d.hasKey("is_nxdomain")) {
            rule.dns.is_nxdomain = d.get("is_nxdomain").asBool();
        }
        rule.dns.min_entropy = d.get("min_entropy").asNumber(0.0);
    }

    // Validate the rule
    auto val_res = SignatureValidator::validateRule(rule);
    if (!val_res.valid) {
        err = val_res.error_message;
        return false;
    }

    return true;
}

// ============================================================================
// SignatureParser Public Methods
// ============================================================================

ParseResult SignatureParser::parseString(const std::string& json_str) {
    ParseResult result;
    JSONVal root;
    try {
        root = MiniJSONParser::parse(json_str);
    } catch (const std::exception& e) {
        result.success = false;
        result.errors.push_back(std::string("JSON parse error: ") + e.what());
        return result;
    }

    if (root.type == JSONType::OBJECT) {
        if (root.hasKey("rules") && root.get("rules").type == JSONType::ARRAY) {
            for (const auto& item : root.get("rules").asArray()) {
                SignatureRule r;
                std::string err;
                if (parseSingleRule(item, r, err)) {
                    result.rules.push_back(std::move(r));
                } else {
                    result.errors.push_back(err);
                }
            }
        } else {
            // Single rule object
            SignatureRule r;
            std::string err;
            if (parseSingleRule(root, r, err)) {
                result.rules.push_back(std::move(r));
            } else {
                result.errors.push_back(err);
            }
        }
    } else if (root.type == JSONType::ARRAY) {
        for (const auto& item : root.asArray()) {
            SignatureRule r;
            std::string err;
            if (parseSingleRule(item, r, err)) {
                result.rules.push_back(std::move(r));
            } else {
                result.errors.push_back(err);
            }
        }
    } else {
        result.success = false;
        result.errors.push_back("Root JSON element must be an object or array");
    }

    if (!result.errors.empty() && result.rules.empty()) {
        result.success = false;
    }
    return result;
}

ParseResult SignatureParser::parseFile(const std::string& filepath) {
    ParseResult result;
    std::ifstream file(filepath);
    if (!file.is_open()) {
        result.success = false;
        result.errors.push_back("Cannot open rule file: " + filepath);
        return result;
    }
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    return parseString(content);
}

ParseResult SignatureParser::parseDirectory(const std::string& dirpath) {
    ParseResult result;
    DIR* dir = opendir(dirpath.c_str());
    if (!dir) {
        result.success = false;
        result.errors.push_back("Cannot open rule directory: " + dirpath);
        return result;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string fname = entry->d_name;
        if (fname == "." || fname == "..") continue;
        if (fname.size() > 5 && fname.substr(fname.size() - 5) == ".json") {
            std::string fullpath = dirpath + "/" + fname;
            auto file_res = parseFile(fullpath);
            result.rules.insert(result.rules.end(), file_res.rules.begin(), file_res.rules.end());
            result.errors.insert(result.errors.end(), file_res.errors.begin(), file_res.errors.end());
            result.warnings.insert(result.warnings.end(), file_res.warnings.begin(), file_res.warnings.end());
        }
    }
    closedir(dir);

    if (result.rules.empty() && !result.errors.empty()) {
        result.success = false;
    }
    return result;
}

} // namespace DPI
