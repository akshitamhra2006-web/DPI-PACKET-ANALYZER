#include "signature_matcher.h"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <map>
#include <sstream>
#include <iomanip>

namespace DPI {

static inline std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

static inline double calculateShannonEntropy(const std::string& str) {
    if (str.empty()) return 0.0;
    std::map<char, size_t> freqs;
    for (char c : str) freqs[c]++;
    double ent = 0.0;
    double len = static_cast<double>(str.size());
    for (const auto& p : freqs) {
        double prob = static_cast<double>(p.second) / len;
        ent -= prob * std::log2(prob);
    }
    return ent;
}

static inline bool matchDomainPattern(const std::string& domain_raw, const std::string& pattern_raw) {
    std::string domain = toLower(domain_raw);
    std::string pattern = toLower(pattern_raw);
    if (pattern.empty() || pattern == "*") return true;
    if (domain == pattern) return true;
    if (pattern.front() == '*' && pattern.size() > 1 && pattern[1] == '.') {
        std::string suffix = pattern.substr(2);
        if (domain == suffix) return true;
        if (domain.size() > suffix.size() &&
            domain.compare(domain.size() - suffix.size(), suffix.size(), suffix) == 0 &&
            domain[domain.size() - suffix.size() - 1] == '.') {
            return true;
        }
    }
    return domain.find(pattern) != std::string::npos;
}

static std::string formatEvidenceSnippet(const uint8_t* data, size_t len, size_t match_offset, size_t match_len) {
    if (!data || len == 0) return "";
    size_t start = (match_offset > 16) ? (match_offset - 16) : 0;
    size_t end = std::min(len, match_offset + match_len + 16);
    std::ostringstream ss;
    for (size_t i = start; i < end; ++i) {
        unsigned char c = data[i];
        if (c >= 32 && c <= 126) {
            ss << static_cast<char>(c);
        } else {
            ss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
    }
    return ss.str();
}

// Case-sensitive or case-insensitive byte sequence search
static size_t searchBuffer(const uint8_t* haystack, size_t haystack_len,
                           const uint8_t* needle, size_t needle_len,
                           bool nocase, size_t start_pos, size_t max_pos) {
    if (!haystack || !needle || needle_len == 0 || haystack_len < needle_len) return std::string::npos;
    if (start_pos + needle_len > max_pos || start_pos >= haystack_len) return std::string::npos;
    size_t limit = std::min(haystack_len - needle_len + 1, max_pos - needle_len + 1);

    for (size_t i = start_pos; i < limit; ++i) {
        bool match = true;
        for (size_t j = 0; j < needle_len; ++j) {
            uint8_t h = haystack[i + j];
            uint8_t n = needle[j];
            if (nocase) {
                h = static_cast<uint8_t>(std::tolower(h));
                n = static_cast<uint8_t>(std::tolower(n));
            }
            if (h != n) {
                match = false;
                break;
            }
        }
        if (match) return i;
    }
    return std::string::npos;
}

// ============================================================================
// Network Matcher
// ============================================================================

bool SignatureMatcher::matchNetwork(const NetworkCriteria& net, const FiveTuple& tuple,
                                    uint8_t tcp_flags, size_t packet_size, std::string& out_dir) {
    out_dir = "FORWARD";

    // Protocol
    if (net.protocol == RuleProtocol::TCP && tuple.protocol != 6) return false;
    if (net.protocol == RuleProtocol::UDP && tuple.protocol != 17) return false;

    // Directional candidate evaluation
    auto evalDirection = [&](uint32_t s_ip, uint32_t d_ip, uint16_t s_port, uint16_t d_port) -> bool {
        // Source IPs
        if (!net.src_ips.empty()) {
            bool matched = false;
            for (const auto& ip_net : net.src_ips) {
                if (ip_net.matches(s_ip)) { matched = true; break; }
            }
            if (!matched) return false;
        }
        // Destination IPs
        if (!net.dst_ips.empty()) {
            bool matched = false;
            for (const auto& ip_net : net.dst_ips) {
                if (ip_net.matches(d_ip)) { matched = true; break; }
            }
            if (!matched) return false;
        }
        // Source Ports
        if (!net.src_ports.empty()) {
            bool matched = false;
            for (const auto& pr : net.src_ports) {
                if (pr.matches(s_port)) { matched = true; break; }
            }
            if (!matched) return false;
        }
        // Destination Ports
        if (!net.dst_ports.empty()) {
            bool matched = false;
            for (const auto& pr : net.dst_ports) {
                if (pr.matches(d_port)) { matched = true; break; }
            }
            if (!matched) return false;
        }
        return true;
    };

    bool fwd_match = evalDirection(tuple.src_ip, tuple.dst_ip, tuple.src_port, tuple.dst_port);
    bool rev_match = evalDirection(tuple.dst_ip, tuple.src_ip, tuple.dst_port, tuple.src_port);

    if (net.direction == RuleDirection::FORWARD) {
        if (!fwd_match) return false;
        out_dir = "FORWARD";
    } else if (net.direction == RuleDirection::REVERSE) {
        if (!rev_match) return false;
        out_dir = "REVERSE";
    } else {
        // BIDIRECTIONAL
        if (fwd_match) out_dir = "FORWARD";
        else if (rev_match) out_dir = "REVERSE";
        else return false;
    }

    // TCP Flags
    if (net.tcp_flags_mask != 0) {
        if ((tcp_flags & net.tcp_flags_mask) != net.tcp_flags_value) return false;
    }

    // Packet Size
    if (packet_size > 0) {
        if (net.packet_size_min > 0 && packet_size < net.packet_size_min) return false;
        if (net.packet_size_max > 0 && packet_size > net.packet_size_max) return false;
    }

    return true;
}

// ============================================================================
// Flow Matcher
// ============================================================================

bool SignatureMatcher::matchFlow(const FlowCriteria& flow_crit, const FlowRecord& flow) {
    if (flow_crit.flow_state != FlowStateCriteria::ANY) {
        if (flow_crit.flow_state == FlowStateCriteria::NEW && flow.state != FlowLifecycleState::NEW) return false;
        if (flow_crit.flow_state == FlowStateCriteria::ESTABLISHED && flow.state != FlowLifecycleState::ESTABLISHED) return false;
        if (flow_crit.flow_state == FlowStateCriteria::CLOSED && flow.state != FlowLifecycleState::CLOSED) return false;
        if (flow_crit.flow_state == FlowStateCriteria::RESET && flow.termination_reason != FlowTerminationReason::NATURAL_FIN_RST) return false;
    }

    uint64_t total_bytes = flow.total_bytes();
    if (flow_crit.min_bytes > 0 && total_bytes < flow_crit.min_bytes) return false;
    if (flow_crit.max_bytes > 0 && total_bytes > flow_crit.max_bytes) return false;

    uint64_t total_pkts = flow.total_packets();
    if (flow_crit.min_packets > 0 && total_pkts < flow_crit.min_packets) return false;
    if (flow_crit.max_packets > 0 && total_pkts > flow_crit.max_packets) return false;

    double dur = flow.duration_seconds();
    if (flow_crit.min_duration_sec > 0.0 && dur < flow_crit.min_duration_sec) return false;
    if (flow_crit.max_duration_sec > 0.0 && dur > flow_crit.max_duration_sec) return false;

    if (flow_crit.min_asymmetry_ratio > 0.0 && flow.byte_asymmetry_ratio() < flow_crit.min_asymmetry_ratio) return false;

    return true;
}

// ============================================================================
// Stream Content Matcher
// ============================================================================

static bool matchChainedPatterns(const std::vector<PatternCondition>& patterns,
                                 const uint8_t* buf, size_t buf_len,
                                 int64_t& first_match_offset, std::string& matched_pat,
                                 std::string& snippet) {
    if (!buf || buf_len == 0 || patterns.empty()) return false;

    size_t prev_match_end = 0;
    first_match_offset = -1;

    for (size_t i = 0; i < patterns.size(); ++i) {
        const auto& p = patterns[i];
        std::vector<uint8_t> temp_bytes;
        const uint8_t* needle = nullptr;
        size_t needle_len = 0;
        if (!p.bytes.empty()) {
            needle = p.bytes.data();
            needle_len = p.bytes.size();
        } else if (p.is_hex) {
            PatternCondition copy_p = p;
            if (copy_p.decodeHex()) {
                temp_bytes = copy_p.bytes;
                needle = temp_bytes.data();
                needle_len = temp_bytes.size();
            }
        } else {
            needle = reinterpret_cast<const uint8_t*>(p.pattern.data());
            needle_len = p.pattern.size();
        }
        if (needle_len == 0) continue;

        size_t start_pos = 0;
        size_t max_pos = buf_len;

        if (i == 0) {
            if (p.offset >= 0) start_pos = static_cast<size_t>(p.offset);
            if (p.depth > 0) max_pos = std::min(buf_len, start_pos + static_cast<size_t>(p.depth));
        } else {
            if (p.relative_distance >= 0) {
                start_pos = prev_match_end + static_cast<size_t>(p.relative_distance);
            } else if (p.offset >= 0) {
                start_pos = static_cast<size_t>(p.offset);
            } else {
                start_pos = prev_match_end;
            }
            if (p.relative_within > 0) {
                max_pos = std::min(buf_len, prev_match_end + static_cast<size_t>(p.relative_within));
            } else if (p.depth > 0) {
                max_pos = std::min(buf_len, start_pos + static_cast<size_t>(p.depth));
            }
        }

        if (start_pos >= buf_len || start_pos + needle_len > max_pos) {
            if (p.negated) continue; // Pattern absent as required
            return false;
        }

        size_t found_idx = searchBuffer(buf, buf_len, needle, needle_len, p.nocase, start_pos, max_pos);
        if (found_idx != std::string::npos) {
            if (p.negated) return false; // Found but required absent
            if (first_match_offset == -1) {
                first_match_offset = static_cast<int64_t>(found_idx);
                matched_pat = p.pattern;
                snippet = formatEvidenceSnippet(buf, buf_len, found_idx, needle_len);
            }
            prev_match_end = found_idx + needle_len;
        } else {
            if (p.negated) continue; // Required absent, was absent -> ok
            return false;
        }
    }
    return true;
}

bool SignatureMatcher::matchStreamContent(const StreamContentCriteria& stream_crit,
                                          const uint8_t* fwd_buf, size_t fwd_len,
                                          const uint8_t* rev_buf, size_t rev_len,
                                          RuleMatchResult& res) {
    if (stream_crit.patterns.empty()) return true;

    StreamDirection required_dir = stream_crit.patterns.front().direction;
    int64_t offset = -1;
    std::string pat, snip;

    bool fwd_matched = false;
    bool rev_matched = false;

    if (fwd_buf && fwd_len > 0 && required_dir != StreamDirection::REV_ONLY) {
        fwd_matched = matchChainedPatterns(stream_crit.patterns, fwd_buf, fwd_len, offset, pat, snip);
        if (fwd_matched) {
            res.direction = "FORWARD";
            res.offset = offset;
            res.pattern = pat;
            res.evidence = snip;
        }
    }

    if (rev_buf && rev_len > 0 && required_dir != StreamDirection::FWD_ONLY) {
        int64_t rev_offset = -1;
        std::string rev_pat, rev_snip;
        rev_matched = matchChainedPatterns(stream_crit.patterns, rev_buf, rev_len, rev_offset, rev_pat, rev_snip);
        if (rev_matched && !fwd_matched) {
            res.direction = "REVERSE";
            res.offset = rev_offset;
            res.pattern = rev_pat;
            res.evidence = rev_snip;
        }
    }

    if (required_dir == StreamDirection::FWD_ONLY) return fwd_matched;
    if (required_dir == StreamDirection::REV_ONLY) return rev_matched;
    if (required_dir == StreamDirection::BOTH) return fwd_matched && rev_matched;
    return fwd_matched || rev_matched;
}

// ============================================================================
// HTTP Matcher
// ============================================================================

bool SignatureMatcher::matchHTTP(const HTTPCriteria& http_crit,
                                 const std::vector<HTTPMessage>& messages,
                                 const FlowRecord* flow,
                                 RuleMatchResult& res) {
    if (!http_crit.has_criteria()) return true;

    auto evalMsg = [&](const std::string& method, const std::string& host,
                       const std::string& uri, const std::string& user_agent,
                       int status, const std::map<std::string, std::string>& headers) -> bool {
        if (!http_crit.method.empty()) {
            if (toLower(method) != toLower(http_crit.method)) return false;
        }
        if (!http_crit.host.empty()) {
            if (!matchDomainPattern(host, http_crit.host)) return false;
        }
        if (!http_crit.uri.empty()) {
            if (toLower(uri).find(toLower(http_crit.uri)) == std::string::npos) return false;
        }
        if (!http_crit.user_agent.empty()) {
            if (toLower(user_agent).find(toLower(http_crit.user_agent)) == std::string::npos) return false;
        }
        if (http_crit.status_code != 0) {
            if (status != http_crit.status_code) return false;
        }
        if (!http_crit.headers.empty()) {
            for (const auto& pair : http_crit.headers) {
                std::string req_hdr_key = toLower(pair.first);
                std::string req_hdr_val = toLower(pair.second);
                bool found = false;
                for (const auto& msg_hdr : headers) {
                    if (toLower(msg_hdr.first) == req_hdr_key) {
                        if (toLower(msg_hdr.second).find(req_hdr_val) != std::string::npos) {
                            found = true;
                            break;
                        }
                    }
                }
                if (!found) return false;
            }
        }
        return true;
    };

    // 1. Check parsed stream HTTP messages individually
    for (const auto& m : messages) {
        if (evalMsg(m.method, m.host, m.uri, m.user_agent, m.status_code, m.headers)) {
            res.scope = MatchScope::HTTP;
            res.evidence = (m.is_request ? "HTTP " + m.method + " " + m.uri : "HTTP " + std::to_string(m.status_code))
                           + " [Host: " + m.host + ", UA: " + m.user_agent + "]";
            return true;
        }
    }

    // 2. Check across stream request/response messages (transaction-level match)
    bool has_req_crit = !http_crit.method.empty() || !http_crit.host.empty() ||
                        !http_crit.uri.empty() || !http_crit.user_agent.empty();
    bool has_resp_crit = (http_crit.status_code != 0);

    if (has_req_crit && has_resp_crit) {
        bool req_matched = false;
        std::string req_evidence;
        for (const auto& m : messages) {
            if (m.is_request) {
                bool ok = true;
                if (!http_crit.method.empty() && toLower(m.method) != toLower(http_crit.method)) ok = false;
                if (!http_crit.host.empty() && !matchDomainPattern(m.host, http_crit.host)) ok = false;
                if (!http_crit.uri.empty() && toLower(m.uri).find(toLower(http_crit.uri)) == std::string::npos) ok = false;
                if (!http_crit.user_agent.empty() && toLower(m.user_agent).find(toLower(http_crit.user_agent)) == std::string::npos) ok = false;
                if (ok) {
                    req_matched = true;
                    req_evidence = "HTTP " + m.method + " " + m.uri + " [Host: " + m.host + ", UA: " + m.user_agent + "]";
                    break;
                }
            }
        }

        bool resp_matched = false;
        std::string resp_evidence;
        for (const auto& m : messages) {
            if (!m.is_request) {
                if (m.status_code == http_crit.status_code) {
                    resp_matched = true;
                    resp_evidence = "HTTP " + std::to_string(m.status_code);
                    break;
                }
            }
        }

        if (req_matched && resp_matched) {
            bool all_headers = true;
            for (const auto& pair : http_crit.headers) {
                std::string req_hdr_key = toLower(pair.first);
                std::string req_hdr_val = toLower(pair.second);
                bool found = false;
                for (const auto& m : messages) {
                    for (const auto& h : m.headers) {
                        if (toLower(h.first) == req_hdr_key && toLower(h.second).find(req_hdr_val) != std::string::npos) {
                            found = true;
                            break;
                        }
                    }
                    if (found) break;
                }
                if (!found) { all_headers = false; break; }
            }

            if (all_headers) {
                res.scope = MatchScope::HTTP;
                res.evidence = req_evidence + " -> " + resp_evidence;
                return true;
            }
        }
    }

    // 3. Check flow-level HTTP metadata if available
    if (flow) {
        std::map<std::string, std::string> dummy_headers;
        if (evalMsg(flow->http_method, flow->http_host, flow->http_uri,
                    flow->http_user_agent, flow->http_status_code, dummy_headers)) {
            res.scope = MatchScope::HTTP;
            res.evidence = "Flow HTTP " + flow->http_method + " " + flow->http_uri
                           + " [Host: " + flow->http_host + ", UA: " + flow->http_user_agent + "]";
            return true;
        }
    }

    return false;
}

// ============================================================================
// TLS Matcher
// ============================================================================

bool SignatureMatcher::matchTLS(const TLSCriteria& tls_crit,
                                const TLSStreamMetadata& tls_meta,
                                const FlowRecord* flow,
                                RuleMatchResult& res) {
    if (!tls_crit.has_criteria()) return true;

    std::string sni = !tls_meta.sni.empty() ? tls_meta.sni : (flow ? flow->sni : "");
    std::string alpn = !tls_meta.alpn.empty() ? tls_meta.alpn : (flow ? flow->tls_alpn : "");

    if (!tls_crit.sni.empty()) {
        if (!matchDomainPattern(sni, tls_crit.sni)) return false;
    }
    if (!tls_crit.alpn.empty()) {
        if (toLower(alpn).find(toLower(tls_crit.alpn)) == std::string::npos) return false;
    }
    if (!tls_crit.version.empty()) {
        bool ver_matched = false;
        std::string req_ver = toLower(tls_crit.version);
        for (const auto& v : tls_meta.supported_versions) {
            if (toLower(v).find(req_ver) != std::string::npos) { ver_matched = true; break; }
        }
        if (flow && toLower(flow->tls_supported_version).find(req_ver) != std::string::npos) {
            ver_matched = true;
        }
        if (!ver_matched) return false;
    }
    if (tls_crit.cipher_suite != 0) {
        bool cs_found = false;
        for (uint16_t cs : tls_meta.cipher_suites) {
            if (cs == tls_crit.cipher_suite) { cs_found = true; break; }
        }
        if (!cs_found) return false;
    }

    res.scope = MatchScope::TLS;
    res.evidence = "TLS SNI=" + sni + " ALPN=" + alpn;
    return true;
}

// ============================================================================
// DNS Matcher
// ============================================================================

bool SignatureMatcher::matchDNS(const DNSCriteria& dns_crit,
                                const FlowRecord* flow,
                                const DNSMessage* dns_msg,
                                RuleMatchResult& res) {
    if (!dns_crit.has_criteria()) return true;

    std::string qname;
    uint16_t qtype = 0;
    int rcode = -1;
    bool is_nx = false;

    if (dns_msg) {
        if (!dns_msg->queries.empty()) {
            qname = dns_msg->queries.front().name;
            qtype = dns_msg->queries.front().type;
        }
        rcode = dns_msg->rcode;
        is_nx = (rcode == 3 || dns_msg->rcode_name == "NXDOMAIN");
    } else if (flow) {
        qname = flow->dns_query;
        rcode = flow->dns_rcode;
        is_nx = (flow->dns_rcode == 3 || flow->dns_rcode_name == "NXDOMAIN");
    }

    if (!dns_crit.query_name.empty()) {
        if (!matchDomainPattern(qname, dns_crit.query_name)) return false;
    }
    if (dns_crit.query_type != 0 && qtype != 0) {
        if (qtype != dns_crit.query_type) return false;
    }
    if (dns_crit.rcode != -1) {
        if (rcode != dns_crit.rcode) return false;
    }
    if (dns_crit.is_nxdomain.has_value()) {
        if (is_nx != dns_crit.is_nxdomain.value()) return false;
    }
    if (dns_crit.min_entropy > 0.0) {
        double ent = calculateShannonEntropy(qname);
        if (ent < dns_crit.min_entropy) return false;
    }

    res.scope = MatchScope::DNS;
    res.evidence = "DNS query=" + qname + " rcode=" + std::to_string(rcode);
    return true;
}

// ============================================================================
// Primary Evaluation Entrypoint
// ============================================================================

RuleMatchResult SignatureMatcher::evaluate(const SignatureRule& rule, const RuleEvaluationContext& ctx) {
    RuleMatchResult res;
    if (!rule.enabled) return res;

    FiveTuple tuple;
    uint8_t flags = 0;
    size_t pkt_size = 0;

    if (ctx.packet) {
        tuple = ctx.packet->tuple;
        flags = ctx.packet->tcp_flags;
        pkt_size = ctx.packet->data.size();
    } else if (ctx.flow) {
        tuple = ctx.flow->initial_tuple;
    } else if (ctx.stream) {
        tuple = ctx.stream->tuple;
    } else {
        return res;
    }

    // 1. Network criteria
    if (rule.network.has_criteria()) {
        std::string dir;
        if (!matchNetwork(rule.network, tuple, flags, pkt_size, dir)) {
            return res;
        }
        res.direction = dir;
    }

    // 2. Flow criteria
    if (rule.flow.has_criteria()) {
        if (!ctx.flow || !matchFlow(rule.flow, *ctx.flow)) {
            return res;
        }
        res.scope = MatchScope::FLOW;
    }

    // 3. Stream content criteria
    if (rule.stream_content.has_criteria()) {
        const uint8_t* fwd_data = ctx.fwd_payload;
        size_t fwd_len = ctx.fwd_len;
        const uint8_t* rev_data = ctx.rev_payload;
        size_t rev_len = ctx.rev_len;

        if (ctx.stream) {
            if (!fwd_data && !ctx.stream->fwd_payload.empty()) {
                fwd_data = ctx.stream->fwd_payload.data();
                fwd_len = ctx.stream->fwd_payload.size();
            }
            if (!rev_data && !ctx.stream->rev_payload.empty()) {
                rev_data = ctx.stream->rev_payload.data();
                rev_len = ctx.stream->rev_payload.size();
            }
        }

        if (!matchStreamContent(rule.stream_content, fwd_data, fwd_len, rev_data, rev_len, res)) {
            return res;
        }
        res.scope = MatchScope::STREAM;
    }

    // 4. HTTP criteria
    if (rule.http.has_criteria()) {
        std::vector<HTTPMessage> msgs;
        if (ctx.http_messages) msgs = *ctx.http_messages;
        else if (ctx.stream) msgs = ctx.stream->http_messages;

        if (!matchHTTP(rule.http, msgs, ctx.flow, res)) {
            return res;
        }
    }

    // 5. TLS criteria
    if (rule.tls.has_criteria()) {
        TLSStreamMetadata tls;
        if (ctx.tls_meta) tls = *ctx.tls_meta;
        else if (ctx.stream) tls = ctx.stream->tls_meta;

        if (!matchTLS(rule.tls, tls, ctx.flow, res)) {
            return res;
        }
    }

    // 6. DNS criteria
    if (rule.dns.has_criteria()) {
        if (!matchDNS(rule.dns, ctx.flow, ctx.dns_message, res)) {
            return res;
        }
    }

    // All specified criteria passed!
    res.matched = true;
    res.details = "Matched signature rule " + rule.rule_id + " (" + rule.name + ") [" +
                  signatureCategoryToString(rule.category) + "/" + signatureSeverityToString(rule.severity) + "]";
    return res;
}

} // namespace DPI
