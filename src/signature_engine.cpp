#include "signature_engine.h"
#include <iomanip>
#include <sstream>
#include <algorithm>

namespace DPI {

SignatureEngine::SignatureEngine()
    : config_(SignatureEngineConfig{}) {
}

SignatureEngine::SignatureEngine(const SignatureEngineConfig& config)
    : config_(config) {
}

void SignatureEngine::reset() {
    next_event_id_ = 1;
    seen_matches_.clear();
    rule_manager_.resetStats();
}

std::string SignatureEngine::generateEventId() {
    std::ostringstream ss;
    ss << "SIGEV-" << std::setw(4) << std::setfill('0') << next_event_id_++;
    return ss.str();
}

static inline std::string formatIPString(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

std::vector<SignatureEvent> SignatureEngine::evaluatePacket(const PacketJob& job) {
    std::vector<SignatureEvent> events;
    if (!config_.enabled) return events;

    RuleEvaluationContext ctx;
    ctx.packet = &job;

    for (const auto& rule : rule_manager_.getRules()) {
        if (!rule.enabled) continue;
        rule_manager_.recordEvaluation();

        auto res = SignatureMatcher::evaluate(rule, ctx);
        if (res.matched) {
            SignatureEvent ev;
            ev.event_id = generateEventId();
            ev.rule_id = rule.rule_id;
            ev.rule_name = rule.name;
            ev.rule_revision = rule.revision;
            ev.category = rule.category;
            ev.severity = rule.severity;
            ev.timestamp_us = (static_cast<uint64_t>(job.ts_sec) * 1000000ULL) + job.ts_usec;
            ev.src_ip = formatIPString(job.tuple.src_ip);
            ev.dst_ip = formatIPString(job.tuple.dst_ip);
            ev.src_port = job.tuple.src_port;
            ev.dst_port = job.tuple.dst_port;
            ev.protocol = (job.tuple.protocol == 6) ? "TCP" : (job.tuple.protocol == 17 ? "UDP" : "IP");
            ev.direction = res.direction;
            ev.flow_id = 0;
            ev.match_scope = MatchScope::PACKET;
            ev.match_details = res.details;
            ev.matched_pattern = res.pattern;
            ev.match_offset = res.offset;
            ev.evidence = res.evidence;
            ev.confidence = "HIGH";
            ev.metadata = rule.metadata;

            rule_manager_.recordMatch(rule.rule_id, rule.category, rule.severity);
            events.push_back(std::move(ev));

            if (events.size() >= config_.max_matches) break;
        }
    }
    return events;
}

std::vector<SignatureEvent> SignatureEngine::evaluateFlow(const FlowRecord& flow) {
    std::vector<SignatureEvent> events;
    if (!config_.enabled) return events;

    RuleEvaluationContext ctx;
    ctx.flow = &flow;

    for (const auto& rule : rule_manager_.getRules()) {
        if (!rule.enabled) continue;
        rule_manager_.recordEvaluation();

        auto res = SignatureMatcher::evaluate(rule, ctx);
        if (res.matched) {
            if (config_.suppress_duplicate_matches) {
                std::string dedup_key = rule.rule_id + ":" + std::to_string(flow.flow_id);
                if (seen_matches_.find(dedup_key) != seen_matches_.end()) {
                    continue;
                }
                seen_matches_.insert(dedup_key);
            }

            SignatureEvent ev;
            ev.event_id = generateEventId();
            ev.rule_id = rule.rule_id;
            ev.rule_name = rule.name;
            ev.rule_revision = rule.revision;
            ev.category = rule.category;
            ev.severity = rule.severity;
            ev.timestamp_us = flow.start_time_us;
            ev.src_ip = formatIPString(flow.initial_tuple.src_ip);
            ev.dst_ip = formatIPString(flow.initial_tuple.dst_ip);
            ev.src_port = flow.initial_tuple.src_port;
            ev.dst_port = flow.initial_tuple.dst_port;
            ev.protocol = (flow.initial_tuple.protocol == 6) ? "TCP" : (flow.initial_tuple.protocol == 17 ? "UDP" : "IP");
            ev.direction = res.direction;
            ev.flow_id = flow.flow_id;
            ev.match_scope = res.scope;
            ev.match_details = res.details;
            ev.matched_pattern = res.pattern;
            ev.match_offset = res.offset;
            ev.evidence = res.evidence;
            ev.confidence = "HIGH";
            ev.metadata = rule.metadata;

            rule_manager_.recordMatch(rule.rule_id, rule.category, rule.severity);
            events.push_back(std::move(ev));

            if (events.size() >= config_.max_matches) break;
        }
    }
    return events;
}

std::vector<SignatureEvent> SignatureEngine::evaluateStream(const StreamRecordSummary& stream,
                                                           const FlowRecord* flow) {
    std::vector<SignatureEvent> events;
    if (!config_.enabled) return events;

    RuleEvaluationContext ctx;
    ctx.stream = &stream;
    ctx.flow = flow;

    // Apply bounded search window
    ctx.fwd_payload = stream.fwd_payload.data();
    ctx.fwd_len = std::min(stream.fwd_payload.size(), config_.max_stream_inspection_bytes);
    ctx.rev_payload = stream.rev_payload.data();
    ctx.rev_len = std::min(stream.rev_payload.size(), config_.max_stream_inspection_bytes);

    ctx.http_messages = &stream.http_messages;
    ctx.tls_meta = &stream.tls_meta;

    for (const auto& rule : rule_manager_.getRules()) {
        if (!rule.enabled) continue;
        rule_manager_.recordEvaluation();

        auto res = SignatureMatcher::evaluate(rule, ctx);
        if (res.matched) {
            uint64_t fid = flow ? flow->flow_id : stream.stream_id;
            if (config_.suppress_duplicate_matches) {
                std::string dedup_key = rule.rule_id + ":" + std::to_string(fid);
                if (seen_matches_.find(dedup_key) != seen_matches_.end()) {
                    continue;
                }
                seen_matches_.insert(dedup_key);
            }

            SignatureEvent ev;
            ev.event_id = generateEventId();
            ev.rule_id = rule.rule_id;
            ev.rule_name = rule.name;
            ev.rule_revision = rule.revision;
            ev.category = rule.category;
            ev.severity = rule.severity;
            ev.timestamp_us = flow ? flow->start_time_us : 0;
            ev.src_ip = formatIPString(stream.tuple.src_ip);
            ev.dst_ip = formatIPString(stream.tuple.dst_ip);
            ev.src_port = stream.tuple.src_port;
            ev.dst_port = stream.tuple.dst_port;
            ev.protocol = (stream.tuple.protocol == 6) ? "TCP" : "UDP";
            ev.direction = res.direction;
            ev.flow_id = fid;
            ev.match_scope = res.scope;
            ev.match_details = res.details;
            ev.matched_pattern = res.pattern;
            ev.match_offset = res.offset;
            ev.evidence = res.evidence;
            ev.confidence = "HIGH";
            ev.metadata = rule.metadata;
            ev.limitations.push_back("Content inspection bounded to first " +
                                     std::to_string(config_.max_stream_inspection_bytes) + " bytes.");

            rule_manager_.recordMatch(rule.rule_id, rule.category, rule.severity);
            events.push_back(std::move(ev));

            if (events.size() >= config_.max_matches) break;
        }
    }
    return events;
}

std::vector<SignatureEvent> SignatureEngine::evaluateAll(const std::vector<FlowRecord>& flows,
                                                         const std::vector<StreamRecordSummary>& streams) {
    std::vector<SignatureEvent> all_events;
    if (!config_.enabled || rule_manager_.getRuleCount() == 0) return all_events;

    // Index flows by canonical tuple for stream joining
    std::unordered_map<FiveTuple, const FlowRecord*, FiveTupleHash> flow_map;
    for (const auto& f : flows) {
        flow_map[f.canonical_tuple] = &f;
    }

    // 1. Evaluate Streams (TCP reassembled payloads, HTTP, TLS)
    for (const auto& stream : streams) {
        if (all_events.size() >= config_.max_matches) break;
        FiveTuple canonical = stream.tuple.toCanonical();
        const FlowRecord* matched_flow = nullptr;
        auto it = flow_map.find(canonical);
        if (it != flow_map.end()) {
            matched_flow = it->second;
        }
        auto stream_events = evaluateStream(stream, matched_flow);
        all_events.insert(all_events.end(), stream_events.begin(), stream_events.end());
    }

    // 2. Evaluate remaining Flows (Network, Flow metrics, UDP DNS, etc.)
    for (const auto& flow : flows) {
        if (all_events.size() >= config_.max_matches) break;
        auto flow_events = evaluateFlow(flow);
        all_events.insert(all_events.end(), flow_events.begin(), flow_events.end());
    }

    return all_events;
}

// ============================================================================
// Reporting and Serialization
// ============================================================================

std::string SignatureEngine::generateReport(const std::vector<SignatureEvent>& events) const {
    std::ostringstream ss;
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║          SIGNATURE-BASED INTRUSION DETECTION REPORT          ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║ Total Rules Loaded:          " << std::setw(8) << rule_manager_.getRuleCount() << "                        ║\n";
    ss << "║ Active Rules:                " << std::setw(8) << rule_manager_.getActiveRuleCount() << "                        ║\n";
    ss << "║ Total Evaluations:           " << std::setw(8) << rule_manager_.getStats().evaluations << "                        ║\n";
    ss << "║ Total Signature Matches:     " << std::setw(8) << events.size() << "                        ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║                     SEVERITY BREAKDOWN                       ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";

    size_t crit = 0, high = 0, med = 0, low = 0;
    for (const auto& ev : events) {
        if (ev.severity == SignatureSeverity::CRITICAL) crit++;
        else if (ev.severity == SignatureSeverity::HIGH) high++;
        else if (ev.severity == SignatureSeverity::MEDIUM) med++;
        else low++;
    }

    ss << "║ CRITICAL:                    " << std::setw(8) << crit << "                        ║\n";
    ss << "║ HIGH:                        " << std::setw(8) << high << "                        ║\n";
    ss << "║ MEDIUM:                      " << std::setw(8) << med << "                        ║\n";
    ss << "║ LOW:                         " << std::setw(8) << low << "                        ║\n";

    if (!events.empty()) {
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║                   DETECTED SIGNATURE EVENTS                  ║\n";
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        for (const auto& ev : events) {
            std::string sev_str = "[" + signatureSeverityToString(ev.severity) + "]";
            ss << "║ " << std::left << std::setw(12) << sev_str << " "
               << std::setw(11) << ev.rule_id << " "
               << std::setw(15) << ev.src_ip << " -> "
               << std::setw(15) << ev.dst_ip << " ║\n";
            std::string name_line = "   -> " + ev.rule_name;
            if (name_line.size() > 58) name_line = name_line.substr(0, 55) + "...";
            ss << "║ " << std::left << std::setw(60) << name_line << " ║\n";
        }
    }
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    return ss.str();
}

void SignatureEngine::exportJson(const std::vector<SignatureEvent>& events, std::ostream& os, int indent) const {
    std::string pad(indent, ' ');
    os << "[\n";
    for (size_t i = 0; i < events.size(); ++i) {
        os << events[i].toJson(indent);
        if (i + 1 < events.size()) os << ",";
        os << "\n";
    }
    os << "]\n";
}

void SignatureEngine::exportCsv(const std::vector<SignatureEvent>& events, std::ostream& os) const {
    os << SignatureEvent::csvHeader() << "\n";
    for (const auto& ev : events) {
        os << ev.toCsvRow() << "\n";
    }
}

} // namespace DPI
