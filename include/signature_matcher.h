#ifndef DPI_SIGNATURE_MATCHER_H
#define DPI_SIGNATURE_MATCHER_H

#include "signature_types.h"
#include "flow_record.h"
#include "stream_types.h"
#include <vector>
#include <string>

namespace DPI {

struct RuleEvaluationContext {
    const PacketJob* packet = nullptr;
    const FlowRecord* flow = nullptr;
    const StreamRecordSummary* stream = nullptr;

    const uint8_t* fwd_payload = nullptr;
    size_t fwd_len = 0;
    const uint8_t* rev_payload = nullptr;
    size_t rev_len = 0;

    const std::vector<HTTPMessage>* http_messages = nullptr;
    const TLSStreamMetadata* tls_meta = nullptr;
    const DNSMessage* dns_message = nullptr;
};

class SignatureMatcher {
public:
    // Evaluate a rule against the evaluation context
    static RuleMatchResult evaluate(const SignatureRule& rule, const RuleEvaluationContext& ctx);

    // Individual component matchers
    static bool matchNetwork(const NetworkCriteria& net, const FiveTuple& tuple,
                            uint8_t tcp_flags, size_t packet_size, std::string& out_dir);

    static bool matchFlow(const FlowCriteria& flow_crit, const FlowRecord& flow);

    static bool matchStreamContent(const StreamContentCriteria& stream_crit,
                                  const uint8_t* fwd_buf, size_t fwd_len,
                                  const uint8_t* rev_buf, size_t rev_len,
                                  RuleMatchResult& res);

    static bool matchHTTP(const HTTPCriteria& http_crit,
                          const std::vector<HTTPMessage>& messages,
                          const FlowRecord* flow,
                          RuleMatchResult& res);

    static bool matchTLS(const TLSCriteria& tls_crit,
                         const TLSStreamMetadata& tls_meta,
                         const FlowRecord* flow,
                         RuleMatchResult& res);

    static bool matchDNS(const DNSCriteria& dns_crit,
                         const FlowRecord* flow,
                         const DNSMessage* dns_msg,
                         RuleMatchResult& res);
};

} // namespace DPI

#endif // DPI_SIGNATURE_MATCHER_H
