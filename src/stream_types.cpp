#include "stream_types.h"
#include <iomanip>
#include <algorithm>

namespace DPI {

std::string tcpStreamStateToString(TCPStreamState state) {
    switch (state) {
        case TCPStreamState::NEW:         return "NEW";
        case TCPStreamState::SYN_SEEN:   return "SYN_SEEN";
        case TCPStreamState::ESTABLISHED:return "ESTABLISHED";
        case TCPStreamState::FIN_SEEN:   return "FIN_SEEN";
        case TCPStreamState::CLOSED:     return "CLOSED";
        case TCPStreamState::RESET:      return "RESET";
        case TCPStreamState::TIMED_OUT:  return "TIMED_OUT";
        default:                         return "UNKNOWN";
    }
}

std::string streamOverlapPolicyToString(StreamOverlapPolicy policy) {
    switch (policy) {
        case StreamOverlapPolicy::FIRST_COME_BSD: return "FIRST_COME_BSD";
        default:                                  return "UNKNOWN";
    }
}

bool StreamReassemblyConfig::validate() const {
    if (max_buffered_bytes_per_stream == 0 || max_buffered_bytes_per_stream > 67108864) {
        return false; // Between 1 byte and 64 MB
    }
    if (max_segments_per_stream == 0 || max_segments_per_stream > 10000) {
        return false;
    }
    if (max_total_reassembly_memory == 0 || max_total_reassembly_memory > 1073741824ULL) {
        return false; // Max 1 GB global
    }
    if (max_active_streams == 0 || max_active_streams > 1000000) {
        return false;
    }
    if (stream_inactivity_timeout_us < 100000ULL) {
        return false; // Minimum 100ms
    }
    return true;
}

static std::string escapeJson(const std::string& str) {
    std::string out;
    out.reserve(str.size() + 8);
    for (char c : str) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\b') out += "\\b";
        else if (c == '\f') out += "\\f";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (static_cast<unsigned char>(c) < 0x20) {
            std::ostringstream ss;
            ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
            out += ss.str();
        } else {
            out += c;
        }
    }
    return out;
}

std::string StreamRecordSummary::toJson() const {
    std::ostringstream ss;
    ss << "  {\n";
    ss << "    \"stream_id\": " << stream_id << ",\n";
    ss << "    \"tuple\": \"" << escapeJson(tuple.toString()) << "\",\n";
    ss << "    \"state\": \"" << tcpStreamStateToString(state) << "\",\n";
    ss << "    \"fwd\": {\n";
    ss << "      \"bytes_reassembled\": " << fwd.bytes_reassembled << ",\n";
    ss << "      \"segments_received\": " << fwd.segments_received << ",\n";
    ss << "      \"out_of_order_count\": " << fwd.out_of_order_count << ",\n";
    ss << "      \"retrans_count\": " << fwd.retrans_count << ",\n";
    ss << "      \"overlap_count\": " << fwd.overlap_count << ",\n";
    ss << "      \"conflict_count\": " << fwd.conflict_count << ",\n";
    ss << "      \"gap_count\": " << fwd.gap_count << ",\n";
    ss << "      \"is_complete\": " << (fwd.is_complete ? "true" : "false") << "\n";
    ss << "    },\n";
    ss << "    \"rev\": {\n";
    ss << "      \"bytes_reassembled\": " << rev.bytes_reassembled << ",\n";
    ss << "      \"segments_received\": " << rev.segments_received << ",\n";
    ss << "      \"out_of_order_count\": " << rev.out_of_order_count << ",\n";
    ss << "      \"retrans_count\": " << rev.retrans_count << ",\n";
    ss << "      \"overlap_count\": " << rev.overlap_count << ",\n";
    ss << "      \"conflict_count\": " << rev.conflict_count << ",\n";
    ss << "      \"gap_count\": " << rev.gap_count << ",\n";
    ss << "      \"is_complete\": " << (rev.is_complete ? "true" : "false") << "\n";
    ss << "    },\n";
    
    // HTTP messages
    ss << "    \"http_messages_count\": " << http_messages.size() << ",\n";
    ss << "    \"http_messages\": [";
    for (size_t i = 0; i < http_messages.size(); ++i) {
        const auto& m = http_messages[i];
        ss << "\n      {\n";
        ss << "        \"is_request\": " << (m.is_request ? "true" : "false") << ",\n";
        if (m.is_request) {
            ss << "        \"method\": \"" << escapeJson(m.method) << "\",\n";
            ss << "        \"uri\": \"" << escapeJson(m.uri) << "\",\n";
        } else {
            ss << "        \"status_code\": " << m.status_code << ",\n";
            ss << "        \"reason_phrase\": \"" << escapeJson(m.reason_phrase) << "\",\n";
        }
        ss << "        \"version\": \"" << escapeJson(m.version) << "\",\n";
        ss << "        \"host\": \"" << escapeJson(m.host) << "\",\n";
        ss << "        \"user_agent\": \"" << escapeJson(m.user_agent) << "\",\n";
        ss << "        \"content_length\": " << m.content_length << "\n";
        ss << "      }" << (i + 1 < http_messages.size() ? "," : "");
    }
    if (!http_messages.empty()) ss << "\n    ";
    ss << "],\n";

    // TLS metadata
    ss << "    \"tls\": {\n";
    ss << "      \"sni\": \"" << escapeJson(tls_meta.sni) << "\",\n";
    ss << "      \"alpn\": \"" << escapeJson(tls_meta.alpn) << "\",\n";
    ss << "      \"supported_versions\": [";
    for (size_t i = 0; i < tls_meta.supported_versions.size(); ++i) {
        ss << "\"" << escapeJson(tls_meta.supported_versions[i]) << "\""
           << (i + 1 < tls_meta.supported_versions.size() ? ", " : "");
    }
    ss << "],\n";
    ss << "      \"has_client_hello\": " << (tls_meta.has_client_hello ? "true" : "false") << ",\n";
    ss << "      \"has_encrypted_data\": " << (tls_meta.has_encrypted_data ? "true" : "false") << ",\n";
    ss << "      \"encrypted_records\": " << tls_meta.encrypted_record_count << ",\n";
    ss << "      \"encrypted_bytes\": " << tls_meta.encrypted_bytes_count << "\n";
    ss << "    }\n";
    ss << "  }";
    return ss.str();
}

std::string StreamRecordSummary::csvHeader() {
    return "stream_id,tuple,state,fwd_bytes,rev_bytes,fwd_segments,rev_segments,"
           "fwd_ooo,rev_ooo,fwd_retrans,rev_retrans,fwd_overlaps,rev_overlaps,"
           "fwd_gaps,rev_gaps,http_count,tls_sni,tls_alpn,tls_encrypted_bytes";
}

std::string StreamRecordSummary::toCsvRow() const {
    std::ostringstream ss;
    ss << stream_id << ","
       << "\"" << escapeJson(tuple.toString()) << "\","
       << tcpStreamStateToString(state) << ","
       << fwd.bytes_reassembled << ","
       << rev.bytes_reassembled << ","
       << fwd.segments_received << ","
       << rev.segments_received << ","
       << fwd.out_of_order_count << ","
       << rev.out_of_order_count << ","
       << fwd.retrans_count << ","
       << rev.retrans_count << ","
       << fwd.overlap_count << ","
       << rev.overlap_count << ","
       << fwd.gap_count << ","
       << rev.gap_count << ","
       << http_messages.size() << ","
       << "\"" << escapeJson(tls_meta.sni) << "\","
       << "\"" << escapeJson(tls_meta.alpn) << "\","
       << tls_meta.encrypted_bytes_count;
    return ss.str();
}

} // namespace DPI
