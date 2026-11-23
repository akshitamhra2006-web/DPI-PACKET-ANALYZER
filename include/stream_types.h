#ifndef DPI_STREAM_TYPES_H
#define DPI_STREAM_TYPES_H

#include "types.h"
#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <sstream>
#include <iomanip>

namespace DPI {

// ============================================================================
// Sequence Space Arithmetic (RFC 793 / RFC 1323)
// Handles 32-bit sequence wraparound across the 0xFFFFFFFF -> 0 boundary
// ============================================================================
inline bool seq_lt(uint32_t s1, uint32_t s2) {
    return static_cast<int32_t>(s1 - s2) < 0;
}

inline bool seq_lte(uint32_t s1, uint32_t s2) {
    return static_cast<int32_t>(s1 - s2) <= 0;
}

inline bool seq_gt(uint32_t s1, uint32_t s2) {
    return static_cast<int32_t>(s1 - s2) > 0;
}

inline bool seq_gte(uint32_t s1, uint32_t s2) {
    return static_cast<int32_t>(s1 - s2) >= 0;
}

// Custom comparator for std::map keyed by sequence number
struct SeqLessThan {
    bool operator()(uint32_t a, uint32_t b) const {
        return seq_lt(a, b);
    }
};

// ============================================================================
// TCP Stream State & Overlap Policy
// ============================================================================
enum class TCPStreamState {
    NEW,
    SYN_SEEN,
    ESTABLISHED,
    FIN_SEEN,
    CLOSED,
    RESET,
    TIMED_OUT
};

std::string tcpStreamStateToString(TCPStreamState state);

enum class StreamOverlapPolicy {
    FIRST_COME_BSD  // Keep previously accepted bytes; trim/discard newer overlapping bytes
};

std::string streamOverlapPolicyToString(StreamOverlapPolicy policy);

// ============================================================================
// TCP Segment Buffer Node
// ============================================================================
struct TCPSegment {
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint8_t flags = 0;
    std::vector<uint8_t> payload;
    uint64_t timestamp_us = 0;
    
    size_t length() const { return payload.size(); }
    uint32_t end_seq() const { return seq + static_cast<uint32_t>(payload.size()); }
};

// ============================================================================
// Stream Directional Telemetry
// ============================================================================
struct StreamDirectionStats {
    uint64_t bytes_reassembled = 0;
    uint32_t segments_received = 0;
    uint32_t out_of_order_count = 0;
    uint32_t retrans_count = 0;
    uint32_t overlap_count = 0;
    uint32_t conflict_count = 0;
    uint32_t gap_count = 0;

    bool syn_seen = false;
    bool fin_seen = false;
    bool rst_seen = false;
    bool is_complete = false;

    uint32_t initial_seq = 0;
    uint32_t base_seq = 0;          // First payload byte sequence (ISN + 1 if SYN)
    uint32_t next_expected_seq = 0;
    uint32_t fin_seq = 0;
};

// ============================================================================
// Reassembly Configuration
// ============================================================================
struct StreamReassemblyConfig {
    size_t max_buffered_bytes_per_stream = 1048576; // 1 MB per direction
    size_t max_segments_per_stream = 256;          // Max out-of-order segments
    size_t max_total_reassembly_memory = 67108864; // 64 MB total across engine
    size_t max_active_streams = 20000;             // Max concurrent active streams
    uint64_t stream_inactivity_timeout_us = 60000000ULL; // 60 seconds
    
    bool enable_http_parsing = true;
    bool enable_tls_parsing = true;
    bool enable_dns_parsing = true;
    
    StreamOverlapPolicy overlap_policy = StreamOverlapPolicy::FIRST_COME_BSD;

    bool validate() const;
};

// ============================================================================
// HTTP/1.x Metadata Structures
// ============================================================================
struct HTTPMessage {
    bool is_request = false;
    std::string method;          // e.g. GET, POST, PUT, DELETE
    std::string uri;             // e.g. /index.html?query=1
    std::string version;         // e.g. HTTP/1.1
    int status_code = 0;         // e.g. 200, 404
    std::string reason_phrase;   // e.g. OK, Not Found
    std::string host;
    std::string user_agent;
    std::string content_type;
    int64_t content_length = -1;
    bool is_chunked = false;
    std::map<std::string, std::string> headers;
    size_t body_bytes_seen = 0;
    bool is_complete = false;
};

// ============================================================================
// TLS Stream Metadata
// ============================================================================
struct TLSStreamMetadata {
    std::string sni;
    std::string alpn;                           // e.g. "h2", "http/1.1"
    std::vector<std::string> supported_versions; // e.g. "TLS 1.3", "TLS 1.2"
    std::vector<uint16_t> cipher_suites;
    uint16_t record_version = 0;
    uint16_t client_version = 0;
    bool has_client_hello = false;
    bool is_handshake_complete = false;
    bool has_encrypted_data = false;
    uint64_t encrypted_record_count = 0;
    uint64_t encrypted_bytes_count = 0;
};

// ============================================================================
// DNS Intelligence Structures
// ============================================================================
struct DNSQueryRecord {
    std::string name;
    uint16_t type = 0;           // 1=A, 28=AAAA, 5=CNAME, 15=MX, 16=TXT, etc.
    std::string type_name;
    uint16_t qclass = 1;         // 1=IN
};

struct DNSAnswerRecord {
    std::string name;
    uint16_t type = 0;
    std::string type_name;
    uint32_t ttl = 0;
    std::string rdata_string;    // Resolved IP address or canonical hostname
};

struct DNSMessage {
    uint16_t tx_id = 0;
    bool is_response = false;
    uint8_t opcode = 0;
    uint8_t rcode = 0;
    std::string rcode_name;      // NOERROR, NXDOMAIN, SERVFAIL, REFUSED, etc.
    bool aa = false;             // Authoritative Answer
    bool tc = false;             // Truncated
    bool rd = false;             // Recursion Desired
    bool ra = false;             // Recursion Available
    std::vector<DNSQueryRecord> queries;
    std::vector<DNSAnswerRecord> answers;
    uint64_t timestamp_us = 0;
    uint64_t latency_us = 0;     // Computed when response matches query
};

// ============================================================================
// Stream Summary Record (Exportable)
// ============================================================================
struct StreamRecordSummary {
    uint64_t stream_id = 0;
    FiveTuple tuple;
    TCPStreamState state = TCPStreamState::NEW;
    StreamDirectionStats fwd;
    StreamDirectionStats rev;
    
    // Extracted protocols
    std::vector<HTTPMessage> http_messages;
    TLSStreamMetadata tls_meta;
    
    // Reassembled stream payloads (Phase 3.4 signature matching)
    std::vector<uint8_t> fwd_payload;
    std::vector<uint8_t> rev_payload;
    
    std::string toJson() const;
    std::string toCsvRow() const;
    static std::string csvHeader();
};

} // namespace DPI

#endif // DPI_STREAM_TYPES_H
