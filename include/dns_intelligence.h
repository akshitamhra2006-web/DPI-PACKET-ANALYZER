#ifndef DPI_DNS_INTELLIGENCE_H
#define DPI_DNS_INTELLIGENCE_H

#include "stream_types.h"
#include <vector>
#include <string>
#include <optional>
#include <unordered_map>
#include <map>

namespace DPI {

class DNSParser {
public:
    // Parse UDP DNS payload (12-byte header directly)
    static std::optional<DNSMessage> parseUDP(const uint8_t* data, size_t len, uint64_t timestamp_us = 0);

    // Parse TCP DNS stream (2-byte length prefix + message)
    static std::vector<DNSMessage> parseTCPStream(const uint8_t* data, size_t len, uint64_t timestamp_us = 0);

    // Helper: convert RCODE to name
    static std::string rcodeToString(uint8_t rcode);

    // Helper: convert QTYPE to name
    static std::string qtypeToString(uint16_t qtype);

    // Safe decompression of DNS names with loop detection & recursion limit
    static bool parseDomainName(const uint8_t* data, size_t len, size_t& offset,
                                std::string& domain, int depth = 0);

private:
    static constexpr size_t MAX_NAME_HOPS = 16;
    static constexpr size_t MAX_DOMAIN_LEN = 255;
    static constexpr size_t MAX_LABEL_LEN = 63;

    static uint16_t readUint16BE(const uint8_t* p);
    static uint32_t readUint32BE(const uint8_t* p);
};

// ============================================================================
// DNS Correlator
// Matches DNS requests with responses, computes transaction latency, and tracks
// NXDOMAIN / SERVFAIL error patterns.
// ============================================================================
class DNSCorrelator {
public:
    struct PendingQuery {
        uint16_t tx_id;
        std::string query_name;
        uint16_t query_type;
        uint64_t timestamp_us;
    };

    struct Stats {
        uint64_t total_queries = 0;
        uint64_t total_responses = 0;
        uint64_t noerror_count = 0;
        uint64_t nxdomain_count = 0;
        uint64_t servfail_count = 0;
        uint64_t refused_count = 0;
        uint64_t correlated_count = 0;
        double total_latency_us = 0.0;

        double mean_latency_us() const {
            return correlated_count > 0 ? (total_latency_us / correlated_count) : 0.0;
        }

        double nxdomain_ratio() const {
            return total_responses > 0 ? static_cast<double>(nxdomain_count) / total_responses : 0.0;
        }
    };

    DNSCorrelator() = default;

    // Process a parsed DNS message and correlate with queries
    void processDNSMessage(const FiveTuple& tuple, DNSMessage& msg);

    const Stats& getStats() const { return stats_; }

    // Check if a client has an abnormally high NXDOMAIN failure count / ratio
    bool isNXDOMAINBurst(uint32_t client_ip, uint32_t min_count = 5, double min_ratio = 0.50) const;

    const std::map<uint32_t, uint32_t>& getClientNXDOMAINCounts() const {
        return client_nxdomain_counts_;
    }

private:
    Stats stats_;

    // Composite key: client_ip (canonical), client_port, tx_id
    struct QueryKey {
        uint32_t client_ip;
        uint16_t client_port;
        uint16_t tx_id;

        bool operator<(const QueryKey& other) const {
            if (client_ip != other.client_ip) return client_ip < other.client_ip;
            if (client_port != other.client_port) return client_port < other.client_port;
            return tx_id < other.tx_id;
        }
    };

    std::map<QueryKey, PendingQuery> pending_queries_;
    std::map<uint32_t, uint32_t> client_nxdomain_counts_; // client_ip -> count
    std::map<uint32_t, uint32_t> client_response_counts_; // client_ip -> total
};

} // namespace DPI

#endif // DPI_DNS_INTELLIGENCE_H
