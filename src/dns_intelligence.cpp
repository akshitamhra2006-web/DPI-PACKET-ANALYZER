#include "dns_intelligence.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <set>

namespace DPI {

uint16_t DNSParser::readUint16BE(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}

uint32_t DNSParser::readUint32BE(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           p[3];
}

std::string DNSParser::rcodeToString(uint8_t rcode) {
    switch (rcode) {
        case 0: return "NOERROR";
        case 1: return "FORMERR";
        case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN";
        case 4: return "NOTIMP";
        case 5: return "REFUSED";
        case 6: return "YXDOMAIN";
        case 7: return "YXRRSET";
        case 8: return "NXRRSET";
        case 9: return "NOTAUTH";
        case 10: return "NOTZONE";
        default: return "RCODE_" + std::to_string(rcode);
    }
}

std::string DNSParser::qtypeToString(uint16_t qtype) {
    switch (qtype) {
        case 1:   return "A";
        case 2:   return "NS";
        case 5:   return "CNAME";
        case 6:   return "SOA";
        case 12:  return "PTR";
        case 15:  return "MX";
        case 16:  return "TXT";
        case 28:  return "AAAA";
        case 33:  return "SRV";
        case 255: return "ANY";
        default:  return "TYPE_" + std::to_string(qtype);
    }
}

bool DNSParser::parseDomainName(const uint8_t* data, size_t len, size_t& offset,
                                std::string& domain, int depth) {
    if (depth > static_cast<int>(MAX_NAME_HOPS) || offset >= len) {
        return false;
    }

    bool jumped = false;
    size_t original_offset = offset;
    size_t curr = offset;
    int hops = 0;
    std::set<size_t> visited_pointers;

    while (curr < len && hops < static_cast<int>(MAX_NAME_HOPS)) {
        uint8_t label_len = data[curr];

        if (label_len == 0) {
            // Null root terminator
            if (!jumped) {
                offset = curr + 1;
            } else {
                offset = original_offset;
            }
            return true;
        }

        // Compression Pointer (0xC0XX)
        if ((label_len & 0xC0) == 0xC0) {
            if (curr + 1 >= len) return false;
            uint16_t ptr_offset = ((static_cast<uint16_t>(label_len & 0x3F)) << 8) | data[curr + 1];

            // Validate pointer bounds: must point to a prior byte within data
            if (ptr_offset >= len) return false;
            if (visited_pointers.find(ptr_offset) != visited_pointers.end()) {
                return false; // Pointer loop detected!
            }
            visited_pointers.insert(ptr_offset);

            if (!jumped) {
                original_offset = curr + 2;
                jumped = true;
            }

            curr = ptr_offset;
            hops++;
            continue;
        }

        // Regular uncompressed label
        if (label_len > MAX_LABEL_LEN || curr + 1 + label_len > len) {
            return false;
        }

        if (!domain.empty()) {
            domain += '.';
        }

        if (domain.size() + label_len > MAX_DOMAIN_LEN) {
            return false; // Domain exceeds RFC 1035 max length
        }

        domain.append(reinterpret_cast<const char*>(data + curr + 1), label_len);
        curr += 1 + label_len;
    }

    if (jumped) {
        offset = original_offset;
    } else {
        offset = curr;
    }

    return hops < static_cast<int>(MAX_NAME_HOPS);
}

std::optional<DNSMessage> DNSParser::parseUDP(const uint8_t* data, size_t len, uint64_t timestamp_us) {
    if (!data || len < 12) return std::nullopt;

    DNSMessage msg;
    msg.timestamp_us = timestamp_us;
    msg.tx_id = readUint16BE(data);

    uint16_t flags = readUint16BE(data + 2);
    msg.is_response = (flags & 0x8000) != 0;
    msg.opcode = static_cast<uint8_t>((flags >> 11) & 0x0F);
    msg.aa = (flags & 0x0400) != 0;
    msg.tc = (flags & 0x0200) != 0;
    msg.rd = (flags & 0x0100) != 0;
    msg.ra = (flags & 0x0080) != 0;
    msg.rcode = static_cast<uint8_t>(flags & 0x000F);
    msg.rcode_name = rcodeToString(msg.rcode);

    uint16_t qdcount = readUint16BE(data + 4);
    uint16_t ancount = readUint16BE(data + 6);

    size_t offset = 12;

    // Parse Questions
    for (uint16_t i = 0; i < qdcount && offset < len; ++i) {
        DNSQueryRecord q;
        if (!parseDomainName(data, len, offset, q.name)) {
            break;
        }
        if (offset + 4 > len) break;
        q.type = readUint16BE(data + offset);
        q.type_name = qtypeToString(q.type);
        q.qclass = readUint16BE(data + offset + 2);
        offset += 4;
        msg.queries.push_back(std::move(q));
    }

    // Parse Answers (if response)
    for (uint16_t i = 0; i < ancount && offset < len; ++i) {
        DNSAnswerRecord a;
        if (!parseDomainName(data, len, offset, a.name)) {
            break;
        }
        if (offset + 10 > len) break;

        a.type = readUint16BE(data + offset);
        a.type_name = qtypeToString(a.type);
        // class = readUint16BE(data + offset + 2);
        a.ttl = readUint32BE(data + offset + 4);
        uint16_t rdlength = readUint16BE(data + offset + 8);
        offset += 10;

        if (offset + rdlength > len) break;

        const uint8_t* rdata = data + offset;

        // Parse common RDATA types
        if (a.type == 1 && rdlength == 4) {
            // Type A: IPv4 address
            std::ostringstream ss;
            ss << static_cast<int>(rdata[0]) << "."
               << static_cast<int>(rdata[1]) << "."
               << static_cast<int>(rdata[2]) << "."
               << static_cast<int>(rdata[3]);
            a.rdata_string = ss.str();
        } else if (a.type == 28 && rdlength == 16) {
            // Type AAAA: IPv6 address
            std::ostringstream ss;
            for (int b = 0; b < 16; b += 2) {
                uint16_t w = (static_cast<uint16_t>(rdata[b]) << 8) | rdata[b + 1];
                if (b > 0) ss << ":";
                ss << std::hex << w;
            }
            a.rdata_string = ss.str();
        } else if (a.type == 5 || a.type == 2 || a.type == 12) {
            // CNAME, NS, or PTR
            size_t cname_offset = offset;
            std::string target_domain;
            if (parseDomainName(data, len, cname_offset, target_domain)) {
                a.rdata_string = target_domain;
            }
        } else if (a.type == 16 && rdlength > 0) {
            // TXT
            uint8_t txt_len = rdata[0];
            if (txt_len + 1 <= rdlength) {
                a.rdata_string = std::string(reinterpret_cast<const char*>(rdata + 1), txt_len);
            }
        }

        offset += rdlength;
        msg.answers.push_back(std::move(a));
    }

    return msg;
}

std::vector<DNSMessage> DNSParser::parseTCPStream(const uint8_t* data, size_t len, uint64_t timestamp_us) {
    std::vector<DNSMessage> messages;
    size_t offset = 0;

    // RFC 1035 §4.2.2: 2-byte big-endian length prefix
    while (offset + 2 <= len) {
        uint16_t msg_len = readUint16BE(data + offset);
        offset += 2;

        if (offset + msg_len > len) {
            break; // Truncated or incomplete TCP DNS message
        }

        auto msg = parseUDP(data + offset, msg_len, timestamp_us);
        if (msg) {
            messages.push_back(*msg);
        }
        offset += msg_len;
    }

    return messages;
}

// ============================================================================
// DNSCorrelator Implementation
// ============================================================================

void DNSCorrelator::processDNSMessage(const FiveTuple& tuple, DNSMessage& msg) {
    if (!msg.is_response) {
        // Query from client
        stats_.total_queries++;
        QueryKey key{tuple.src_ip, tuple.src_port, msg.tx_id};
        PendingQuery pq;
        pq.tx_id = msg.tx_id;
        pq.query_name = msg.queries.empty() ? "" : msg.queries.front().name;
        pq.query_type = msg.queries.empty() ? 0 : msg.queries.front().type;
        pq.timestamp_us = msg.timestamp_us;
        pending_queries_[key] = pq;
    } else {
        // Response from server to client
        stats_.total_responses++;
        uint32_t client_ip = tuple.dst_ip;
        uint16_t client_port = tuple.dst_port;

        client_response_counts_[client_ip]++;

        if (msg.rcode == 0) {
            stats_.noerror_count++;
        } else if (msg.rcode == 3) {
            stats_.nxdomain_count++;
            client_nxdomain_counts_[client_ip]++;
        } else if (msg.rcode == 2) {
            stats_.servfail_count++;
        } else if (msg.rcode == 5) {
            stats_.refused_count++;
        }

        // Try to match pending query
        QueryKey key{client_ip, client_port, msg.tx_id};
        auto it = pending_queries_.find(key);
        if (it != pending_queries_.end()) {
            if (msg.timestamp_us >= it->second.timestamp_us) {
                msg.latency_us = msg.timestamp_us - it->second.timestamp_us;
                stats_.total_latency_us += static_cast<double>(msg.latency_us);
                stats_.correlated_count++;
            }
            pending_queries_.erase(it);
        }
    }
}

bool DNSCorrelator::isNXDOMAINBurst(uint32_t client_ip, uint32_t min_count, double min_ratio) const {
    auto nx_it = client_nxdomain_counts_.find(client_ip);
    if (nx_it == client_nxdomain_counts_.end() || nx_it->second < min_count) {
        return false;
    }
    auto tot_it = client_response_counts_.find(client_ip);
    if (tot_it == client_response_counts_.end() || tot_it->second == 0) {
        return false;
    }
    double ratio = static_cast<double>(nx_it->second) / tot_it->second;
    return ratio >= min_ratio;
}

} // namespace DPI
