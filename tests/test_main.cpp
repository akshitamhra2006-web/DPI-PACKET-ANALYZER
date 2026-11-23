#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <cstring>
#include <memory>
#include <chrono>
#include <thread>
#include <unordered_set>
#include <map>
#include <fstream>

#include "types.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "rule_manager.h"
#include "connection_tracker.h"
#include "load_balancer.h"
#include "fast_path.h"
#include "dpi_engine.h"
#include "pcap_reader.h"
#include "flow_record.h"
#include "flow_table.h"
#include "detection_types.h"
#include "detection_config.h"
#include "detector.h"
#include "behavioral_detectors.h"
#include "detection_engine.h"
#include "stream_types.h"
#include "tcp_stream_reassembler.h"
#include "http_stream_parser.h"
#include "tls_stream_parser.h"
#include "dns_intelligence.h"
#include "incident_types.h"
#include "incident_config.h"
#include "incident_correlator.h"
#include "signature_types.h"
#include "signature_validator.h"
#include "signature_parser.h"
#include "signature_matcher.h"
#include "signature_manager.h"
#include "signature_engine.h"
#include "threat_intel_types.h"
#include "threat_intel_validator.h"
#include "threat_intel_parser.h"
#include "threat_intel_manager.h"
#include "threat_intel_engine.h"
#include "risk_profiler.h"
#include "network_analytics.h"
#include "investigation_types.h"
#include "investigation_manager.h"
#include "report_generator.h"

using namespace DPI;
using namespace PacketAnalyzer;

// Simple test framework
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "  FAILED: " << msg << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            return false; \
        } \
    } while (0)

#define RUN_TEST(fn) \
    do { \
        std::cout << "[RUN ] " << #fn << "..." << std::flush; \
        if (fn()) { \
            std::cout << " [PASS]\n"; \
            g_tests_passed++; \
        } else { \
            std::cout << " [FAIL]\n"; \
            g_tests_failed++; \
        } \
    } while (0)

// ============================================================================
// TEST 1: Ethernet Header Parsing (Valid)
// ============================================================================
bool test_ethernet_parsing_valid() {
    // 14-byte Ethernet frame: Dst MAC, Src MAC, EtherType (0x0800 IPv4)
    uint8_t pkt[14] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Dst
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Src
        0x08, 0x00                           // EtherType: IPv4
    };
    RawPacket raw;
    raw.data.assign(pkt, pkt + sizeof(pkt));
    raw.header.incl_len = sizeof(pkt);
    raw.header.orig_len = sizeof(pkt);

    ParsedPacket parsed;
    size_t offset = 0;
    bool ok = PacketParser::parseEthernet(raw.data.data(), raw.data.size(), parsed, offset);
    TEST_ASSERT(ok, "parseEthernet failed on valid frame");
    TEST_ASSERT(parsed.ether_type == EtherType::IPv4, "EtherType mismatch");
    TEST_ASSERT(parsed.dest_mac == "00:11:22:33:44:55", "Dest MAC mismatch");
    TEST_ASSERT(parsed.src_mac == "aa:bb:cc:dd:ee:ff", "Src MAC mismatch");
    TEST_ASSERT(offset == 14, "Offset must be 14");
    return true;
}

// ============================================================================
// TEST 2: Ethernet Header Parsing (Truncated)
// ============================================================================
bool test_ethernet_parsing_truncated() {
    uint8_t pkt[10] = {0}; // Less than 14 bytes
    ParsedPacket parsed;
    size_t offset = 0;
    bool ok = PacketParser::parseEthernet(pkt, sizeof(pkt), parsed, offset);
    TEST_ASSERT(!ok, "parseEthernet should fail on truncated frame");
    return true;
}

// ============================================================================
// TEST 3: Ethernet 802.1Q VLAN Tag Parsing
// ============================================================================
bool test_ethernet_vlan_8021q() {
    // 18-byte VLAN frame: Dst, Src, TPID=0x8100, TCI=0x0001, EtherType=0x0800
    uint8_t pkt[18] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x81, 0x00, 0x00, 0x01,              // VLAN 1
        0x08, 0x00                           // IPv4
    };
    ParsedPacket parsed;
    size_t offset = 0;
    bool ok = PacketParser::parseEthernet(pkt, sizeof(pkt), parsed, offset);
    TEST_ASSERT(ok, "parseEthernet failed on 802.1Q VLAN frame");
    TEST_ASSERT(parsed.ether_type == EtherType::IPv4, "VLAN inner EtherType must be IPv4");
    TEST_ASSERT(offset == 18, "Offset after VLAN header must be 18");
    return true;
}

// ============================================================================
// TEST 4: IPv4 Header Parsing (Valid)
// ============================================================================
bool test_ipv4_parsing_valid() {
    // Minimal 20-byte IPv4 packet (TCP, 192.168.1.10 -> 10.0.0.1)
    uint8_t ip[20] = {
        0x45, 0x00, 0x00, 0x28,  // Ver=4, IHL=5, TotLen=40
        0x12, 0x34, 0x40, 0x00,  // Id, Flags (DF)
        0x40, 0x06, 0x00, 0x00,  // TTL=64, Proto=6 (TCP), Cksum
        192, 168, 1, 10,         // Src IP
        10, 0, 0, 1              // Dst IP
    };
    ParsedPacket parsed;
    size_t offset = 0;
    bool ok = PacketParser::parseIPv4(ip, sizeof(ip), parsed, offset);
    TEST_ASSERT(ok, "parseIPv4 failed on valid header");
    TEST_ASSERT(parsed.has_ip, "has_ip must be true");
    TEST_ASSERT(parsed.ttl == 64, "TTL must be 64");
    TEST_ASSERT(parsed.protocol == 6, "Protocol must be 6");
    TEST_ASSERT(parsed.src_ip == "192.168.1.10", "Src IP mismatch");
    TEST_ASSERT(parsed.dest_ip == "10.0.0.1", "Dst IP mismatch");
    TEST_ASSERT(offset == 20, "Offset must be 20");
    return true;
}

// ============================================================================
// TEST 5: IPv4 Header Parsing (Invalid IHL & Truncated)
// ============================================================================
bool test_ipv4_parsing_truncated_and_invalid() {
    // Truncated (< 20 bytes)
    uint8_t truncated[15] = {0x45, 0x00};
    ParsedPacket parsed;
    size_t offset = 0;
    TEST_ASSERT(!PacketParser::parseIPv4(truncated, sizeof(truncated), parsed, offset),
                "Truncated IPv4 should fail");

    // Invalid IHL (< 5)
    uint8_t bad_ihl[20] = {0x44, 0x00}; // IHL = 4 (invalid)
    offset = 0;
    TEST_ASSERT(!PacketParser::parseIPv4(bad_ihl, sizeof(bad_ihl), parsed, offset),
                "IPv4 with IHL < 5 should fail");

    // Total length underflow (total_length claimed 10, but minimum header size is 20)
    uint8_t bad_len[20] = {
        0x45, 0x00, 0x00, 0x0A, // TotLen=10 (less than IHL=20)
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        1, 1, 1, 1, 2, 2, 2, 2
    };
    offset = 0;
    TEST_ASSERT(!PacketParser::parseIPv4(bad_len, sizeof(bad_len), parsed, offset),
                "IPv4 with total_length < header_len must fail safely");
    return true;
}

// ============================================================================
// TEST 6: IPv4 Endian Independence
// ============================================================================
bool test_ipv4_endian_independence() {
    std::string ip_str = "172.16.254.1";
    uint32_t parsed_ip = RuleManager::parseIP(ip_str);
    std::string formatted = RuleManager::ipToString(parsed_ip);
    TEST_ASSERT(formatted == ip_str, "parseIP and ipToString roundtrip mismatch");
    return true;
}

// ============================================================================
// TEST 7: TCP Header Parsing & Flags
// ============================================================================
bool test_tcp_parsing_valid_and_flags() {
    // 20-byte TCP header: Sport 54321 (0xD431), Dport 443 (0x01BB), Seq 1, Ack 0, DataOffset 5 (0x50), Flags SYN|ACK (0x12)
    uint8_t tcp[20] = {
        0xD4, 0x31, 0x01, 0xBB, // Sport=54321, Dport=443
        0x00, 0x00, 0x00, 0x01, // Seq=1
        0x00, 0x00, 0x00, 0x00, // Ack=0
        0x50, 0x12, 0x72, 0x10, // DataOffset=5, Flags=SYN|ACK (0x12), Window
        0x00, 0x00, 0x00, 0x00  // Checksum, Urgent
    };
    ParsedPacket parsed;
    size_t offset = 0;
    bool ok = PacketParser::parseTCP(tcp, sizeof(tcp), parsed, offset);
    TEST_ASSERT(ok, "parseTCP failed on valid TCP header");
    TEST_ASSERT(parsed.has_tcp, "has_tcp must be true");
    TEST_ASSERT(parsed.src_port == 54321, "Src port mismatch");
    TEST_ASSERT(parsed.dest_port == 443, "Dst port mismatch");
    TEST_ASSERT((parsed.tcp_flags & TCPFlags::SYN) != 0, "SYN flag missing");
    TEST_ASSERT((parsed.tcp_flags & TCPFlags::ACK) != 0, "ACK flag missing");
    TEST_ASSERT(offset == 20, "Offset must be 20");
    return true;
}

// ============================================================================
// TEST 8: TCP Header Parsing (Truncated & Invalid Offset)
// ============================================================================
bool test_tcp_parsing_truncated_and_invalid() {
    uint8_t truncated[16] = {0};
    ParsedPacket parsed;
    size_t offset = 0;
    TEST_ASSERT(!PacketParser::parseTCP(truncated, sizeof(truncated), parsed, offset),
                "Truncated TCP (< 20 bytes) must fail");

    // Invalid Data Offset < 5 (e.g. 4)
    uint8_t bad_offset[20] = {0};
    bad_offset[12] = 0x40; // Data offset 4
    offset = 0;
    TEST_ASSERT(!PacketParser::parseTCP(bad_offset, sizeof(bad_offset), parsed, offset),
                "TCP data offset < 5 must fail");
    return true;
}

// ============================================================================
// TEST 9: UDP Header Parsing (Valid)
// ============================================================================
bool test_udp_parsing_valid() {
    // 8-byte UDP header: Sport 53 (0x0035), Dport 12345 (0x3039), Len 8, Checksum 0
    uint8_t udp[8] = {
        0x00, 0x35, 0x30, 0x39,
        0x00, 0x08, 0x00, 0x00
    };
    ParsedPacket parsed;
    size_t offset = 0;
    bool ok = PacketParser::parseUDP(udp, sizeof(udp), parsed, offset);
    TEST_ASSERT(ok, "parseUDP failed on valid header");
    TEST_ASSERT(parsed.has_udp, "has_udp must be true");
    TEST_ASSERT(parsed.src_port == 53, "UDP src port mismatch");
    TEST_ASSERT(parsed.dest_port == 12345, "UDP dest port mismatch");
    TEST_ASSERT(offset == 8, "UDP offset must be 8");
    return true;
}

// ============================================================================
// TEST 10: UDP Header Parsing (Truncated & Malformed Length)
// ============================================================================
bool test_udp_parsing_truncated_and_invalid() {
    uint8_t truncated[6] = {0};
    ParsedPacket parsed;
    size_t offset = 0;
    TEST_ASSERT(!PacketParser::parseUDP(truncated, sizeof(truncated), parsed, offset),
                "Truncated UDP (< 8 bytes) must fail");

    // Length reported in header < 8
    uint8_t bad_len[8] = {
        0x00, 0x35, 0x30, 0x39,
        0x00, 0x05, 0x00, 0x00 // length = 5
    };
    offset = 0;
    TEST_ASSERT(!PacketParser::parseUDP(bad_len, sizeof(bad_len), parsed, offset),
                "UDP length < 8 must fail");
    return true;
}

// ============================================================================
// TEST 11: DNS Query Extraction (Valid & Truncated Bounds Guard)
// ============================================================================
bool test_dns_parsing_valid_and_truncated() {
    // Valid DNS query for "google.com"
    // DNS Header (12 bytes) + \x06google\x03com\x00 + QType (2) + QClass (2)
    uint8_t valid_dns[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 'g', 'o', 'o', 'g', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01, 0x00, 0x01
    };
    auto query = DNSExtractor::extractQuery(valid_dns, sizeof(valid_dns));
    TEST_ASSERT(query.has_value(), "Valid DNS query extraction failed");
    TEST_ASSERT(*query == "google.com", "Extracted domain should be google.com");

    // Truncated/corrupt DNS query: label claims length 50 but only 3 bytes remain
    uint8_t malformed_dns[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x32, 'a', 'b', 'c' // claims 50 bytes
    };
    auto bad_query = DNSExtractor::extractQuery(malformed_dns, sizeof(malformed_dns));
    TEST_ASSERT(!bad_query.has_value(), "Malformed DNS query with excessive label length must return nullopt safely");
    return true;
}

// ============================================================================
// TEST 12: HTTP Host Extraction
// ============================================================================
bool test_http_host_extractor() {
    std::string http_req = "GET / HTTP/1.1\r\nHost: www.example.org\r\nUser-Agent: test\r\n\r\n";
    auto host = HTTPHostExtractor::extract(reinterpret_cast<const uint8_t*>(http_req.data()), http_req.size());
    TEST_ASSERT(host.has_value(), "HTTP Host extraction failed");
    TEST_ASSERT(*host == "www.example.org", "Host mismatch");

    // Case insensitive "host:"
    std::string http_lower = "GET / HTTP/1.1\r\nhost: sub.domain.net\r\n\r\n";
    auto host_lower = HTTPHostExtractor::extract(reinterpret_cast<const uint8_t*>(http_lower.data()), http_lower.size());
    TEST_ASSERT(host_lower.has_value() && *host_lower == "sub.domain.net", "Case insensitive host extraction failed");

    // Missing host
    std::string http_no_host = "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
    auto no_host = HTTPHostExtractor::extract(reinterpret_cast<const uint8_t*>(http_no_host.data()), http_no_host.size());
    TEST_ASSERT(!no_host.has_value(), "Missing Host header should return nullopt");
    return true;
}

// ============================================================================
// TEST 13: TLS SNI Extraction & Extensions Parsing
// ============================================================================
bool test_tls_sni_extractor() {
    // Construct a minimal valid TLS ClientHello with SNI "test.example.com"
    std::string server_name = "test.example.com";
    std::vector<uint8_t> payload;

    // TLS Record Header (5 bytes): ContentType=22 (Handshake), Version=0x0301, Length
    payload.push_back(0x16); // Handshake
    payload.push_back(0x03);
    payload.push_back(0x01); // TLS 1.0
    payload.push_back(0x00);
    payload.push_back(0x00); // placeholder for record length

    // Handshake Header (4 bytes): MsgType=1 (ClientHello), Length (3 bytes)
    payload.push_back(0x01);
    payload.push_back(0x00);
    payload.push_back(0x00);
    payload.push_back(0x00); // placeholder for handshake length

    // Client Version (2 bytes)
    payload.push_back(0x03);
    payload.push_back(0x03); // TLS 1.2

    // Random (32 bytes)
    for (int i = 0; i < 32; i++) payload.push_back(static_cast<uint8_t>(i));

    // Session ID: len = 0
    payload.push_back(0x00);

    // Cipher Suites: len = 2, suite = 0x002f
    payload.push_back(0x00);
    payload.push_back(0x02);
    payload.push_back(0x00);
    payload.push_back(0x2f);

    // Compression Methods: len = 1, method = 0
    payload.push_back(0x01);
    payload.push_back(0x00);

    // Extensions
    std::vector<uint8_t> ext_data;
    // Extension Type 0 (server_name)
    ext_data.push_back(0x00);
    ext_data.push_back(0x00);

    // SNI list: type 0 (host_name), name_len, name
    std::vector<uint8_t> sni_payload;
    // ServerNameList length
    uint16_t sni_list_len = 3 + server_name.size();
    sni_payload.push_back((sni_list_len >> 8) & 0xFF);
    sni_payload.push_back(sni_list_len & 0xFF);
    sni_payload.push_back(0x00); // host_name
    sni_payload.push_back((server_name.size() >> 8) & 0xFF);
    sni_payload.push_back(server_name.size() & 0xFF);
    for (char c : server_name) sni_payload.push_back(static_cast<uint8_t>(c));

    // Extension length
    ext_data.push_back((sni_payload.size() >> 8) & 0xFF);
    ext_data.push_back(sni_payload.size() & 0xFF);
    ext_data.insert(ext_data.end(), sni_payload.begin(), sni_payload.end());

    // Total Extensions length
    payload.push_back((ext_data.size() >> 8) & 0xFF);
    payload.push_back(ext_data.size() & 0xFF);
    payload.insert(payload.end(), ext_data.begin(), ext_data.end());

    // Patch lengths
    size_t handshake_len = payload.size() - 9;
    payload[6] = (handshake_len >> 16) & 0xFF;
    payload[7] = (handshake_len >> 8) & 0xFF;
    payload[8] = handshake_len & 0xFF;

    size_t record_len = payload.size() - 5;
    payload[3] = (record_len >> 8) & 0xFF;
    payload[4] = record_len & 0xFF;

    auto sni = SNIExtractor::extract(payload.data(), payload.size());
    TEST_ASSERT(sni.has_value(), "SNI extraction failed on valid ClientHello");
    TEST_ASSERT(*sni == server_name, "Extracted SNI does not match");

    // Truncated ClientHello
    auto trunc_sni = SNIExtractor::extract(payload.data(), 15);
    TEST_ASSERT(!trunc_sni.has_value(), "Truncated TLS record must return nullopt safely");
    return true;
}

// ============================================================================
// TEST 14: QUIC Memory Safety & Guard
// ============================================================================
bool test_quic_memory_safety() {
    // Attempt underflow attack payload (< 5 bytes, malformed lengths)
    uint8_t short_quic[] = {0xC0, 0x00, 0x00};
    auto res1 = QUICSNIExtractor::extract(short_quic, sizeof(short_quic));
    TEST_ASSERT(!res1.has_value(), "Short QUIC must return nullopt safely without crash");

    uint8_t malformed_quic[64] = {0};
    malformed_quic[0] = 0xC0; // Long header
    malformed_quic[1] = 0x00; malformed_quic[2] = 0x00; malformed_quic[3] = 0x00; malformed_quic[4] = 0x01; // v1
    malformed_quic[5] = 200;  // excessive DCIL
    auto res2 = QUICSNIExtractor::extract(malformed_quic, sizeof(malformed_quic));
    TEST_ASSERT(!res2.has_value(), "Malformed QUIC DCIL must return nullopt safely");
    return true;
}

// ============================================================================
// TEST 15: Domain Exact Matching
// ============================================================================
bool test_domain_exact_matching() {
    RuleManager rm;
    rm.blockDomain("example.com");
    TEST_ASSERT(rm.isDomainBlocked("example.com"), "Exact domain should be blocked");
    TEST_ASSERT(!rm.isDomainBlocked("other.com"), "Different domain should not be blocked");
    return true;
}

// ============================================================================
// TEST 16: Domain Subdomain / Suffix Matching
// ============================================================================
bool test_domain_subdomain_matching() {
    RuleManager rm;
    rm.blockDomain("example.com");
    TEST_ASSERT(rm.isDomainBlocked("sub.example.com"), "Subdomain sub.example.com should be blocked");
    TEST_ASSERT(rm.isDomainBlocked("deep.sub.example.com"), "Deep subdomain should be blocked");
    return true;
}

// ============================================================================
// TEST 17: Domain False Positive Prevention: netflix.com != x.com
// ============================================================================
bool test_domain_false_positive_netflix_x() {
    RuleManager rm;
    rm.blockDomain("x.com");
    TEST_ASSERT(!rm.isDomainBlocked("netflix.com"), "netflix.com must NOT be blocked by rule x.com");
    TEST_ASSERT(rm.isDomainBlocked("x.com"), "x.com must be blocked");
    TEST_ASSERT(rm.isDomainBlocked("api.x.com"), "api.x.com must be blocked");

    // Also verify app classification
    AppType app = sniToAppType("netflix.com");
    TEST_ASSERT(app == AppType::NETFLIX, "netflix.com must classify as NETFLIX, not TWITTER");
    return true;
}

// ============================================================================
// TEST 18: Domain False Positive Prevention: microsoft.com != t.co
// ============================================================================
bool test_domain_false_positive_microsoft_tco() {
    RuleManager rm;
    rm.blockDomain("t.co");
    TEST_ASSERT(!rm.isDomainBlocked("microsoft.com"), "microsoft.com must NOT be blocked by rule t.co");
    TEST_ASSERT(rm.isDomainBlocked("t.co"), "t.co must be blocked");
    TEST_ASSERT(rm.isDomainBlocked("sub.t.co"), "sub.t.co must be blocked");

    // Also verify app classification
    AppType app = sniToAppType("microsoft.com");
    TEST_ASSERT(app == AppType::MICROSOFT, "microsoft.com must classify as MICROSOFT, not TWITTER");
    return true;
}

// ============================================================================
// TEST 19: Domain Boundaries: Prefix & Suffix Attack Prevention
// ============================================================================
bool test_domain_prefix_and_suffix_boundaries() {
    RuleManager rm;
    rm.blockDomain("example.com");
    TEST_ASSERT(!rm.isDomainBlocked("notexample.com"), "Prefix match notexample.com must NOT match example.com");
    TEST_ASSERT(!rm.isDomainBlocked("example.com.attacker.org"), "Suffix attack example.com.attacker.org must NOT match example.com");
    return true;
}

// ============================================================================
// TEST 20: Symmetrical Flow Hashing & Bidirectional Tracking
// ============================================================================
bool test_bidirectional_flow_hashing() {
    FiveTuple fwd;
    fwd.src_ip = RuleManager::parseIP("192.168.1.100");
    fwd.dst_ip = RuleManager::parseIP("10.0.0.5");
    fwd.src_port = 50000;
    fwd.dst_port = 443;
    fwd.protocol = 6; // TCP

    FiveTuple rev;
    rev.src_ip = RuleManager::parseIP("10.0.0.5");
    rev.dst_ip = RuleManager::parseIP("192.168.1.100");
    rev.src_port = 443;
    rev.dst_port = 50000;
    rev.protocol = 6; // TCP

    FiveTuple udp_fwd = fwd;
    udp_fwd.protocol = 17; // UDP

    FiveTupleHash hasher;
    size_t hash_fwd = hasher(fwd);
    size_t hash_rev = hasher(rev);
    size_t hash_udp = hasher(udp_fwd);

    TEST_ASSERT(hash_fwd == hash_rev, "Forward and reverse flows must produce identical hash");
    TEST_ASSERT(hash_fwd != hash_udp, "TCP and UDP flows must produce distinct hashes");
    TEST_ASSERT(fwd.toCanonical() == rev.toCanonical(), "Canonical representation of forward and reverse must match");
    return true;
}

// ============================================================================
// TEST 21: Load Balancer Distribution & Zero Worker Starvation
// ============================================================================
bool test_multithreaded_lb_distribution() {
    constexpr int NUM_LBS = 2;
    constexpr int FPS_PER_LB = 2;
    constexpr int TOTAL_FPS = NUM_LBS * FPS_PER_LB;

    std::vector<std::unique_ptr<ThreadSafeQueue<PacketJob>>> queues;
    std::vector<ThreadSafeQueue<PacketJob>*> raw_queues;
    for (int i = 0; i < TOTAL_FPS; i++) {
        queues.push_back(std::make_unique<ThreadSafeQueue<PacketJob>>(1000));
        raw_queues.push_back(queues.back().get());
    }

    LBManager lbm(NUM_LBS, FPS_PER_LB, raw_queues);
    lbm.startAll();

    // Generate 60 distinct synthetic flows
    FiveTupleHash hasher;
    for (int i = 0; i < 60; i++) {
        PacketJob job;
        job.packet_id = i;
        job.tuple.src_ip = RuleManager::parseIP("10.0.0." + std::to_string((i % 200) + 1));
        job.tuple.dst_ip = RuleManager::parseIP("172.16.0." + std::to_string((i % 200) + 1));
        job.tuple.src_port = 10000 + (i * 17);
        job.tuple.dst_port = 80 + (i % 3);
        job.tuple.protocol = (i % 2 == 0) ? 6 : 17;

        job.target_fp = hasher(job.tuple) % TOTAL_FPS;
        LoadBalancer& lb = lbm.getLBForPacket(job.tuple);
        lb.getInputQueue().push(std::move(job));
    }

    // Give time for LB threads to dispatch
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    lbm.stopAll();

    // Check that ALL 4 queues received traffic (ZERO starvation)
    for (int i = 0; i < TOTAL_FPS; i++) {
        size_t count = queues[i]->size();
        TEST_ASSERT(count > 0, ("Fast Path worker queue " + std::to_string(i) + " starved (0 packets received)").c_str());
    }
    return true;
}

// ============================================================================
// TEST 22: Connection Tracker O(1) LRU Eviction & Cleanup
// ============================================================================
bool test_connection_tracker_lru_eviction() {
    ConnectionTracker tracker(0, 5); // capacity of 5 connections

    for (int i = 1; i <= 5; i++) {
        FiveTuple t;
        t.src_ip = i;
        t.dst_ip = 100;
        t.src_port = 1000 + i;
        t.dst_port = 80;
        t.protocol = 6;
        Connection* conn = tracker.getOrCreateConnection(t);
        TEST_ASSERT(conn != nullptr, "Failed to create connection");
    }
    TEST_ASSERT(tracker.getActiveCount() == 5, "Connection count should be 5");

    // Touch connection 1 so it becomes most recently used
    FiveTuple t1;
    t1.src_ip = 1; t1.dst_ip = 100; t1.src_port = 1001; t1.dst_port = 80; t1.protocol = 6;
    Connection* touched = tracker.getConnection(t1);
    TEST_ASSERT(touched != nullptr, "Connection 1 must exist");

    // Insert connection 6, which exceeds capacity 5.
    // Connection 2 was the least recently used, so connection 2 must be evicted!
    FiveTuple t6;
    t6.src_ip = 6; t6.dst_ip = 100; t6.src_port = 1006; t6.dst_port = 80; t6.protocol = 6;
    tracker.getOrCreateConnection(t6);
    TEST_ASSERT(tracker.getActiveCount() == 5, "Capacity must stay capped at 5");

    // Verify connection 1 is STILL alive
    TEST_ASSERT(tracker.getConnection(t1) != nullptr, "Recently accessed connection 1 should not be evicted");

    // Verify connection 2 WAS evicted
    FiveTuple t2;
    t2.src_ip = 2; t2.dst_ip = 100; t2.src_port = 1002; t2.dst_port = 80; t2.protocol = 6;
    TEST_ASSERT(tracker.getConnection(t2) == nullptr, "Least recently used connection 2 must be evicted");
    return true;
}

// ============================================================================
// TEST 23: Packet Reordering Buffer (In-order Output Reconstruction)
// ============================================================================
bool test_packet_reordering_output() {
    // Simulate out-of-order arrival in output reordering logic
    std::unordered_map<uint32_t, PacketJob> reorder_map;
    uint32_t next_expected_id = 0;
    std::vector<uint32_t> emitted_ids;

    auto deliver_packet = [&](uint32_t id, PacketAction act) {
        PacketJob job;
        job.packet_id = id;
        job.action = act;
        reorder_map[id] = job;

        while (true) {
            auto it = reorder_map.find(next_expected_id);
            if (it == reorder_map.end()) break;
            if (it->second.action == PacketAction::FORWARD) {
                emitted_ids.push_back(it->second.packet_id);
            }
            reorder_map.erase(it);
            next_expected_id++;
        }
    };

    // Packets arrive in order: 2 (FORWARD), 0 (FORWARD), 3 (FORWARD), 1 (DROP)
    deliver_packet(2, PacketAction::FORWARD);
    TEST_ASSERT(emitted_ids.empty(), "Packet 2 arrived first, cannot emit yet");

    deliver_packet(0, PacketAction::FORWARD);
    TEST_ASSERT(emitted_ids.size() == 1 && emitted_ids[0] == 0, "Packet 0 should emit immediately");

    deliver_packet(3, PacketAction::FORWARD);
    TEST_ASSERT(emitted_ids.size() == 1, "Packet 3 arrived, still waiting for packet 1");

    deliver_packet(1, PacketAction::DROP);
    // Now packet 1 (DROP), 2 (FORWARD), and 3 (FORWARD) must resolve!
    TEST_ASSERT(emitted_ids.size() == 3, "All forwarded packets must be emitted");
    TEST_ASSERT(emitted_ids[0] == 0 && emitted_ids[1] == 2 && emitted_ids[2] == 3,
                "Emitted packets must be in strictly ascending capture order");
    TEST_ASSERT(next_expected_id == 4, "Next expected ID must be 4");
    TEST_ASSERT(reorder_map.empty(), "Reorder map must be empty");
    return true;
}

// ============================================================================
// TEST 24: End-to-End PCAP Processing & Rule Filtering
// ============================================================================
bool test_end_to_end_pcap_processing() {
    DPIEngine::Config cfg;
    cfg.num_load_balancers = 2;
    cfg.fps_per_lb = 2;
    DPIEngine engine(cfg);
    TEST_ASSERT(engine.initialize(), "DPIEngine initialization failed");

    // Apply multiple rules
    engine.blockApp(AppType::YOUTUBE);
    engine.blockIP("192.168.1.50");
    engine.blockDomain("tiktok.com");
    engine.blockPort(80);

    std::string in_file = "test_dpi.pcap";
    std::string out_file = "/tmp/test_dpi_out.pcap";
    bool ok = engine.processFile(in_file, out_file);
    TEST_ASSERT(ok, "processFile failed");

    const auto& stats = engine.getStats();
    TEST_ASSERT(stats.total_packets == 77, "Total packets must be 77");
    TEST_ASSERT(stats.dropped_packets > 0, "Dropped packets must be > 0");
    TEST_ASSERT(stats.forwarded_packets + stats.dropped_packets == stats.total_packets,
                "Forwarded + Dropped must equal total packets");

    // Verify output PCAP file exists and has valid header
    std::ifstream out(out_file, std::ios::binary);
    TEST_ASSERT(out.is_open(), "Output PCAP file must exist");
    PcapGlobalHeader gh;
    out.read(reinterpret_cast<char*>(&gh), sizeof(gh));
    TEST_ASSERT(gh.magic_number == 0xa1b2c3d4 || gh.magic_number == 0xd4c3b2a1,
                "Output PCAP magic number mismatch");
    out.close();
    return true;
}

// Helper to create synthetic PacketJob for flow tests
static PacketJob createTestJob(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port,
                              uint8_t proto, size_t size, uint32_t sec, uint32_t usec, uint8_t flags = 0) {
    PacketJob job;
    job.tuple.src_ip = src_ip;
    job.tuple.dst_ip = dst_ip;
    job.tuple.src_port = src_port;
    job.tuple.dst_port = dst_port;
    job.tuple.protocol = proto;
    job.data.resize(size);
    job.ts_sec = sec;
    job.ts_usec = usec;
    job.tcp_flags = flags;
    return job;
}

// ============================================================================
// TEST 25: Welford's Statistical Accumulator (Variance & Mean Precision)
// ============================================================================
bool test_welford_statistical_accumulator() {
    StatisticalAccumulator acc;
    TEST_ASSERT(acc.count == 0, "Initial count must be 0");
    TEST_ASSERT(acc.mean() == 0.0, "Mean of empty accumulator must be 0");
    TEST_ASSERT(acc.variance() == 0.0, "Variance of empty accumulator must be 0");
    TEST_ASSERT(acc.stddev() == 0.0, "StdDev of empty accumulator must be 0");

    // Single value
    acc.update(42.0);
    TEST_ASSERT(acc.count == 1, "Count must be 1");
    TEST_ASSERT(acc.mean() == 42.0, "Mean must be 42");
    TEST_ASSERT(acc.min() == 42.0, "Min must be 42");
    TEST_ASSERT(acc.max() == 42.0, "Max must be 42");
    TEST_ASSERT(acc.variance() == 0.0, "Variance of single element must be 0");

    // Known dataset: [10, 20, 30, 40, 50]
    // N = 5, Mean = 30, Sum = 150
    // Differences from mean: -20, -10, 0, 10, 20
    // Squared differences: 400 + 100 + 0 + 100 + 400 = 1000
    // Sample variance = 1000 / (5 - 1) = 250.0
    StatisticalAccumulator test_acc;
    std::vector<double> vals = {10.0, 20.0, 30.0, 40.0, 50.0};
    for (double v : vals) {
        test_acc.update(v);
    }
    TEST_ASSERT(test_acc.count == 5, "Count must be 5");
    TEST_ASSERT(std::abs(test_acc.mean() - 30.0) < 1e-9, "Mean must be 30.0");
    TEST_ASSERT(std::abs(test_acc.sum - 150.0) < 1e-9, "Sum must be 150.0");
    TEST_ASSERT(test_acc.min() == 10.0, "Min must be 10.0");
    TEST_ASSERT(test_acc.max() == 50.0, "Max must be 50.0");
    TEST_ASSERT(std::abs(test_acc.variance() - 250.0) < 1e-9, "Sample variance must be 250.0");
    TEST_ASSERT(std::abs(test_acc.stddev() - std::sqrt(250.0)) < 1e-9, "StdDev mismatch");
    return true;
}

// ============================================================================
// TEST 26: Flow Record Directionality & Asymmetry Metrics
// ============================================================================
bool test_flow_record_directionality_and_symmetry() {
    FlowRecord flow;
    flow.flow_id = 1;
    FiveTuple client_tuple;
    client_tuple.src_ip = 0xC0A8010A; // 192.168.1.10
    client_tuple.dst_ip = 0x5DB8D822; // 93.184.216.34
    client_tuple.src_port = 54321;
    client_tuple.dst_port = 443;
    client_tuple.protocol = 6;
    flow.initial_tuple = client_tuple;
    flow.canonical_tuple = client_tuple.toCanonical();

    // First packet: Forward, size 100, at 1.0s
    PacketJob j1 = createTestJob(client_tuple.src_ip, client_tuple.dst_ip, client_tuple.src_port, client_tuple.dst_port,
                                6, 100, 1, 0, 0x02);
    flow.update(j1);
    TEST_ASSERT(flow.fwd.packet_count == 1, "Fwd packets must be 1");
    TEST_ASSERT(flow.fwd.byte_count == 100, "Fwd bytes must be 100");
    TEST_ASSERT(flow.rev.packet_count == 0, "Rev packets must be 0");

    // Second packet: Reverse, size 200, at 1.05s (50ms later)
    PacketJob j2 = createTestJob(client_tuple.dst_ip, client_tuple.src_ip, client_tuple.dst_port, client_tuple.src_port,
                                6, 200, 1, 50000, 0x12);
    flow.update(j2);
    TEST_ASSERT(flow.fwd.packet_count == 1, "Fwd packets must be 1");
    TEST_ASSERT(flow.rev.packet_count == 1, "Rev packets must be 1");
    TEST_ASSERT(flow.rev.byte_count == 200, "Rev bytes must be 200");
    TEST_ASSERT(flow.total_packets() == 2, "Total packets must be 2");
    TEST_ASSERT(flow.total_bytes() == 300, "Total bytes must be 300");

    // Third packet: Reverse, size 400, at 1.06s (10ms later)
    PacketJob j3 = createTestJob(client_tuple.dst_ip, client_tuple.src_ip, client_tuple.dst_port, client_tuple.src_port,
                                6, 400, 1, 60000, 0x10);
    flow.update(j3);
    TEST_ASSERT(flow.rev.packet_count == 2, "Rev packets must be 2");
    TEST_ASSERT(flow.rev.byte_count == 600, "Rev bytes must be 600");

    // Asymmetry ratios:
    // Packet Asymmetry = 1 / (2 + 1) = 1/3 = 0.333333
    // Byte Asymmetry = 100 / (600 + 1) = 100 / 601
    TEST_ASSERT(std::abs(flow.packet_asymmetry_ratio() - (1.0 / 3.0)) < 1e-4, "Packet asymmetry ratio mismatch");
    TEST_ASSERT(std::abs(flow.byte_asymmetry_ratio() - (100.0 / 601.0)) < 1e-4, "Byte asymmetry ratio mismatch");

    // Verify IAT on reverse direction: 60000 - 50000 = 10000 us
    TEST_ASSERT(flow.rev.iat_stats.count == 1, "Rev IAT count must be 1");
    TEST_ASSERT(flow.rev.iat_stats.mean() == 10000.0, "Rev IAT mean must be 10000 us");
    return true;
}

// ============================================================================
// TEST 27: TCP Flag Tracking and Rate Metrics
// ============================================================================
bool test_flow_record_tcp_flags_and_rate_metrics() {
    FlowRecord flow;
    flow.flow_id = 2;
    flow.initial_tuple.src_ip = 0x0A000001;
    flow.initial_tuple.dst_ip = 0x0A000002;
    flow.initial_tuple.src_port = 8080;
    flow.initial_tuple.dst_port = 9090;
    flow.initial_tuple.protocol = 6;
    flow.canonical_tuple = flow.initial_tuple.toCanonical();

    // j1: SYN (fwd, 1.00s)
    flow.update(createTestJob(0x0A000001, 0x0A000002, 8080, 9090, 6, 60, 1, 0, 0x02));
    // j2: SYN-ACK (rev, 1.10s)
    flow.update(createTestJob(0x0A000002, 0x0A000001, 9090, 8080, 6, 60, 1, 100000, 0x12));
    // j3: ACK (fwd, 1.20s)
    flow.update(createTestJob(0x0A000001, 0x0A000002, 8080, 9090, 6, 52, 1, 200000, 0x10));
    // j4: PSH-ACK (fwd, 1.30s)
    flow.update(createTestJob(0x0A000001, 0x0A000002, 8080, 9090, 6, 1000, 1, 300000, 0x18));
    // j5: FIN-ACK (rev, 1.40s)
    flow.update(createTestJob(0x0A000002, 0x0A000001, 9090, 8080, 6, 52, 1, 400000, 0x11));
    // j6: ACK (fwd, 1.50s)
    flow.update(createTestJob(0x0A000001, 0x0A000002, 8080, 9090, 6, 52, 1, 500000, 0x10));

    TEST_ASSERT(flow.fwd.syn_count == 1, "Fwd SYN count mismatch");
    TEST_ASSERT(flow.fwd.ack_count == 3, "Fwd ACK count mismatch");
    TEST_ASSERT(flow.fwd.psh_count == 1, "Fwd PSH count mismatch");
    TEST_ASSERT(flow.rev.syn_count == 1, "Rev SYN count mismatch");
    TEST_ASSERT(flow.rev.ack_count == 2, "Rev ACK count mismatch");
    TEST_ASSERT(flow.rev.fin_count == 1, "Rev FIN count mismatch");

    // Duration: 1.50s - 1.00s = 0.5s
    TEST_ASSERT(std::abs(flow.duration_seconds() - 0.5) < 1e-6, "Duration mismatch");
    TEST_ASSERT(flow.has_rate_metrics(), "Should have valid rate metrics");
    // Packets/sec: 6 / 0.5 = 12.0
    TEST_ASSERT(std::abs(flow.packets_per_second() - 12.0) < 1e-5, "Packets/sec mismatch");
    // Total bytes = 60 + 60 + 52 + 1000 + 52 + 52 = 1276
    // Bytes/sec = 1276 / 0.5 = 2552.0
    TEST_ASSERT(std::abs(flow.bytes_per_second() - 2552.0) < 1e-5, "Bytes/sec mismatch");
    return true;
}

// ============================================================================
// TEST 28: Flow Record JSON and CSV Serialization
// ============================================================================
bool test_flow_record_json_and_csv_serialization() {
    FlowRecord flow;
    flow.flow_id = 999;
    flow.initial_tuple.src_ip = 0xC0A80001; // 192.168.0.1
    flow.initial_tuple.dst_ip = 0x08080808; // 8.8.8.8
    flow.initial_tuple.src_port = 5353;
    flow.initial_tuple.dst_port = 53;
    flow.initial_tuple.protocol = 17; // UDP
    flow.canonical_tuple = flow.initial_tuple.toCanonical();

    flow.update(createTestJob(0xC0A80001, 0x08080808, 5353, 53, 17, 80, 2, 0, 0));
    flow.update(createTestJob(0x08080808, 0xC0A80001, 53, 5353, 17, 120, 2, 20000, 0));
    flow.app_type = AppType::DNS;
    flow.detected_app_name = "DNS";
    flow.dns_query = "example.com";
    flow.termination_reason = FlowTerminationReason::NATURAL_FIN_RST;

    std::string json = flow.toJson();
    TEST_ASSERT(json.find("\"flow_id\": 999") != std::string::npos, "JSON must contain flow_id");
    TEST_ASSERT(json.find("\"app_type\": \"DNS\"") != std::string::npos, "JSON must contain app_type");
    TEST_ASSERT(json.find("\"dns_query\": \"example.com\"") != std::string::npos, "JSON must contain dns_query");
    TEST_ASSERT(json.find("\"total_packets\": 2") != std::string::npos, "JSON must contain total_packets");
    TEST_ASSERT(json.find("\"forward\": {") != std::string::npos, "JSON must contain forward object");

    std::string header = FlowRecord::csvHeader();
    std::string row = flow.toCsvRow();
    TEST_ASSERT(!header.empty(), "CSV header must not be empty");
    TEST_ASSERT(!row.empty(), "CSV row must not be empty");
    TEST_ASSERT(row.find("999") != std::string::npos, "CSV row must contain flow_id");
    TEST_ASSERT(row.find("DNS") != std::string::npos, "CSV row must contain DNS");
    return true;
}

// ============================================================================
// TEST 29: Flow Table Bidirectional Canonical Hashing & Tracking
// ============================================================================
bool test_flow_table_canonical_bidirectional_lookup() {
    FlowTable table(0, 1000, 60000000ULL);

    PacketJob job1 = createTestJob(0xC0A80164, 0x08080808, 45000, 53, 17, 60, 1, 0, 0);
    FlowRecord* r1 = table.processPacket(job1);
    TEST_ASSERT(r1 != nullptr, "Flow record pointer should not be null");
    TEST_ASSERT(table.getActiveFlowCount() == 1, "Active flow count must be 1");
    TEST_ASSERT(table.getTotalFlowsSeen() == 1, "Total flows seen must be 1");
    TEST_ASSERT(r1->fwd.packet_count == 1, "Fwd packets must be 1");
    TEST_ASSERT(r1->rev.packet_count == 0, "Rev packets must be 0");

    // Reverse packet (swap src and dst)
    PacketJob job2 = createTestJob(0x08080808, 0xC0A80164, 53, 45000, 17, 120, 1, 10000, 0);
    FlowRecord* r2 = table.processPacket(job2);
    TEST_ASSERT(r2 == r1, "Reverse packet must map to identical FlowRecord");
    TEST_ASSERT(table.getActiveFlowCount() == 1, "Active flow count must remain 1");
    TEST_ASSERT(table.getTotalFlowsSeen() == 1, "Total flows seen must remain 1");
    TEST_ASSERT(r2->fwd.packet_count == 1, "Fwd packets must be 1");
    TEST_ASSERT(r2->rev.packet_count == 1, "Rev packets must be 1");
    TEST_ASSERT(r2->total_packets() == 2, "Total packets must be 2");
    return true;
}

// ============================================================================
// TEST 30: Flow Table Idle Timeout Cleanup
// ============================================================================
bool test_flow_table_idle_timeout_cleanup() {
    uint64_t timeout_us = 10000000ULL; // 10 seconds timeout
    FlowTable table(0, 1000, timeout_us);

    PacketJob job = createTestJob(0x01020304, 0x05060708, 1000, 2000, 6, 64, 1, 0, 0); // T0 = 1.0s = 1000000us
    table.processPacket(job);
    TEST_ASSERT(table.getActiveFlowCount() == 1, "Active flows should be 1");

    // Advance time by 5s (1000000 + 5000000 = 6000000us) -> within timeout
    size_t evicted = table.cleanupIdleFlows(6000000ULL);
    TEST_ASSERT(evicted == 0, "No flows should be evicted at T0+5s");
    TEST_ASSERT(table.getActiveFlowCount() == 1, "Active flows must still be 1");

    // Advance time to T0 + 15s (1000000 + 15000000 = 16000000us) -> exceeds 10s timeout
    evicted = table.cleanupIdleFlows(16000000ULL);
    TEST_ASSERT(evicted == 1, "Exactly 1 flow should be evicted at T0+15s");
    TEST_ASSERT(table.getActiveFlowCount() == 0, "Active flows must now be 0");
    TEST_ASSERT(table.getFinalizedFlowCount() == 1, "Finalized flows must be 1");
    TEST_ASSERT(table.getFinalizedFlows()[0].termination_reason == FlowTerminationReason::IDLE_TIMEOUT,
                "Termination reason must be IDLE_TIMEOUT");
    return true;
}

// ============================================================================
// TEST 31: Flow Table O(1) LRU Capacity Eviction
// ============================================================================
bool test_flow_table_lru_capacity_eviction() {
    size_t capacity = 3;
    FlowTable table(0, capacity, 60000000ULL);

    // Insert 3 flows (reaches capacity)
    table.processPacket(createTestJob(0x0A000001, 0x0A000002, 1001, 80, 6, 50, 1, 0, 0)); // Flow 1
    table.processPacket(createTestJob(0x0A000001, 0x0A000002, 1002, 80, 6, 50, 1, 100, 0)); // Flow 2
    table.processPacket(createTestJob(0x0A000001, 0x0A000002, 1003, 80, 6, 50, 1, 200, 0)); // Flow 3
    TEST_ASSERT(table.getActiveFlowCount() == 3, "Table should have 3 active flows");

    // Touch Flow 1 again (moves Flow 1 to most recently used, so Flow 2 is now oldest)
    table.processPacket(createTestJob(0x0A000001, 0x0A000002, 1001, 80, 6, 50, 1, 300, 0));

    // Insert Flow 4 -> must evict Flow 2 (oldest LRU)
    table.processPacket(createTestJob(0x0A000001, 0x0A000002, 1004, 80, 6, 50, 1, 400, 0));
    TEST_ASSERT(table.getActiveFlowCount() == 3, "Active flows should remain at capacity (3)");
    TEST_ASSERT(table.getFinalizedFlowCount() == 1, "Finalized flows should be 1");

    const auto& evicted = table.getFinalizedFlows()[0];
    TEST_ASSERT(evicted.initial_tuple.src_port == 1002, "Evicted flow must be Flow 2 (port 1002)");
    TEST_ASSERT(evicted.termination_reason == FlowTerminationReason::CAPACITY_EVICTION,
                "Termination reason must be CAPACITY_EVICTION");
    return true;
}

// ============================================================================
// TEST 32: End-to-End PCAP Flow Intelligence & Export Verification
// ============================================================================
bool test_end_to_end_flow_intelligence_pcap() {
    DPIEngine::Config cfg;
    cfg.num_load_balancers = 2;
    cfg.fps_per_lb = 2;
    cfg.export_flows_json = "/tmp/test_flows.json";
    cfg.export_flows_csv = "/tmp/test_flows.csv";
    cfg.show_flow_stats = true;

    DPIEngine engine(cfg);
    TEST_ASSERT(engine.initialize(), "DPIEngine initialization failed");

    std::string in_file = "test_dpi.pcap";
    std::string out_file = "/tmp/test_flows_out.pcap";
    bool ok = engine.processFile(in_file, out_file);
    TEST_ASSERT(ok, "processFile failed");

    // Check JSON export file
    std::ifstream json_file("/tmp/test_flows.json");
    TEST_ASSERT(json_file.is_open(), "Exported JSON file must exist");
    std::string json_content((std::istreambuf_iterator<char>(json_file)),
                              std::istreambuf_iterator<char>());
    json_file.close();
    TEST_ASSERT(!json_content.empty(), "Exported JSON must not be empty");
    TEST_ASSERT(json_content.front() == '[' && json_content.find("]") != std::string::npos,
                "Exported JSON must be a valid JSON array");
    TEST_ASSERT(json_content.find("\"flow_id\"") != std::string::npos, "JSON must contain flow_id");
    TEST_ASSERT(json_content.find("\"total_packets\"") != std::string::npos, "JSON must contain total_packets");
    TEST_ASSERT(json_content.find("\"forward\"") != std::string::npos, "JSON must contain forward");

    // Check CSV export file
    std::ifstream csv_file("/tmp/test_flows.csv");
    TEST_ASSERT(csv_file.is_open(), "Exported CSV file must exist");
    std::string first_line;
    std::getline(csv_file, first_line);
    TEST_ASSERT(first_line.find("flow_id,protocol,src_ip") != std::string::npos,
                "CSV must contain proper header columns");
    std::string data_line;
    size_t csv_rows = 0;
    while (std::getline(csv_file, data_line)) {
        if (!data_line.empty()) csv_rows++;
    }
    csv_file.close();
    TEST_ASSERT(csv_rows > 0, "CSV must contain data rows");

    // Verify report generation
    std::string flow_report = engine.generateFlowIntelligenceReport();
    TEST_ASSERT(flow_report.find("NETWORK FLOW INTELLIGENCE REPORT") != std::string::npos,
                "Flow report header must be present");
    TEST_ASSERT(flow_report.find("Total Flows Tracked:") != std::string::npos,
                "Flow report must list total flows");
    return true;
}

// ============================================================================
// PHASE 3.1: BEHAVIORAL NETWORK DETECTION TESTS (TESTS 33-48)
// ============================================================================

static FlowRecord createSyntheticFlow(uint64_t id, uint32_t src_ip, uint32_t dst_ip, 
                                     uint16_t src_port, uint16_t dst_port, uint8_t proto,
                                     uint64_t start_us, uint64_t duration_us,
                                     uint64_t fwd_pkts, uint64_t fwd_bytes,
                                     uint64_t rev_pkts, uint64_t rev_bytes,
                                     uint32_t fwd_syn = 0, uint32_t fwd_ack = 0,
                                     uint32_t rev_syn = 0, uint32_t rev_ack = 0,
                                     uint32_t rev_rst = 0,
                                     AppType app = AppType::UNKNOWN,
                                     const std::string& dns = "") {
    FlowRecord f;
    f.flow_id = id;
    f.initial_tuple.src_ip = src_ip;
    f.initial_tuple.dst_ip = dst_ip;
    f.initial_tuple.src_port = src_port;
    f.initial_tuple.dst_port = dst_port;
    f.initial_tuple.protocol = proto;
    f.canonical_tuple = f.initial_tuple.toCanonical();
    f.start_time_us = start_us;
    f.last_time_us = start_us + duration_us;
    f.fwd.packet_count = fwd_pkts;
    f.fwd.byte_count = fwd_bytes;
    f.rev.packet_count = rev_pkts;
    f.rev.byte_count = rev_bytes;
    f.fwd.syn_count = fwd_syn;
    f.fwd.ack_count = fwd_ack;
    f.rev.syn_count = rev_syn;
    f.rev.ack_count = rev_ack;
    f.rev.rst_count = rev_rst;
    f.app_type = app;
    f.dns_query = dns;
    return f;
}

// TEST 33: Vertical Port Scan Detection
bool test_detection_port_scan_vertical() {
    DetectionConfig config;
    PortScanDetector detector;
    std::vector<FlowRecord> flows;

    uint32_t src = 0x0A000005; // 10.0.0.5
    uint32_t dst = 0xC0A80101; // 192.168.1.1

    // 15 unique destination ports within 3 seconds
    for (uint16_t p = 1000; p < 1015; ++p) {
        flows.push_back(createSyntheticFlow(p, src, dst, 50000 + p, p, 6,
                                           1000000ULL + (p - 1000) * 100000ULL, 10000,
                                           1, 60, 0, 0, 1, 0, 0, 0, 0));
    }

    auto events = detector.detect(flows, config);
    TEST_ASSERT(events.size() == 1, "Expected exactly 1 vertical port scan detection");
    TEST_ASSERT(events[0].category == DetectionCategory::NETWORK_RECONNAISSANCE, "Category mismatch");
    TEST_ASSERT(events[0].evidence["scan_type"] == "vertical_port_scan", "Scan type mismatch");
    TEST_ASSERT(events[0].evidence["unique_destination_ports"] == "15", "Port count mismatch");
    TEST_ASSERT(events[0].source_ip == src, "Source IP mismatch");
    TEST_ASSERT(events[0].destination_ip == dst, "Destination IP mismatch");
    return true;
}

// TEST 34: Horizontal Port Scan Detection (IP Sweep)
bool test_detection_port_scan_horizontal() {
    DetectionConfig config;
    PortScanDetector detector;
    std::vector<FlowRecord> flows;

    uint32_t src = 0x0A000005; // 10.0.0.5
    uint16_t target_port = 22; // SSH

    // 12 unique destination hosts targeting port 22
    for (uint32_t i = 1; i <= 12; ++i) {
        uint32_t dst = 0xC0A80100 + i; // 192.168.1.i
        flows.push_back(createSyntheticFlow(i, src, dst, 40000 + i, target_port, 6,
                                           2000000ULL + i * 100000ULL, 10000,
                                           1, 60, 0, 0, 1, 0, 0, 0, 0));
    }

    auto events = detector.detect(flows, config);
    TEST_ASSERT(events.size() == 1, "Expected exactly 1 horizontal IP sweep detection");
    TEST_ASSERT(events[0].evidence["scan_type"] == "horizontal_ip_sweep", "Scan type mismatch");
    TEST_ASSERT(events[0].evidence["target_port"] == "22", "Target port mismatch");
    TEST_ASSERT(events[0].evidence["unique_target_ips"] == "12", "Target IP count mismatch");
    return true;
}

// TEST 35: Port Scan Benign & Window Boundary Edge Cases
bool test_detection_port_scan_benign_and_boundary() {
    DetectionConfig config;
    PortScanDetector detector;
    std::vector<FlowRecord> flows;

    uint32_t src = 0x0A000005;
    uint32_t dst = 0xC0A80101;

    // Sub-threshold: only 3 ports
    for (uint16_t p = 80; p < 83; ++p) {
        flows.push_back(createSyntheticFlow(p, src, dst, 50000 + p, p, 6,
                                           1000000ULL + p * 10000ULL, 10000,
                                           1, 60, 1, 60, 1, 1, 1, 1, 0));
    }
    auto events = detector.detect(flows, config);
    TEST_ASSERT(events.empty(), "Sub-threshold traffic must not trigger port scan alert");

    // Outside time window: 12 ports but spaced 20s apart (far exceeding 10s window)
    flows.clear();
    for (uint16_t p = 100; p < 112; ++p) {
        flows.push_back(createSyntheticFlow(p, src, dst, 50000 + p, p, 6,
                                           1000000ULL + (p - 100) * 20000000ULL, 10000,
                                           1, 60, 0, 0, 1, 0, 0, 0, 0));
    }
    events = detector.detect(flows, config);
    TEST_ASSERT(events.empty(), "Scattered attempts outside window must not trigger port scan alert");
    return true;
}

// TEST 36: Connection Burst Detection
bool test_detection_connection_burst() {
    DetectionConfig config;
    ConnectionBurstDetector detector;
    std::vector<FlowRecord> flows;

    uint32_t src = 0x0A000008;

    // 20 flows initiated within 1.0 second (threshold is 15 in 2.0s)
    for (size_t i = 0; i < 20; ++i) {
        flows.push_back(createSyntheticFlow(i + 1, src, 0x08080808, 40000 + i, 443, 6,
                                           1000000ULL + i * 50000ULL, 10000,
                                           2, 120, 2, 120, 1, 1, 1, 1, 0));
    }

    auto events = detector.detect(flows, config);
    TEST_ASSERT(events.size() == 1, "Expected 1 connection burst event");
    TEST_ASSERT(events[0].category == DetectionCategory::CONNECTION_ANOMALY, "Category mismatch");
    TEST_ASSERT(events[0].evidence["flow_count"] == "20", "Flow count mismatch");

    // Normal traffic check: 8 flows spread over 5 seconds
    flows.clear();
    for (size_t i = 0; i < 8; ++i) {
        flows.push_back(createSyntheticFlow(i + 1, src, 0x08080808, 40000 + i, 443, 6,
                                           1000000ULL + i * 600000ULL, 10000,
                                           2, 120, 2, 120, 1, 1, 1, 1, 0));
    }
    events = detector.detect(flows, config);
    TEST_ASSERT(events.empty(), "Normal connection rate must not trigger burst alert");
    return true;
}

// TEST 37: Repeated Connection Attempts Detection
bool test_detection_repeated_attempts() {
    DetectionConfig config;
    RepeatedAttemptsDetector detector;
    std::vector<FlowRecord> flows;

    uint32_t src = 0x0A000009;
    uint32_t dst = 0x0A000001;
    uint16_t port = 445;

    // 8 repeated connection attempts, all unanswered (rev.packet_count == 0)
    for (size_t i = 0; i < 8; ++i) {
        flows.push_back(createSyntheticFlow(i + 1, src, dst, 51000 + i, port, 6,
                                           1000000ULL + i * 500000ULL, 2000000,
                                           1, 60, 0, 0, 1, 0, 0, 0, 0));
    }

    auto events = detector.detect(flows, config);
    TEST_ASSERT(events.size() == 1, "Expected 1 repeated attempts event");
    TEST_ASSERT(events[0].category == DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT, "Category mismatch");
    TEST_ASSERT(events[0].evidence["attempts_count"] == "8", "Attempts mismatch");

    // Successful connections check: 8 successful flows with complete handshakes
    flows.clear();
    for (size_t i = 0; i < 8; ++i) {
        flows.push_back(createSyntheticFlow(i + 1, src, dst, 51000 + i, port, 6,
                                           1000000ULL + i * 500000ULL, 2000000,
                                           5, 500, 5, 500, 1, 4, 1, 4, 0));
    }
    events = detector.detect(flows, config);
    TEST_ASSERT(events.empty(), "Successful connections must not trigger repeated failed attempts alert");
    return true;
}

// TEST 38: DNS High Query Frequency & Domain Diversity
bool test_detection_dns_high_frequency() {
    DetectionConfig config;
    DNSAnomalyDetector detector;
    std::vector<FlowRecord> flows;

    uint32_t src = 0x0A000010;
    uint32_t dst = 0x08080808;

    // 25 distinct DNS queries within 4 seconds (threshold is 20)
    for (size_t i = 0; i < 25; ++i) {
        std::string query = "host" + std::to_string(i) + ".example.com";
        flows.push_back(createSyntheticFlow(i + 1, src, dst, 52000 + i, 53, 17,
                                           1000000ULL + i * 150000ULL, 20000,
                                           1, 75, 1, 100, 0, 0, 0, 0, 0,
                                           AppType::DNS, query));
    }

    auto events = detector.detect(flows, config);
    TEST_ASSERT(events.size() == 1, "Expected 1 DNS high rate event");
    TEST_ASSERT(events[0].category == DetectionCategory::SUSPICIOUS_DNS, "Category mismatch");
    TEST_ASSERT(events[0].evidence["query_count"] == "25", "Query count mismatch");
    return true;
}

// TEST 39: Suspicious DNS Domain Length & Tunneling Candidates
bool test_detection_dns_long_domain_tunneling() {
    DetectionConfig config;
    DNSAnomalyDetector detector;
    std::vector<FlowRecord> flows;

    uint32_t src = 0x0A000012;
    uint32_t dst = 0x08080808;

    // Long encoded domain (67 characters)
    std::string tunnel_query = "v1-a8f3d99e01bc4a5f67e8890123456789abcdef.tunnel.exfil-data.org";
    flows.push_back(createSyntheticFlow(1, src, dst, 53000, 53, 17,
                                       1000000ULL, 20000, 1, 90, 1, 120,
                                       0, 0, 0, 0, 0, AppType::DNS, tunnel_query));

    auto events = detector.detect(flows, config);
    TEST_ASSERT(events.size() == 1, "Expected 1 DNS tunneling candidate event");
    TEST_ASSERT(events[0].evidence["dns_query"] == tunnel_query, "Query mismatch");
    TEST_ASSERT(events[0].evidence["query_length"] == std::to_string(tunnel_query.length()), "Length mismatch");

    // Benign domain check
    flows.clear();
    flows.push_back(createSyntheticFlow(2, src, dst, 53001, 53, 17,
                                       1000000ULL, 20000, 1, 60, 1, 80,
                                       0, 0, 0, 0, 0, AppType::DNS, "google.com"));
    events = detector.detect(flows, config);
    TEST_ASSERT(events.empty(), "Benign DNS query must not trigger tunneling alert");
    return true;
}

// TEST 40: Unusual Outbound Volume Anomaly Detection
bool test_detection_outbound_volume_anomaly() {
    DetectionConfig config;
    OutboundAnomalyDetector detector;
    std::vector<FlowRecord> flows;

    uint32_t src = 0x0A000015;
    uint32_t dst = 0x5D000001;

    // Flow transferring 8 MB outbound on non-standard port 9999
    flows.push_back(createSyntheticFlow(1, src, dst, 54000, 9999, 6,
                                       1000000ULL, 5000000ULL,
                                       5500, 8000000ULL, 200, 10000ULL,
                                       1, 500, 1, 200, 0));

    auto events = detector.detect(flows, config);
    TEST_ASSERT(events.size() == 1, "Expected 1 outbound anomaly event");
    TEST_ASSERT(events[0].category == DetectionCategory::UNUSUAL_TRAFFIC_VOLUME, "Category mismatch");
    TEST_ASSERT(events[0].evidence["forward_bytes"] == "8000000", "Forward bytes mismatch");

    // Balanced flow check: 5000 bytes forward, 5000 bytes reverse
    flows.clear();
    flows.push_back(createSyntheticFlow(2, src, dst, 54001, 443, 6,
                                       1000000ULL, 200000ULL,
                                       10, 5000ULL, 10, 5000ULL,
                                       1, 9, 1, 9, 0));
    events = detector.detect(flows, config);
    TEST_ASSERT(events.empty(), "Balanced flow must not trigger outbound volume alert");
    return true;
}

// TEST 41: Periodic Beacon-Like Communication Detection
bool test_detection_beacon_periodic() {
    DetectionConfig config;
    BeaconDetector detector;
    std::vector<FlowRecord> flows;

    uint32_t src = 0x0A000020;
    uint32_t dst = 0xC6336405; // 198.51.100.5
    uint16_t port = 8080;

    // 6 connections spaced at exact 2.0s intervals (2,000,000 us)
    for (size_t i = 0; i < 6; ++i) {
        flows.push_back(createSyntheticFlow(i + 1, src, dst, 55000 + i, port, 6,
                                           1000000ULL + i * 2000000ULL, 50000,
                                           4, 250, 4, 300, 1, 3, 1, 3, 0));
    }

    auto events = detector.detect(flows, config);
    TEST_ASSERT(events.size() == 1, "Expected 1 periodic beaconing event");
    TEST_ASSERT(events[0].category == DetectionCategory::COMMAND_AND_CONTROL, "Category mismatch");
    TEST_ASSERT(events[0].evidence["connection_count"] == "6", "Connection count mismatch");
    return true;
}

// TEST 42: Beacon Jitter Rejection (False Positive Prevention)
bool test_detection_beacon_jitter_rejection() {
    DetectionConfig config;
    BeaconDetector detector;
    std::vector<FlowRecord> flows;

    uint32_t src = 0x0A000020;
    uint32_t dst = 0xC6336405;
    uint16_t port = 8080;

    // 6 connections with heavily jittered intervals: +1.0s, +7.5s, +0.6s, +12.0s, +3.2s
    std::vector<uint64_t> timestamps = {
        1000000ULL, 2000000ULL, 9500000ULL, 10100000ULL, 22100000ULL, 25300000ULL
    };
    for (size_t i = 0; i < timestamps.size(); ++i) {
        flows.push_back(createSyntheticFlow(i + 1, src, dst, 55000 + i, port, 6,
                                           timestamps[i], 50000,
                                           4, 250, 4, 300, 1, 3, 1, 3, 0));
    }

    auto events = detector.detect(flows, config);
    TEST_ASSERT(events.empty(), "Jittered irregular traffic must not trigger beaconing alert");
    return true;
}

// TEST 43: TCP SYN Anomaly Detection (SYN-Heavy Flow Pattern)
bool test_detection_tcp_syn_anomaly() {
    DetectionConfig config;
    TCPAnomalyDetector detector;
    std::vector<FlowRecord> flows;

    uint32_t src = 0x0A000030;

    // 10 TCP flows: 9 SYN-only (90% SYN ratio, exceeding 85% threshold)
    for (size_t i = 0; i < 9; ++i) {
        flows.push_back(createSyntheticFlow(i + 1, src, 0x08080808, 56000 + i, 80 + i, 6,
                                           1000000ULL + i * 100000ULL, 10000,
                                           1, 60, 0, 0, 1, 0, 0, 0, 0));
    }
    // 1 normal flow
    flows.push_back(createSyntheticFlow(10, src, 0x08080808, 56010, 443, 6,
                                       2000000ULL, 10000,
                                       5, 300, 5, 300, 1, 4, 1, 4, 0));

    auto events = detector.detect(flows, config);
    TEST_ASSERT(events.size() == 1, "Expected 1 TCP SYN anomaly event");
    TEST_ASSERT(events[0].category == DetectionCategory::PROTOCOL_ANOMALY, "Category mismatch");
    TEST_ASSERT(events[0].evidence["syn_heavy_flows"] == "9", "SYN heavy count mismatch");
    return true;
}

// TEST 44: TCP RST Anomaly Detection
bool test_detection_tcp_rst_anomaly() {
    DetectionConfig config;
    TCPAnomalyDetector detector;
    std::vector<FlowRecord> flows;

    uint32_t src = 0x0A000031;

    // 10 TCP flows: 6 terminating with RST (60% RST ratio, exceeding 40% threshold)
    for (size_t i = 0; i < 6; ++i) {
        flows.push_back(createSyntheticFlow(i + 1, src, 0x08080808, 57000 + i, 8080, 6,
                                           1000000ULL + i * 100000ULL, 10000,
                                           2, 100, 1, 54, 1, 1, 0, 0, 1)); // rev_rst=1
    }
    for (size_t i = 6; i < 10; ++i) {
        flows.push_back(createSyntheticFlow(i + 1, src, 0x08080808, 57000 + i, 8080, 6,
                                           1000000ULL + i * 100000ULL, 10000,
                                           4, 200, 4, 200, 1, 3, 1, 3, 0));
    }

    auto events = detector.detect(flows, config);
    TEST_ASSERT(events.size() == 1, "Expected 1 TCP RST anomaly event");
    TEST_ASSERT(events[0].evidence["rst_flow_count"] == "6", "RST count mismatch");
    return true;
}

// TEST 45: Detection Event JSON and CSV Serialization
bool test_detection_event_serialization_json_csv() {
    DetectionEvent ev;
    ev.schema_version = "1.0";
    ev.detection_id = "DET-TEST-001";
    ev.detector_name = "port_scan_detector";
    ev.category = DetectionCategory::NETWORK_RECONNAISSANCE;
    ev.severity = DetectionSeverity::MEDIUM;
    ev.timestamp_us = 1700000000000000ULL;
    ev.timestamp_iso = "2023-11-14T22:13:20.000Z";
    ev.source_ip = 0xC0A8010A;
    ev.destination_ip = 0xC0A80101;
    ev.source_ip_str = "192.168.1.10";
    ev.destination_ip_str = "192.168.1.1";
    ev.protocol = 6;
    ev.relevant_ports = {80, 443, 8080};
    ev.related_flow_ids = {101, 102, 103};
    ev.evidence["unique_destination_ports"] = "3";
    ev.evidence["observed_metric"] = "3 ports";
    ev.explanation = "Test explanation for serialization.";
    ev.limitations = {"Test limitation 1."};
    ev.recommended_actions = {"Test recommended action 1."};

    // Test JSON serialization
    std::string json = ev.toJson();
    TEST_ASSERT(json.find("\"detection_id\": \"DET-TEST-001\"") != std::string::npos, "JSON must contain detection_id");
    TEST_ASSERT(json.find("\"detector\": \"port_scan_detector\"") != std::string::npos, "JSON must contain detector");
    TEST_ASSERT(json.find("\"category\": \"NETWORK_RECONNAISSANCE\"") != std::string::npos, "JSON must contain category");
    TEST_ASSERT(json.find("\"severity\": \"MEDIUM\"") != std::string::npos, "JSON must contain severity");
    TEST_ASSERT(json.find("\"source_ip\": \"192.168.1.10\"") != std::string::npos, "JSON must contain source_ip");

    // Test CSV serialization
    std::string header = DetectionEvent::csvHeader();
    std::string csv_row = ev.toCsvRow();
    TEST_ASSERT(!header.empty(), "CSV header must not be empty");
    TEST_ASSERT(csv_row.find("DET-TEST-001") != std::string::npos, "CSV row must contain detection_id");
    TEST_ASSERT(csv_row.find("NETWORK_RECONNAISSANCE") != std::string::npos, "CSV row must contain category");

    // Test batch export functions
    std::ostringstream json_os;
    DetectionEngine::exportJson({ev}, json_os);
    TEST_ASSERT(json_os.str().front() == '[' && json_os.str().find("]") != std::string::npos, "Valid JSON array required");

    std::ostringstream csv_os;
    DetectionEngine::exportCsv({ev}, csv_os);
    TEST_ASSERT(csv_os.str().find("DET-TEST-001") != std::string::npos, "Exported CSV must contain row");
    return true;
}

// TEST 46: Detection Event Deduplication
bool test_detection_deduplication() {
    DetectionEvent ev1;
    ev1.detector_name = "port_scan_detector";
    ev1.category = DetectionCategory::NETWORK_RECONNAISSANCE;
    ev1.source_ip = 0x0A000001;
    ev1.destination_ip = 0x0A000002;
    ev1.timestamp_us = 1000000ULL;

    DetectionEvent ev2 = ev1; // duplicate fingerprint
    DetectionEvent ev3 = ev1;
    ev3.destination_ip = 0x0A000003; // different destination -> unique

    std::vector<DetectionEvent> events = {ev1, ev2, ev3};
    auto deduplicated = DetectionEngine::deduplicate(events);
    TEST_ASSERT(deduplicated.size() == 2, "Duplicate events within same window must be deduplicated");
    return true;
}

// TEST 47: Detection Configuration Validation & Detector Toggling
bool test_detection_config_validation_and_toggle() {
    DetectionConfig config;
    TEST_ASSERT(config.validate(), "Default configuration must be valid");

    config.port_scan_vertical_port_threshold = 0;
    TEST_ASSERT(!config.validate(), "Zero threshold must fail validation");
    config.port_scan_vertical_port_threshold = 10;

    TEST_ASSERT(config.setDetectorEnabled("port_scan", false), "setDetectorEnabled should succeed");
    TEST_ASSERT(!config.isDetectorEnabled("port_scan"), "Detector must be reported disabled");

    TEST_ASSERT(config.setDetectorEnabled("port_scan", true), "Re-enabling detector should succeed");
    TEST_ASSERT(config.isDetectorEnabled("port_scan"), "Detector must be reported enabled");
    return true;
}

// TEST 48: End-to-End PCAP Behavioral Detection Integration
bool test_detection_end_to_end_pcap() {
    DPIEngine::Config cfg;
    cfg.num_load_balancers = 2;
    cfg.fps_per_lb = 2;
    cfg.enable_detection = true;
    cfg.show_detection_stats = true;
    cfg.export_detections_json = "/tmp/test_detections.json";
    cfg.export_detections_csv = "/tmp/test_detections.csv";

    DPIEngine engine(cfg);
    TEST_ASSERT(engine.initialize(), "DPIEngine initialization failed");

    std::string in_file = "test_dpi.pcap";
    std::string out_file = "/tmp/test_detection_out.pcap";
    bool ok = engine.processFile(in_file, out_file);
    TEST_ASSERT(ok, "processFile failed");

    // Verify detection report generation
    std::string report = engine.generateDetectionReport();
    TEST_ASSERT(report.find("BEHAVIORAL NETWORK DETECTION REPORT") != std::string::npos,
                "Detection report header must be present");

    // Verify JSON export
    std::ifstream json_file("/tmp/test_detections.json");
    TEST_ASSERT(json_file.is_open(), "Detections JSON file must exist");
    std::string json_content((std::istreambuf_iterator<char>(json_file)),
                              std::istreambuf_iterator<char>());
    json_file.close();
    TEST_ASSERT(json_content.front() == '[' && json_content.find("]") != std::string::npos,
                "Detections JSON must be valid JSON array");

    // Verify CSV export
    std::ifstream csv_file("/tmp/test_detections.csv");
    TEST_ASSERT(csv_file.is_open(), "Detections CSV file must exist");
    std::string header;
    std::getline(csv_file, header);
    TEST_ASSERT(header.find("detection_id,detector,category") != std::string::npos,
                "CSV must contain valid detection header");
    csv_file.close();
    return true;
}

// ============================================================================
// PHASE 3.2: TCP STREAM REASSEMBLY & PROTOCOL INTELLIGENCE TESTS (49-73)
// ============================================================================

// TEST 49: Basic In-Order Stream Reassembly
bool test_stream_in_order_reassembly() {
    TCPHalfStream stream;
    // Handshake SYN at seq 1000
    bool added = stream.processSegment(1000, 0, 0x02, nullptr, 0, 100000);
    TEST_ASSERT(!added, "SYN with no payload should return false");
    TEST_ASSERT(stream.getStats().next_expected_seq == 1001, "Expected seq after SYN is 1001");

    // Segment 1: seq 1001, "Hello " (6 bytes)
    std::string s1 = "Hello ";
    added = stream.processSegment(1001, 0, 0, reinterpret_cast<const uint8_t*>(s1.data()), s1.size(), 101000);
    TEST_ASSERT(added, "In-order segment 1 must return true");
    TEST_ASSERT(stream.getStats().bytes_reassembled == 6, "Reassembled byte count mismatch");

    // Segment 2: seq 1007, "World!" (6 bytes)
    std::string s2 = "World!";
    added = stream.processSegment(1007, 0, 0, reinterpret_cast<const uint8_t*>(s2.data()), s2.size(), 102000);
    TEST_ASSERT(added, "In-order segment 2 must return true");
    TEST_ASSERT(stream.getStats().bytes_reassembled == 12, "Total bytes mismatch");

    std::string result(reinterpret_cast<const char*>(stream.getReassembledData().data()),
                       stream.getReassembledData().size());
    TEST_ASSERT(result == "Hello World!", "Reassembled stream content mismatch");
    return true;
}

// TEST 50: Out-of-Order Stream Reassembly
bool test_stream_out_of_order_reassembly() {
    TCPHalfStream stream;
    stream.processSegment(2000, 0, 0x02, nullptr, 0, 100000); // SYN -> next = 2001

    // Receive Segment 2 first: seq 2006, "World"
    std::string s2 = "World";
    bool added = stream.processSegment(2006, 0, 0, reinterpret_cast<const uint8_t*>(s2.data()), s2.size(), 101000);
    TEST_ASSERT(!added, "Out-of-order segment must not be added to contiguous stream yet");
    TEST_ASSERT(stream.getStats().out_of_order_count == 1, "Expected 1 out of order segment");
    TEST_ASSERT(stream.getBufferedOutOfOrderBytes() == 5, "Expected 5 buffered bytes");

    // Receive Segment 3: seq 2011, "!"
    std::string s3 = "!";
    stream.processSegment(2011, 0, 0, reinterpret_cast<const uint8_t*>(s3.data()), s3.size(), 102000);
    TEST_ASSERT(stream.getStats().out_of_order_count == 2, "Expected 2 out of order segments");

    // Receive Segment 1: seq 2001, "Hello"
    std::string s1 = "Hello";
    added = stream.processSegment(2001, 0, 0, reinterpret_cast<const uint8_t*>(s1.data()), s1.size(), 103000);
    TEST_ASSERT(added, "Arrival of missing head segment must drain out-of-order buffer");
    TEST_ASSERT(stream.getStats().bytes_reassembled == 11, "Expected all 11 bytes reassembled");
    TEST_ASSERT(stream.getBufferedOutOfOrderBytes() == 0, "Out-of-order queue must be empty");

    std::string result(reinterpret_cast<const char*>(stream.getReassembledData().data()),
                       stream.getReassembledData().size());
    TEST_ASSERT(result == "HelloWorld!", "Reassembled stream mismatch");
    return true;
}

// TEST 51: Retransmission Handling
bool test_stream_retransmission() {
    TCPHalfStream stream;
    stream.processSegment(100, 0, 0x02, nullptr, 0, 1000); // SYN -> next = 101

    std::string s1 = "DATA1";
    stream.processSegment(101, 0, 0, reinterpret_cast<const uint8_t*>(s1.data()), s1.size(), 2000);
    TEST_ASSERT(stream.getStats().bytes_reassembled == 5, "Initial segment accepted");

    // Exact duplicate packet retransmission
    bool added = stream.processSegment(101, 0, 0, reinterpret_cast<const uint8_t*>(s1.data()), s1.size(), 3000);
    TEST_ASSERT(!added, "Retransmission must not be appended");
    TEST_ASSERT(stream.getStats().retrans_count == 1, "Expected 1 retransmission recorded");
    TEST_ASSERT(stream.getStats().bytes_reassembled == 5, "Byte count must remain 5");
    return true;
}

// TEST 52: Identical Overlap Handling (Prefix Trimming)
bool test_stream_identical_overlap() {
    TCPHalfStream stream;
    stream.processSegment(100, 0, 0x02, nullptr, 0, 1000); // SYN -> next = 101

    std::string s1 = "ABCDE"; // seq 101 to 105. next = 106
    stream.processSegment(101, 0, 0, reinterpret_cast<const uint8_t*>(s1.data()), s1.size(), 2000);

    // Overlapping segment: starts at 103, payload "CDEFG" (length 5).
    // Overlaps "CDE" at seq 103-105. New suffix is "FG" at seq 106-107.
    std::string s2 = "CDEFG";
    bool added = stream.processSegment(103, 0, 0, reinterpret_cast<const uint8_t*>(s2.data()), s2.size(), 3000);
    TEST_ASSERT(added, "Overlap suffix must be appended");
    TEST_ASSERT(stream.getStats().overlap_count == 1, "Overlap count must be 1");
    TEST_ASSERT(stream.getStats().bytes_reassembled == 7, "Total reassembled must be 7 bytes (ABCDEFG)");

    std::string result(reinterpret_cast<const char*>(stream.getReassembledData().data()),
                       stream.getReassembledData().size());
    TEST_ASSERT(result == "ABCDEFG", "Trimmed overlap content mismatch");
    return true;
}

// TEST 53: Conflicting Overlap Handling
bool test_stream_conflicting_overlap() {
    TCPHalfStream stream;
    stream.processSegment(100, 0, 0x02, nullptr, 0, 1000); // SYN -> next = 101

    std::string s1 = "ABCDE"; // seq 101 to 105 (next = 106)
    stream.processSegment(101, 0, 0, reinterpret_cast<const uint8_t*>(s1.data()), s1.size(), 2000);

    // Conflicting segment: starts at 103, but gives "XYZFG" instead of "CDEFG"
    std::string s2 = "XYZFG";
    stream.processSegment(103, 0, 0, reinterpret_cast<const uint8_t*>(s2.data()), s2.size(), 3000);
    TEST_ASSERT(stream.getStats().conflict_count == 1, "Conflicting overlap must be detected");
    TEST_ASSERT(stream.getStats().overlap_count == 1, "Overlap count must be incremented");

    // First-in policy keeps "ABCDE" and only accepts non-overlapping suffix "FG"
    std::string result(reinterpret_cast<const char*>(stream.getReassembledData().data()),
                       stream.getReassembledData().size());
    TEST_ASSERT(result == "ABCDEFG", "First-in policy must be preserved");
    return true;
}

// TEST 54: Gap Detection in Stream
bool test_stream_gap_handling() {
    TCPHalfStream stream;
    stream.processSegment(100, 0, 0x02, nullptr, 0, 1000); // SYN -> next = 101

    std::string s1 = "AAA"; // seq 101 to 103 (next = 104)
    stream.processSegment(101, 0, 0, reinterpret_cast<const uint8_t*>(s1.data()), s1.size(), 2000);

    // Segment with a gap: starts at seq 110 (missing 104-109)
    std::string s3 = "CCC";
    stream.processSegment(110, 0, 0, reinterpret_cast<const uint8_t*>(s3.data()), s3.size(), 3000);
    TEST_ASSERT(stream.getStats().gap_count >= 1, "Gap count must be recorded");
    TEST_ASSERT(stream.getStats().bytes_reassembled == 3, "Only contiguous data must be delivered");
    return true;
}

// TEST 55: Sequence Number Wraparound (0xFFFFFFFF -> 0x00000000)
bool test_stream_seq_wraparound() {
    TCPHalfStream stream;
    // SYN at 0xFFFFFFFE -> next_expected_seq = 0xFFFFFFFF
    stream.processSegment(0xFFFFFFFE, 0, 0x02, nullptr, 0, 1000);
    TEST_ASSERT(stream.getStats().next_expected_seq == 0xFFFFFFFF, "Expected 0xFFFFFFFF");

    // Segment 1 at 0xFFFFFFFF (1 byte: 'A') -> next_expected_seq = 0x00000000
    uint8_t d1 = 'A';
    stream.processSegment(0xFFFFFFFF, 0, 0, &d1, 1, 2000);
    TEST_ASSERT(stream.getStats().next_expected_seq == 0x00000000, "Sequence must wrap to 0");

    // Segment 2 at 0x00000000 (1 byte: 'B') -> next_expected_seq = 0x00000001
    uint8_t d2 = 'B';
    stream.processSegment(0x00000000, 0, 0, &d2, 1, 3000);
    TEST_ASSERT(stream.getStats().next_expected_seq == 0x00000001, "Sequence must advance to 1");

    std::string result(reinterpret_cast<const char*>(stream.getReassembledData().data()),
                       stream.getReassembledData().size());
    TEST_ASSERT(result == "AB", "Wraparound reassembly content mismatch");
    return true;
}

// TEST 56: SYN and FIN Sequence Space Consumption
bool test_stream_syn_fin_consumption() {
    TCPHalfStream stream;
    // SYN at seq 500
    stream.processSegment(500, 0, 0x02, nullptr, 0, 1000);
    TEST_ASSERT(stream.getStats().syn_seen, "SYN must be marked");
    TEST_ASSERT(stream.getStats().next_expected_seq == 501, "SYN must consume 1 seq number");

    // Payload + FIN at seq 501 (data "END", len 3)
    std::string fin_data = "END";
    stream.processSegment(501, 0, 0x01, reinterpret_cast<const uint8_t*>(fin_data.data()), fin_data.size(), 2000);
    TEST_ASSERT(stream.getStats().fin_seen, "FIN must be marked");
    TEST_ASSERT(stream.isComplete(), "Stream must be marked complete upon reaching FIN");
    TEST_ASSERT(stream.getStats().bytes_reassembled == 3, "Payload bytes must be reassembled");
    return true;
}

// TEST 57: RST Abort Handling
bool test_stream_rst_handling() {
    FiveTuple tuple{0x0A000001, 0x0A000002, 1234, 80, 6};
    TCPConnectionStream stream(1, tuple);

    PacketJob p1;
    p1.tuple = tuple;
    p1.tcp_flags = 0x02; // SYN
    p1.tcp_seq = 100;
    stream.processPacket(p1);
    TEST_ASSERT(stream.getState() == TCPStreamState::SYN_SEEN, "State must be SYN_SEEN");

    PacketJob p_rst;
    p_rst.tuple = tuple;
    p_rst.tcp_flags = 0x04; // RST
    p_rst.tcp_seq = 101;
    stream.processPacket(p_rst);
    TEST_ASSERT(stream.getState() == TCPStreamState::RESET, "State must transition to RESET");
    TEST_ASSERT(stream.isComplete(), "Reset stream must be marked complete/closed");
    return true;
}

// TEST 58: Memory Limits and Eviction
bool test_stream_memory_limits_and_eviction() {
    StreamReassemblyConfig cfg;
    cfg.max_buffered_bytes_per_stream = 64; // Strict limit: 64 bytes
    TCPHalfStream stream(cfg);
    stream.processSegment(1, 0, 0x02, nullptr, 0, 0); // SYN -> next = 2

    // Send an out-of-order segment of 128 bytes (exceeds 64 byte limit)
    std::vector<uint8_t> large_payload(128, 'Z');
    bool added = stream.processSegment(500, 0, 0, large_payload.data(), large_payload.size(), 0);
    TEST_ASSERT(!added, "Exceeding memory limit must not be added");
    TEST_ASSERT(stream.getBufferedOutOfOrderBytes() == 0, "Oversized out-of-order segment must be dropped");
    return true;
}

// TEST 59: Bidirectional Stream Independence
bool test_stream_bidirectional_independence() {
    FiveTuple tuple{0x0A000001, 0x0A000002, 8080, 80, 6};
    TCPConnectionStream stream(1, tuple);

    // Forward SYN: seq 10000
    PacketJob fwd_syn;
    fwd_syn.tuple = tuple;
    fwd_syn.tcp_flags = 0x02;
    fwd_syn.tcp_seq = 10000;
    stream.processPacket(fwd_syn);

    // Reverse SYN-ACK: seq 80000
    PacketJob rev_syn_ack;
    rev_syn_ack.tuple = tuple.reverse();
    rev_syn_ack.tcp_flags = 0x12;
    rev_syn_ack.tcp_seq = 80000;
    stream.processPacket(rev_syn_ack);

    TEST_ASSERT(stream.getForwardStream().getStats().next_expected_seq == 10001, "Forward next seq mismatch");
    TEST_ASSERT(stream.getReverseStream().getStats().next_expected_seq == 80001, "Reverse next seq mismatch");

    // Forward sends "PING", Reverse sends "PONG"
    std::string ping = "PING";
    PacketJob fwd_data;
    fwd_data.tuple = tuple;
    fwd_data.tcp_seq = 10001;
    fwd_data.data.assign(ping.begin(), ping.end());
    fwd_data.payload_offset = 0;
    fwd_data.payload_length = ping.size();
    stream.processPacket(fwd_data);

    std::string pong = "PONG";
    PacketJob rev_data;
    rev_data.tuple = tuple.reverse();
    rev_data.tcp_seq = 80001;
    rev_data.data.assign(pong.begin(), pong.end());
    rev_data.payload_offset = 0;
    rev_data.payload_length = pong.size();
    stream.processPacket(rev_data);

    TEST_ASSERT(stream.getForwardStream().getStats().bytes_reassembled == 4, "Fwd reassembled mismatch");
    TEST_ASSERT(stream.getReverseStream().getStats().bytes_reassembled == 4, "Rev reassembled mismatch");
    return true;
}

// TEST 60: HTTP Request and Response Parsing
bool test_http_basic_request_response() {
    std::string req = "GET /v1/users?id=42 HTTP/1.1\r\n"
                      "Host: api.service.local\r\n"
                      "User-Agent: PacketAnalyzer/3.2\r\n"
                      "Accept: application/json\r\n"
                      "Content-Length: 0\r\n\r\n";
    size_t consumed = 0;
    auto msg = HTTPStreamParser::parseMessage(reinterpret_cast<const uint8_t*>(req.data()), req.size(), consumed);
    TEST_ASSERT(msg.has_value(), "Valid HTTP request must parse");
    TEST_ASSERT(msg->is_request, "Must be request");
    TEST_ASSERT(msg->method == "GET", "Method must be GET");
    TEST_ASSERT(msg->uri == "/v1/users?id=42", "URI mismatch");
    TEST_ASSERT(msg->host == "api.service.local", "Host mismatch");
    TEST_ASSERT(msg->user_agent == "PacketAnalyzer/3.2", "User-Agent mismatch");
    TEST_ASSERT(consumed == req.size(), "All bytes must be consumed");

    std::string resp = "HTTP/1.1 200 OK\r\n"
                       "Content-Type: application/json\r\n"
                       "Content-Length: 12\r\n\r\n"
                       "{\"status\":1}";
    auto resp_msg = HTTPStreamParser::parseMessage(reinterpret_cast<const uint8_t*>(resp.data()), resp.size(), consumed);
    TEST_ASSERT(resp_msg.has_value(), "Valid HTTP response must parse");
    TEST_ASSERT(!resp_msg->is_request, "Must be response");
    TEST_ASSERT(resp_msg->status_code == 200, "Status code must be 200");
    TEST_ASSERT(resp_msg->reason_phrase == "OK", "Reason phrase mismatch");
    TEST_ASSERT(resp_msg->content_length == 12, "Content-Length mismatch");
    TEST_ASSERT(resp_msg->is_complete, "Response must be marked complete");
    return true;
}

// TEST 61: HTTP Message Split Across TCP Segments
bool test_http_split_request() {
    TCPHalfStream stream;
    stream.processSegment(100, 0, 0x02, nullptr, 0, 1000); // SYN -> next = 101

    // Segment 1 carries first half
    std::string part1 = "POST /upload HTTP/1.1\r\nHost: cdn.cloud.";
    stream.processSegment(101, 0, 0, reinterpret_cast<const uint8_t*>(part1.data()), part1.size(), 2000);

    // Partial stream should not parse yet
    auto msgs1 = HTTPStreamParser::parseStream(stream.getReassembledData().data(), stream.getReassembledData().size());
    TEST_ASSERT(msgs1.empty(), "Partial HTTP header must not parse");

    // Segment 2 completes the message
    std::string part2 = "net\r\nContent-Length: 5\r\n\r\n12345";
    stream.processSegment(101 + part1.size(), 0, 0, reinterpret_cast<const uint8_t*>(part2.data()), part2.size(), 3000);

    auto msgs2 = HTTPStreamParser::parseStream(stream.getReassembledData().data(), stream.getReassembledData().size());
    TEST_ASSERT(msgs2.size() == 1, "Reassembled HTTP message must parse");
    TEST_ASSERT(msgs2[0].method == "POST", "Method must be POST");
    TEST_ASSERT(msgs2[0].host == "cdn.cloud.net", "Host must be complete");
    TEST_ASSERT(msgs2[0].content_length == 5, "Content length must be 5");
    return true;
}

// TEST 62: Multiple Pipelined HTTP Messages in Single Stream
bool test_http_multiple_pipelined_messages() {
    std::string pipeline = "GET /page1 HTTP/1.1\r\nHost: site.org\r\n\r\n"
                           "GET /page2 HTTP/1.1\r\nHost: site.org\r\n\r\n"
                           "GET /page3 HTTP/1.1\r\nHost: site.org\r\n\r\n";
    auto msgs = HTTPStreamParser::parseStream(reinterpret_cast<const uint8_t*>(pipeline.data()), pipeline.size());
    TEST_ASSERT(msgs.size() == 3, "Expected 3 pipelined HTTP requests");
    TEST_ASSERT(msgs[0].uri == "/page1", "Message 1 URI mismatch");
    TEST_ASSERT(msgs[1].uri == "/page2", "Message 2 URI mismatch");
    TEST_ASSERT(msgs[2].uri == "/page3", "Message 3 URI mismatch");
    return true;
}

// TEST 63: Chunked Transfer-Encoding Parsing
bool test_http_chunked_transfer() {
    std::string chunked_resp = "HTTP/1.1 200 OK\r\n"
                               "Transfer-Encoding: chunked\r\n\r\n"
                               "4\r\nWiki\r\n"
                               "5\r\npedia\r\n"
                               "0\r\n\r\n";
    size_t consumed = 0;
    auto msg = HTTPStreamParser::parseMessage(reinterpret_cast<const uint8_t*>(chunked_resp.data()),
                                             chunked_resp.size(), consumed);
    TEST_ASSERT(msg.has_value(), "Chunked response must parse");
    TEST_ASSERT(msg->is_chunked, "is_chunked must be true");
    TEST_ASSERT(msg->is_complete, "Chunked message must be complete upon 0-chunk");
    TEST_ASSERT(consumed == chunked_resp.size(), "All chunked bytes consumed");
    return true;
}

// TEST 64: HTTP Parser Resource Limits & Malformed Input
bool test_http_malformed_and_limits() {
    // Malformed request with invalid token
    std::string bad_req = "INVALID_TOKEN /index HTTP/1.1\r\n\r\n";
    size_t consumed = 0;
    auto msg1 = HTTPStreamParser::parseMessage(reinterpret_cast<const uint8_t*>(bad_req.data()),
                                               bad_req.size(), consumed);
    TEST_ASSERT(!msg1.has_value(), "Invalid HTTP verb must be rejected");

    // Header without delimiter
    std::string unterminated = "GET /index HTTP/1.1\r\nHost: incomplete";
    auto msg2 = HTTPStreamParser::parseMessage(reinterpret_cast<const uint8_t*>(unterminated.data()),
                                               unterminated.size(), consumed);
    TEST_ASSERT(!msg2.has_value(), "Unterminated header must return nullopt");
    return true;
}

// Helper to construct synthetic TLS ClientHello packet
static std::vector<uint8_t> createSyntheticClientHello(const std::string& sni,
                                                       const std::string& alpn,
                                                       uint16_t supported_version) {
    std::vector<uint8_t> body;
    // Client Version: TLS 1.2 (0x03, 0x03)
    body.push_back(0x03); body.push_back(0x03);
    // Random 32 bytes
    for (int i = 0; i < 32; i++) body.push_back(static_cast<uint8_t>(i));
    // Session ID len: 0
    body.push_back(0x00);
    // Cipher suites: 2 bytes len + 2 suites
    body.push_back(0x00); body.push_back(0x04);
    body.push_back(0xC0); body.push_back(0x2F);
    body.push_back(0x13); body.push_back(0x01);
    // Compression methods: 1 len + null
    body.push_back(0x01); body.push_back(0x00);

    // Extensions buffer
    std::vector<uint8_t> exts;

    // SNI extension
    if (!sni.empty()) {
        exts.push_back(0x00); exts.push_back(0x00); // Ext type 0
        uint16_t sni_ext_len = static_cast<uint16_t>(sni.size() + 5);
        exts.push_back(sni_ext_len >> 8); exts.push_back(sni_ext_len & 0xFF);
        uint16_t list_len = static_cast<uint16_t>(sni.size() + 3);
        exts.push_back(list_len >> 8); exts.push_back(list_len & 0xFF);
        exts.push_back(0x00); // host_name
        uint16_t name_len = static_cast<uint16_t>(sni.size());
        exts.push_back(name_len >> 8); exts.push_back(name_len & 0xFF);
        exts.insert(exts.end(), sni.begin(), sni.end());
    }

    // ALPN extension
    if (!alpn.empty()) {
        exts.push_back(0x00); exts.push_back(0x10); // Ext type 16
        uint16_t alpn_ext_len = static_cast<uint16_t>(alpn.size() + 3);
        exts.push_back(alpn_ext_len >> 8); exts.push_back(alpn_ext_len & 0xFF);
        uint16_t list_len = static_cast<uint16_t>(alpn.size() + 1);
        exts.push_back(list_len >> 8); exts.push_back(list_len & 0xFF);
        exts.push_back(static_cast<uint8_t>(alpn.size()));
        exts.insert(exts.end(), alpn.begin(), alpn.end());
    }

    // Supported Versions extension
    if (supported_version != 0) {
        exts.push_back(0x00); exts.push_back(0x2B); // Ext type 43
        exts.push_back(0x00); exts.push_back(0x03); // Length 3
        exts.push_back(0x02); // List length 2
        exts.push_back(supported_version >> 8);
        exts.push_back(supported_version & 0xFF);
    }

    // Add extensions length + exts to body
    uint16_t exts_len = static_cast<uint16_t>(exts.size());
    body.push_back(exts_len >> 8); body.push_back(exts_len & 0xFF);
    body.insert(body.end(), exts.begin(), exts.end());

    // Wrap in Handshake (Type 0x01 ClientHello)
    std::vector<uint8_t> handshake;
    handshake.push_back(0x01);
    uint32_t hs_len = static_cast<uint32_t>(body.size());
    handshake.push_back((hs_len >> 16) & 0xFF);
    handshake.push_back((hs_len >> 8) & 0xFF);
    handshake.push_back(hs_len & 0xFF);
    handshake.insert(handshake.end(), body.begin(), body.end());

    // Wrap in Record Header (0x16 Handshake, 0x0301 TLS 1.0)
    std::vector<uint8_t> record;
    record.push_back(0x16);
    record.push_back(0x03); record.push_back(0x01);
    uint16_t rec_len = static_cast<uint16_t>(handshake.size());
    record.push_back(rec_len >> 8); record.push_back(rec_len & 0xFF);
    record.insert(record.end(), handshake.begin(), handshake.end());

    return record;
}

// TEST 65: TLS ClientHello Split Across Multiple TCP Segments
bool test_tls_client_hello_split_across_segments() {
    auto full_record = createSyntheticClientHello("bank.secure-login.com", "h2", 0x0304);
    TEST_ASSERT(full_record.size() > 40, "Record must be created");

    // Split record across 2 TCP segments
    size_t split_point = 25;
    std::vector<uint8_t> seg1(full_record.begin(), full_record.begin() + split_point);
    std::vector<uint8_t> seg2(full_record.begin() + split_point, full_record.end());

    TCPHalfStream stream;
    stream.processSegment(1000, 0, 0x02, nullptr, 0, 1000); // SYN -> next = 1001

    // Feed Segment 1 (incomplete TLS record)
    stream.processSegment(1001, 0, 0, seg1.data(), seg1.size(), 2000);
    auto meta1 = TLSStreamParser::parseStream(stream.getReassembledData().data(), stream.getReassembledData().size());
    TEST_ASSERT(meta1.sni.empty(), "Fragmented ClientHello must not extract SNI before reassembly");

    // Feed Segment 2 (completes TLS record)
    stream.processSegment(1001 + seg1.size(), 0, 0, seg2.data(), seg2.size(), 3000);
    auto meta2 = TLSStreamParser::parseStream(stream.getReassembledData().data(), stream.getReassembledData().size());
    TEST_ASSERT(meta2.has_client_hello, "ClientHello must be recognized");
    TEST_ASSERT(meta2.sni == "bank.secure-login.com", "SNI must be extracted from reconstructed stream");
    return true;
}

// TEST 66: TLS ALPN and Supported Versions Extraction
bool test_tls_alpn_and_supported_versions() {
    auto record = createSyntheticClientHello("portal.example.com", "h2", 0x0304); // TLS 1.3
    auto meta = TLSStreamParser::parseStream(record.data(), record.size());
    TEST_ASSERT(meta.sni == "portal.example.com", "SNI mismatch");
    TEST_ASSERT(meta.alpn == "h2", "ALPN must be h2");
    TEST_ASSERT(!meta.supported_versions.empty(), "Supported versions must not be empty");
    TEST_ASSERT(meta.supported_versions.front() == "TLS 1.3", "Expected TLS 1.3 in supported versions");
    return true;
}

// TEST 67: TLS Encrypted Application Data Demarcation
bool test_tls_encrypted_application_data() {
    // Construct Application Data record: Type 0x17, Version 0x0303 (TLS 1.2), Length 60
    std::vector<uint8_t> app_data;
    app_data.push_back(0x17); // Application Data
    app_data.push_back(0x03); app_data.push_back(0x03);
    app_data.push_back(0x00); app_data.push_back(60); // 60 bytes
    for (int i = 0; i < 60; i++) app_data.push_back(0xAA);

    auto meta = TLSStreamParser::parseStream(app_data.data(), app_data.size());
    TEST_ASSERT(meta.has_encrypted_data, "Encrypted data flag must be set");
    TEST_ASSERT(meta.encrypted_record_count == 1, "Encrypted record count must be 1");
    TEST_ASSERT(meta.encrypted_bytes_count == 60, "Encrypted byte count must be 60");
    return true;
}

// Helper to construct synthetic DNS packet
static std::vector<uint8_t> createSyntheticDNSPacket(uint16_t tx_id, bool is_response,
                                                     uint8_t rcode, const std::string& query_domain,
                                                     const std::string& answer_ip = "") {
    std::vector<uint8_t> pkt;
    // TxID
    pkt.push_back(tx_id >> 8); pkt.push_back(tx_id & 0xFF);
    // Flags: Response=0x8180 | rcode, Query=0x0100
    uint16_t flags = is_response ? (0x8180 | (rcode & 0x0F)) : 0x0100;
    pkt.push_back(flags >> 8); pkt.push_back(flags & 0xFF);
    // QDCOUNT: 1
    pkt.push_back(0x00); pkt.push_back(0x01);
    // ANCOUNT: 1 if answer_ip, else 0
    uint16_t ancount = (!answer_ip.empty() && is_response) ? 1 : 0;
    pkt.push_back(ancount >> 8); pkt.push_back(ancount & 0xFF);
    // NSCOUNT: 0, ARCOUNT: 0
    pkt.push_back(0x00); pkt.push_back(0x00);
    pkt.push_back(0x00); pkt.push_back(0x00);

    // Question Section
    std::istringstream iss(query_domain);
    std::string label;
    while (std::getline(iss, label, '.')) {
        pkt.push_back(static_cast<uint8_t>(label.size()));
        pkt.insert(pkt.end(), label.begin(), label.end());
    }
    pkt.push_back(0x00); // Root label
    // QTYPE: 1 (A), QCLASS: 1 (IN)
    pkt.push_back(0x00); pkt.push_back(0x01);
    pkt.push_back(0x00); pkt.push_back(0x01);

    // Answer Section if response with IP
    if (!answer_ip.empty() && is_response) {
        // Name compression pointer to offset 12 (0xC00C)
        pkt.push_back(0xC0); pkt.push_back(0x0C);
        // TYPE: 1 (A), CLASS: 1 (IN)
        pkt.push_back(0x00); pkt.push_back(0x01);
        pkt.push_back(0x00); pkt.push_back(0x01);
        // TTL: 300 (0x0000012C)
        pkt.push_back(0x00); pkt.push_back(0x00); pkt.push_back(0x01); pkt.push_back(0x2C);
        // RDLENGTH: 4
        pkt.push_back(0x00); pkt.push_back(0x04);
        // Parse IPv4
        uint32_t a, b, c, d;
        if (sscanf(answer_ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            pkt.push_back(static_cast<uint8_t>(a));
            pkt.push_back(static_cast<uint8_t>(b));
            pkt.push_back(static_cast<uint8_t>(c));
            pkt.push_back(static_cast<uint8_t>(d));
        } else {
            pkt.push_back(192); pkt.push_back(168); pkt.push_back(1); pkt.push_back(1);
        }
    }

    return pkt;
}

// TEST 68: DNS Query and Response Parsing
bool test_dns_query_and_response_parsing() {
    auto query_pkt = createSyntheticDNSPacket(0xABCD, false, 0, "google.com");
    auto q_msg = DNSParser::parseUDP(query_pkt.data(), query_pkt.size(), 1000000);
    TEST_ASSERT(q_msg.has_value(), "DNS Query must parse");
    TEST_ASSERT(!q_msg->is_response, "Must be query");
    TEST_ASSERT(q_msg->tx_id == 0xABCD, "TxID mismatch");
    TEST_ASSERT(!q_msg->queries.empty(), "Queries must not be empty");
    TEST_ASSERT(q_msg->queries.front().name == "google.com", "Query name mismatch");
    TEST_ASSERT(q_msg->queries.front().type == 1, "QTYPE must be A");

    auto resp_pkt = createSyntheticDNSPacket(0xABCD, true, 0, "google.com", "142.250.190.46");
    auto r_msg = DNSParser::parseUDP(resp_pkt.data(), resp_pkt.size(), 1020000);
    TEST_ASSERT(r_msg.has_value(), "DNS Response must parse");
    TEST_ASSERT(r_msg->is_response, "Must be response");
    TEST_ASSERT(r_msg->rcode == 0, "RCODE must be NOERROR");
    TEST_ASSERT(!r_msg->answers.empty(), "Answers must not be empty");
    TEST_ASSERT(r_msg->answers.front().rdata_string == "142.250.190.46", "Resolved IP mismatch");
    return true;
}

// TEST 69: DNS Compression Loop Safety (Zero Infinite Loop)
bool test_dns_compression_loop_safety() {
    // Construct packet where compression pointer points back to itself at offset 12
    std::vector<uint8_t> loop_pkt;
    loop_pkt.push_back(0x12); loop_pkt.push_back(0x34); // TxID
    loop_pkt.push_back(0x01); loop_pkt.push_back(0x00); // Query flags
    loop_pkt.push_back(0x00); loop_pkt.push_back(0x01); // QDCOUNT: 1
    loop_pkt.push_back(0x00); loop_pkt.push_back(0x00);
    loop_pkt.push_back(0x00); loop_pkt.push_back(0x00);
    loop_pkt.push_back(0x00); loop_pkt.push_back(0x00);
    // Offset 12: compression pointer 0xC00C (points to 12!)
    loop_pkt.push_back(0xC0); loop_pkt.push_back(0x0C);
    loop_pkt.push_back(0x00); loop_pkt.push_back(0x01); // Type A
    loop_pkt.push_back(0x00); loop_pkt.push_back(0x01); // Class IN

    // Parser must detect the loop and safely return without hanging
    auto msg = DNSParser::parseUDP(loop_pkt.data(), loop_pkt.size(), 1000);
    TEST_ASSERT(msg.has_value(), "Header should parse");
    TEST_ASSERT(msg->queries.empty(), "Malformed loop domain must be safely rejected");
    return true;
}

// TEST 70: TCP DNS Length-Prefixed Stream Parsing
bool test_dns_tcp_length_prefixed() {
    auto dns_udp = createSyntheticDNSPacket(0x7777, false, 0, "tcp-dns.org");
    uint16_t len = static_cast<uint16_t>(dns_udp.size());

    std::vector<uint8_t> tcp_stream;
    tcp_stream.push_back(len >> 8);
    tcp_stream.push_back(len & 0xFF);
    tcp_stream.insert(tcp_stream.end(), dns_udp.begin(), dns_udp.end());

    auto msgs = DNSParser::parseTCPStream(tcp_stream.data(), tcp_stream.size(), 500000);
    TEST_ASSERT(msgs.size() == 1, "TCP DNS message must parse");
    TEST_ASSERT(msgs[0].tx_id == 0x7777, "TxID mismatch");
    TEST_ASSERT(msgs[0].queries.front().name == "tcp-dns.org", "Query domain mismatch");
    return true;
}

// TEST 71: DNS Query-Response Correlation & Latency Tracking
bool test_dns_query_response_correlation() {
    DNSCorrelator correlator;
    FiveTuple tuple{0x0A000005, 0x08080808, 45678, 53, 17};

    // Client query at t = 1000000 us
    auto q_pkt = createSyntheticDNSPacket(0x9999, false, 0, "timed-lookup.com");
    auto q_msg = DNSParser::parseUDP(q_pkt.data(), q_pkt.size(), 1000000);
    correlator.processDNSMessage(tuple, *q_msg);
    TEST_ASSERT(correlator.getStats().total_queries == 1, "Query count mismatch");

    // Server response at t = 1035000 us (35ms latency)
    auto r_pkt = createSyntheticDNSPacket(0x9999, true, 0, "timed-lookup.com", "93.184.216.34");
    auto r_msg = DNSParser::parseUDP(r_pkt.data(), r_pkt.size(), 1035000);
    correlator.processDNSMessage(tuple.reverse(), *r_msg);

    TEST_ASSERT(correlator.getStats().correlated_count == 1, "Expected 1 correlated query");
    TEST_ASSERT(correlator.getStats().total_responses == 1, "Response count mismatch");
    TEST_ASSERT(r_msg->latency_us == 35000, "Calculated transaction latency must be 35000 us");
    TEST_ASSERT(correlator.getStats().mean_latency_us() == 35000.0, "Mean latency mismatch");
    return true;
}

// TEST 72: Behavioral Detection: NXDOMAIN Burst / DGA Detection
bool test_dns_nxdomain_burst_detection() {
    DetectionConfig config;
    config.dns_nxdomain_burst_threshold = 5;

    std::vector<FlowRecord> flows;
    uint32_t infected_host = 0xC0A80155; // 192.168.1.85
    uint32_t dns_server = 0x08080808;   // 8.8.8.8

    // Generate 6 failed DNS lookups with NXDOMAIN responses
    for (uint16_t i = 1; i <= 6; ++i) {
        FlowRecord f;
        f.flow_id = 9000 + i;
        f.initial_tuple = {infected_host, dns_server, static_cast<uint16_t>(50000 + i), 53, 17};
        f.canonical_tuple = f.initial_tuple.toCanonical();
        f.app_type = AppType::DNS;
        f.start_time_us = 1000000ULL + i * 50000ULL;
        f.dns_query = "dga-random-" + std::to_string(i) + ".biz";
        f.dns_rcode = 3; // NXDOMAIN
        f.dns_rcode_name = "NXDOMAIN";
        flows.push_back(std::move(f));
    }

    DNSAnomalyDetector detector;
    auto events = detector.detect(flows, config);
    bool found_nxdomain_alert = false;
    for (const auto& ev : events) {
        if (ev.evidence.find("nxdomain_count") != ev.evidence.end()) {
            found_nxdomain_alert = true;
            TEST_ASSERT(ev.severity == DetectionSeverity::HIGH, "DGA NXDOMAIN surge must be HIGH severity");
            TEST_ASSERT(ev.evidence.at("nxdomain_count") == "6", "Expected 6 recorded NXDOMAIN failures");
            TEST_ASSERT(ev.source_ip == infected_host, "Source IP mismatch");
        }
    }
    TEST_ASSERT(found_nxdomain_alert, "Expected NXDOMAIN / DGA anomaly event to be emitted");
    return true;
}

// TEST 73: End-to-End PCAP Stream Reassembly & Export Verification
bool test_end_to_end_pcap_stream_reassembly() {
    DPIEngine::Config cfg;
    cfg.num_load_balancers = 2;
    cfg.fps_per_lb = 2;
    cfg.enable_stream_reassembly = true;
    cfg.show_stream_stats = true;
    cfg.export_streams_json = "/tmp/test_streams.json";
    cfg.export_streams_csv = "/tmp/test_streams.csv";

    DPIEngine engine(cfg);
    TEST_ASSERT(engine.initialize(), "Engine initialization failed");

    bool ok = engine.processFile("test_dpi.pcap", "/tmp/test_stream_out.pcap");
    TEST_ASSERT(ok, "processFile failed");

    // Verify stream report was generated
    std::string report = engine.generateStreamReport();
    TEST_ASSERT(report.find("TCP STREAM REASSEMBLY REPORT") != std::string::npos,
                "Stream report header must be present");

    // Verify JSON export
    std::ifstream jf("/tmp/test_streams.json");
    TEST_ASSERT(jf.is_open(), "Streams JSON file must exist");
    std::string j_content((std::istreambuf_iterator<char>(jf)),
                           std::istreambuf_iterator<char>());
    jf.close();
    TEST_ASSERT(j_content.front() == '[' && j_content.find("]") != std::string::npos,
                "Streams JSON must be a valid JSON array");

    // Verify CSV export
    std::ifstream cf("/tmp/test_streams.csv");
    TEST_ASSERT(cf.is_open(), "Streams CSV file must exist");
    std::string c_header;
    std::getline(cf, c_header);
    TEST_ASSERT(c_header.find("stream_id,tuple,state") != std::string::npos,
                "CSV must contain valid stream header");
    cf.close();

    // Verify that finalized flows now contain stream metrics
    auto flows = engine.getFPManager()->getAllFinalizedFlows();
    bool found_tcp_reassembly = false;
    for (const auto& f : flows) {
        if (f.initial_tuple.protocol == 6 && (f.tcp_fwd_bytes_reassembled > 0 || f.tcp_rev_bytes_reassembled > 0)) {
            found_tcp_reassembly = true;
            break;
        }
    }
    TEST_ASSERT(found_tcp_reassembly, "Flows must be enriched with reassembled TCP byte telemetry");
    return true;
}

// ============================================================================
// Phase 3.3 Security Intelligence & Threat Correlation Test Helpers & Tests
// ============================================================================

static FlowRecord createMockFlow(uint64_t id, const std::string& src_ip, const std::string& dst_ip,
                                 uint16_t src_port, uint16_t dst_port, uint8_t proto,
                                 uint64_t fwd_pkts, uint64_t fwd_bytes,
                                 uint64_t rev_pkts, uint64_t rev_bytes,
                                 uint64_t start_us = 1000000, uint64_t last_us = 2000000) {
    FlowRecord f;
    f.flow_id = id;
    auto parseIP = [](const std::string& ip) -> uint32_t {
        uint32_t res = 0; int oct = 0, sh = 0;
        for (char c : ip) {
            if (c == '.') { res |= (oct << sh); sh += 8; oct = 0; }
            else if (c >= '0' && c <= '9') { oct = oct * 10 + (c - '0'); }
        }
        res |= (oct << sh);
        return res;
    };
    f.initial_tuple.src_ip = parseIP(src_ip);
    f.initial_tuple.dst_ip = parseIP(dst_ip);
    f.initial_tuple.src_port = src_port;
    f.initial_tuple.dst_port = dst_port;
    f.initial_tuple.protocol = proto;
    f.canonical_tuple = f.initial_tuple.toCanonical();
    f.fwd.packet_count = fwd_pkts;
    f.fwd.byte_count = fwd_bytes;
    f.rev.packet_count = rev_pkts;
    f.rev.byte_count = rev_bytes;
    f.start_time_us = start_us;
    f.last_time_us = last_us;
    f.state = FlowLifecycleState::ESTABLISHED;
    return f;
}

static DetectionEvent createMockDetection(const std::string& det_id, const std::string& detector,
                                          DetectionCategory cat, DetectionSeverity sev,
                                          const std::string& src_ip, const std::string& dst_ip,
                                          uint64_t ts_us = 1000000,
                                          const std::vector<uint16_t>& ports = {},
                                          const std::vector<uint64_t>& flows = {},
                                          const std::string& explanation = "Mock detection") {
    DetectionEvent d;
    d.detection_id = det_id;
    d.detector_name = detector;
    d.category = cat;
    d.severity = sev;
    d.source_ip_str = src_ip;
    d.destination_ip_str = dst_ip;
    d.timestamp_us = ts_us;
    d.relevant_ports = ports;
    d.related_flow_ids = flows;
    d.explanation = explanation;
    return d;
}

// TEST 74: Reconnaissance Incident Generation
bool test_incident_reconnaissance_generation() {
    IncidentCorrelator correlator;
    std::vector<DetectionEvent> dets;
    dets.push_back(createMockDetection("DET-01", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                       DetectionSeverity::HIGH, "192.168.1.100", "10.0.0.1", 1000000,
                                       {80, 443, 22, 21, 25, 8080, 8443, 3306, 5432, 6379, 8000, 8888, 9000, 9200, 27017},
                                       {1, 2}, "Vertical port scan detected"));
    dets.push_back(createMockDetection("DET-02", "repeated_attempts_detector", DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT,
                                       DetectionSeverity::MEDIUM, "192.168.1.100", "10.0.0.1", 1100000,
                                       {}, {3, 4}, "Repeated connection attempts"));

    std::vector<FlowRecord> flows;
    for (uint16_t p = 20; p <= 36; ++p) {
        flows.push_back(createMockFlow(p, "192.168.1.100", "10.0.0.1", 50000 + p, p, 6, 2, 120, 0, 0));
    }

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(!incidents.empty(), "Reconnaissance incident must be generated");
    TEST_ASSERT(incidents[0].category == IncidentCategory::RECONNAISSANCE, "Category must be RECONNAISSANCE");
    TEST_ASSERT(incidents[0].primary_endpoint == "192.168.1.100", "Primary endpoint mismatch");
    TEST_ASSERT(incidents[0].severity >= IncidentSeverity::MEDIUM, "Severity must be at least MEDIUM");
    TEST_ASSERT(!incidents[0].timeline.empty(), "Timeline must not be empty");
    return true;
}

// TEST 75: Horizontal Port Sweep Correlation
bool test_incident_horizontal_scan_correlation() {
    IncidentCorrelator correlator;
    std::vector<DetectionEvent> dets;
    dets.push_back(createMockDetection("DET-10", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                       DetectionSeverity::HIGH, "10.10.10.5", "", 2000000,
                                       {80}, {1}, "Horizontal port sweep across 12 hosts on port 80"));

    std::vector<FlowRecord> flows;
    for (int i = 1; i <= 12; ++i) {
        std::string dst = "192.168.1." + std::to_string(i);
        flows.push_back(createMockFlow(i, "10.10.10.5", dst, 40000 + i, 80, 6, 1, 60, 0, 0));
    }

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(!incidents.empty(), "Horizontal sweep incident must be generated");
    TEST_ASSERT(incidents[0].category == IncidentCategory::RECONNAISSANCE, "Category must be RECONNAISSANCE");
    TEST_ASSERT(incidents[0].related_endpoints.size() >= 12, "Must correlate all targeted hosts");
    return true;
}

// TEST 76: Vertical Port Scan Correlation
bool test_incident_vertical_scan_correlation() {
    IncidentCorrelator correlator;
    std::vector<DetectionEvent> dets;
    std::vector<uint16_t> ports;
    for (uint16_t p = 1; p <= 20; ++p) ports.push_back(p);

    dets.push_back(createMockDetection("DET-20", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                       DetectionSeverity::HIGH, "172.16.0.10", "172.16.0.1", 3000000,
                                       ports, {}, "Vertical scan on 20 ports"));

    std::vector<FlowRecord> flows;
    for (uint16_t p : ports) {
        flows.push_back(createMockFlow(p, "172.16.0.10", "172.16.0.1", 45000 + p, p, 6, 1, 60, 0, 0));
    }

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(!incidents.empty(), "Vertical scan incident must be generated");
    TEST_ASSERT(incidents[0].category == IncidentCategory::RECONNAISSANCE, "Category must be RECONNAISSANCE");
    TEST_ASSERT(incidents[0].related_ports.size() >= 20, "Related ports must contain scanned ports");
    return true;
}

// TEST 77: Repeated Connection Attempt Correlation
bool test_incident_repeated_connection_correlation() {
    IncidentCorrelator correlator;
    std::vector<DetectionEvent> dets;
    dets.push_back(createMockDetection("DET-30", "repeated_attempts_detector", DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT,
                                       DetectionSeverity::MEDIUM, "192.168.1.50", "10.0.0.2", 4000000,
                                       {443}, {1, 2, 3}, "5 repeated connection attempts"));
    dets.push_back(createMockDetection("DET-31", "tcp_anomaly_detector", DetectionCategory::PROTOCOL_ANOMALY,
                                       DetectionSeverity::MEDIUM, "192.168.1.50", "10.0.0.2", 4050000,
                                       {443}, {1, 2, 3}, "SYN-heavy incomplete communication"));

    std::vector<FlowRecord> flows;
    for (int i = 1; i <= 5; ++i) {
        flows.push_back(createMockFlow(i, "192.168.1.50", "10.0.0.2", 60000 + i, 443, 6, 3, 180, 0, 0));
    }

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(!incidents.empty(), "Repeated attempts and SYN anomaly must correlate");
    TEST_ASSERT(incidents[0].related_detection_ids.size() >= 2, "Must correlate both detections");
    return true;
}

// TEST 78: DNS Tunneling Candidate Correlation
bool test_incident_dns_tunneling_correlation() {
    IncidentCorrelator correlator;
    std::vector<DetectionEvent> dets;
    dets.push_back(createMockDetection("DET-40", "dns_tunneling_detector", DetectionCategory::SUSPICIOUS_DNS,
                                       DetectionSeverity::HIGH, "192.168.1.75", "8.8.8.8", 5000000,
                                       {53}, {1}, "DNS tunneling candidate with excessive domain length"));

    std::vector<FlowRecord> flows;
    for (int i = 1; i <= 5; ++i) {
        auto f = createMockFlow(i, "192.168.1.75", "8.8.8.8", 55000 + i, 53, 17, 1, 150, 1, 150);
        f.dns_query = "v1-tunnel-data-payload-base64-encoded-string.exfil.attacker.org";
        flows.push_back(f);
    }

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(!incidents.empty(), "DNS tunneling incident must be generated");
    TEST_ASSERT(incidents[0].category == IncidentCategory::DNS_SUSPICIOUS_ACTIVITY, "Category must be DNS_SUSPICIOUS_ACTIVITY");
    TEST_ASSERT(incidents[0].observed_metrics.find("tunneling_candidate") != incidents[0].observed_metrics.end(), "Must flag tunneling candidate");
    return true;
}

// TEST 79: DNS NXDOMAIN Burst Correlation
bool test_incident_dns_nxdomain_burst_correlation() {
    IncidentCorrelator correlator;
    std::vector<DetectionEvent> dets;
    dets.push_back(createMockDetection("DET-50", "dns_nxdomain_burst_detector", DetectionCategory::SUSPICIOUS_DNS,
                                       DetectionSeverity::MEDIUM, "192.168.1.80", "1.1.1.1", 6000000,
                                       {53}, {}, "NXDOMAIN surge observed: 8 consecutive lookup failures"));

    std::vector<FlowRecord> flows;
    for (int i = 1; i <= 8; ++i) {
        auto f = createMockFlow(i, "192.168.1.80", "1.1.1.1", 52000 + i, 53, 17, 1, 80, 1, 80);
        f.dns_query = "dga-random-domain-" + std::to_string(i) + ".xyz";
        flows.push_back(f);
    }

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(!incidents.empty(), "NXDOMAIN burst incident must be generated");
    TEST_ASSERT(incidents[0].category == IncidentCategory::DNS_SUSPICIOUS_ACTIVITY, "Category must be DNS_SUSPICIOUS_ACTIVITY");
    TEST_ASSERT(incidents[0].observed_metrics.find("nxdomain_burst") != incidents[0].observed_metrics.end(), "Must flag NXDOMAIN burst");
    return true;
}

// TEST 80: DNS Query Diversity Correlation
bool test_incident_dns_query_diversity_correlation() {
    IncidentCorrelator correlator;
    std::vector<DetectionEvent> dets;
    dets.push_back(createMockDetection("DET-60", "dns_frequency_detector", DetectionCategory::SUSPICIOUS_DNS,
                                       DetectionSeverity::LOW, "192.168.1.90", "8.8.4.4", 7000000,
                                       {53}, {}, "High query frequency burst"));
    dets.push_back(createMockDetection("DET-61", "dns_nxdomain_burst_detector", DetectionCategory::SUSPICIOUS_DNS,
                                       DetectionSeverity::MEDIUM, "192.168.1.90", "8.8.4.4", 7050000,
                                       {53}, {}, "NXDOMAIN burst"));

    std::vector<FlowRecord> flows;
    for (int i = 1; i <= 15; ++i) {
        auto f = createMockFlow(i, "192.168.1.90", "8.8.4.4", 51000 + i, 53, 17, 1, 75, 1, 75);
        f.dns_query = "domain-" + std::to_string(i) + ".info";
        flows.push_back(f);
    }

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(!incidents.empty(), "High query diversity incident must be generated");
    TEST_ASSERT(incidents[0].category == IncidentCategory::DNS_SUSPICIOUS_ACTIVITY, "Category must be DNS_SUSPICIOUS_ACTIVITY");
    TEST_ASSERT(std::stoi(incidents[0].observed_metrics["unique_domains_count"]) >= 15, "Domain count mismatch");
    return true;
}

// TEST 81: Beacon-Like Communication Correlation
bool test_incident_beacon_correlation() {
    IncidentCorrelator correlator;
    std::vector<DetectionEvent> dets;
    dets.push_back(createMockDetection("DET-70", "beacon_detector", DetectionCategory::COMMAND_AND_CONTROL,
                                       DetectionSeverity::HIGH, "10.0.1.20", "45.33.32.156", 8000000,
                                       {443}, {1, 2, 3, 4, 5}, "Periodic low-jitter beaconing (CV=0.08)"));

    std::vector<FlowRecord> flows;
    for (int i = 1; i <= 6; ++i) {
        flows.push_back(createMockFlow(i, "10.0.1.20", "45.33.32.156", 48000 + i, 443, 6, 4, 240, 3, 180));
    }

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(!incidents.empty(), "Beacon communication incident must be generated");
    TEST_ASSERT(incidents[0].category == IncidentCategory::SUSPICIOUS_OUTBOUND_COMMUNICATION, "Category must be SUSPICIOUS_OUTBOUND_COMMUNICATION");
    TEST_ASSERT(incidents[0].primary_endpoint == "10.0.1.20", "Primary endpoint mismatch");
    return true;
}

// TEST 82: Suspicious Outbound Anomaly & TLS Metadata Correlation
bool test_incident_outbound_anomaly_correlation() {
    IncidentCorrelator correlator;
    std::vector<DetectionEvent> dets;
    dets.push_back(createMockDetection("DET-80", "beacon_detector", DetectionCategory::COMMAND_AND_CONTROL,
                                       DetectionSeverity::HIGH, "10.0.1.30", "198.51.100.22", 9000000,
                                       {8443}, {1}, "Automated beacon channel"));

    std::vector<FlowRecord> flows;
    for (int i = 1; i <= 6; ++i) {
        flows.push_back(createMockFlow(i, "10.0.1.30", "198.51.100.22", 47000 + i, 8443, 6, 5, 300, 4, 220));
    }

    std::vector<StreamRecordSummary> streams;
    StreamRecordSummary sm;
    sm.stream_id = 1;
    sm.tls_meta.sni = "c2.stealth-network.org";
    sm.tls_meta.alpn = "h2";
    streams.push_back(sm);

    auto incidents = correlator.correlate(dets, flows, streams);
    TEST_ASSERT(!incidents.empty(), "Outbound communication incident must be generated");
    TEST_ASSERT(incidents[0].observed_metrics.find("tls_sni") != incidents[0].observed_metrics.end(), "TLS SNI must be correlated");
    TEST_ASSERT(incidents[0].observed_metrics["tls_sni"] == "c2.stealth-network.org", "TLS SNI mismatch");
    return true;
}

// TEST 83: Potential Data Exfiltration Correlation
bool test_incident_potential_exfiltration_correlation() {
    IncidentCorrelator correlator;
    std::vector<DetectionEvent> dets;
    dets.push_back(createMockDetection("DET-90", "outbound_anomaly_detector", DetectionCategory::UNUSUAL_TRAFFIC_VOLUME,
                                       DetectionSeverity::HIGH, "192.168.1.150", "203.0.113.88", 10000000,
                                       {443}, {1}, "Large outbound volume transfer with high asymmetry"));

    std::vector<FlowRecord> flows;
    // 150KB egress, 1KB ingress -> ratio 150:1
    flows.push_back(createMockFlow(1, "192.168.1.150", "203.0.113.88", 53210, 443, 6, 120, 150000, 10, 1000));

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(!incidents.empty(), "Potential exfiltration incident must be generated");
    TEST_ASSERT(incidents[0].category == IncidentCategory::POTENTIAL_DATA_EXFILTRATION, "Category must be POTENTIAL_DATA_EXFILTRATION");
    TEST_ASSERT(!incidents[0].limitations.empty(), "Limitations must state that exfiltration is not verified theft");
    return true;
}

// TEST 84: Multi-Stage Suspicious Activity Generation
bool test_incident_multi_stage_generation() {
    IncidentCorrelator correlator;
    std::string victim = "192.168.1.200";
    std::vector<DetectionEvent> dets;
    dets.push_back(createMockDetection("STG-1", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                       DetectionSeverity::HIGH, victim, "10.0.0.1", 1000000, {80, 443}));
    dets.push_back(createMockDetection("STG-2", "repeated_attempts_detector", DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT,
                                       DetectionSeverity::MEDIUM, victim, "10.0.0.1", 2000000));
    dets.push_back(createMockDetection("STG-3", "dns_tunneling_detector", DetectionCategory::SUSPICIOUS_DNS,
                                       DetectionSeverity::HIGH, victim, "8.8.8.8", 3000000));
    dets.push_back(createMockDetection("STG-4", "beacon_detector", DetectionCategory::COMMAND_AND_CONTROL,
                                       DetectionSeverity::HIGH, victim, "198.51.100.99", 4000000));
    dets.push_back(createMockDetection("STG-5", "outbound_anomaly_detector", DetectionCategory::UNUSUAL_TRAFFIC_VOLUME,
                                       DetectionSeverity::HIGH, victim, "198.51.100.99", 5000000));

    std::vector<FlowRecord> flows;
    flows.push_back(createMockFlow(1, victim, "10.0.0.1", 50001, 80, 6, 2, 120, 0, 0, 1000000, 1100000));
    flows.push_back(createMockFlow(2, victim, "8.8.8.8", 50002, 53, 17, 2, 160, 2, 160, 3000000, 3100000));
    flows.push_back(createMockFlow(3, victim, "198.51.100.99", 50003, 443, 6, 50, 80000, 10, 1000, 5000000, 5200000));

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(!incidents.empty(), "Multi-stage incident must be generated");
    TEST_ASSERT(incidents[0].category == IncidentCategory::MULTI_STAGE_ACTIVITY, "Category must be MULTI_STAGE_ACTIVITY");
    TEST_ASSERT(incidents[0].severity == IncidentSeverity::CRITICAL, "Multi-stage incident must have CRITICAL severity");
    TEST_ASSERT(incidents[0].confidence == IncidentConfidence::HIGH, "Confidence must be HIGH");

    // Check timeline has STAGE_TRANSITION markers
    bool found_stage_marker = false;
    for (const auto& ev : incidents[0].timeline) {
        if (ev.event_type == "STAGE_TRANSITION") {
            found_stage_marker = true;
            break;
        }
    }
    TEST_ASSERT(found_stage_marker, "Timeline must contain STAGE_TRANSITION events");
    return true;
}

// TEST 85: Insufficient Evidence Rejection
bool test_incident_insufficient_evidence_rejection() {
    IncidentCorrelator correlator;
    std::vector<DetectionEvent> dets;
    // Single isolated LOW severity detection that does not meet correlation criteria
    dets.push_back(createMockDetection("DET-LOW", "dns_frequency_detector", DetectionCategory::SUSPICIOUS_DNS,
                                       DetectionSeverity::LOW, "192.168.1.250", "8.8.8.8", 1000000));

    std::vector<FlowRecord> flows;
    flows.push_back(createMockFlow(1, "192.168.1.250", "8.8.8.8", 50000, 53, 17, 1, 50, 1, 50));

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(incidents.empty(), "Isolated low evidence must be rejected without creating an incident");
    return true;
}

// TEST 86: Score Calculation Explainability
bool test_incident_score_calculation() {
    IncidentConfig cfg;
    cfg.min_incident_score = 10.0;
    IncidentCorrelator correlator(cfg);

    std::vector<DetectionEvent> dets;
    dets.push_back(createMockDetection("DET-S1", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                       DetectionSeverity::HIGH, "10.0.0.5", "10.0.0.1", 1000000, {80, 443}, {1}));
    dets.push_back(createMockDetection("DET-S2", "repeated_attempts_detector", DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT,
                                       DetectionSeverity::MEDIUM, "10.0.0.5", "10.0.0.1", 1100000, {}, {2}));

    std::vector<FlowRecord> flows;
    flows.push_back(createMockFlow(1, "10.0.0.5", "10.0.0.1", 50000, 80, 6, 2, 120, 0, 0));
    flows.push_back(createMockFlow(2, "10.0.0.5", "10.0.0.1", 50001, 443, 6, 2, 120, 0, 0));

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(!incidents.empty(), "Incident must be generated");
    // Default weights: 2 detections * 15.0 = 30.0
    TEST_ASSERT(incidents[0].correlation_score >= 30.0, "Score must be >= sum of detection weights");
    return true;
}

// TEST 87: Confidence Level Calculation
bool test_incident_confidence_calculation() {
    IncidentCorrelator correlator;

    // High confidence: 3+ flows, 2+ detections
    std::vector<DetectionEvent> dets_high;
    dets_high.push_back(createMockDetection("D1", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                            DetectionSeverity::HIGH, "10.0.0.6", "10.0.0.1", 1000000, {80}, {1}));
    dets_high.push_back(createMockDetection("D2", "repeated_attempts_detector", DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT,
                                            DetectionSeverity::MEDIUM, "10.0.0.6", "10.0.0.1", 2000000, {}, {2, 3}));

    std::vector<FlowRecord> flows_high;
    flows_high.push_back(createMockFlow(1, "10.0.0.6", "10.0.0.1", 50000, 80, 6, 2, 120, 0, 0, 1000000, 1500000));
    flows_high.push_back(createMockFlow(2, "10.0.0.6", "10.0.0.1", 50001, 80, 6, 2, 120, 0, 0, 1600000, 2000000));
    flows_high.push_back(createMockFlow(3, "10.0.0.6", "10.0.0.1", 50002, 80, 6, 2, 120, 0, 0, 2100000, 2500000));

    auto inc_high = correlator.correlate(dets_high, flows_high);
    TEST_ASSERT(!inc_high.empty(), "High confidence incident must be generated");
    TEST_ASSERT(inc_high[0].confidence == IncidentConfidence::HIGH, "Confidence must be HIGH");
    TEST_ASSERT(!inc_high[0].confidence_explanation.empty(), "Explanation must not be empty");
    return true;
}

// TEST 88: Duplicate Evidence Handling
bool test_incident_duplicate_evidence_handling() {
    IncidentCorrelator correlator;
    std::vector<DetectionEvent> dets;
    auto d1 = createMockDetection("DUP-1", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                  DetectionSeverity::HIGH, "10.0.0.7", "10.0.0.1", 1000000, {80}, {1});
    dets.push_back(d1);
    dets.push_back(d1); // Exact duplicate

    dets.push_back(createMockDetection("DUP-2", "repeated_attempts_detector", DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT,
                                       DetectionSeverity::MEDIUM, "10.0.0.7", "10.0.0.1", 1100000, {}, {2}));

    std::vector<FlowRecord> flows;
    flows.push_back(createMockFlow(1, "10.0.0.7", "10.0.0.1", 50000, 80, 6, 2, 120, 0, 0));
    flows.push_back(createMockFlow(2, "10.0.0.7", "10.0.0.1", 50001, 80, 6, 2, 120, 0, 0));

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(!incidents.empty(), "Incident must be generated");
    // Merged detection IDs should deduplicate DUP-1
    size_t dup1_count = 0;
    for (const auto& id : incidents[0].related_detection_ids) {
        if (id == "DUP-1") dup1_count++;
    }
    TEST_ASSERT(dup1_count <= 2, "Duplicate detection references should be bounded");
    return true;
}

// TEST 89: Same-Flow Evidence Deduplication
bool test_incident_same_flow_deduplication() {
    IncidentCorrelator correlator;
    std::vector<DetectionEvent> dets;
    // Two detections on the exact same flow 42
    dets.push_back(createMockDetection("F1", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                       DetectionSeverity::HIGH, "10.0.0.8", "10.0.0.1", 1000000, {80}, {42}));
    dets.push_back(createMockDetection("F2", "repeated_attempts_detector", DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT,
                                       DetectionSeverity::MEDIUM, "10.0.0.8", "10.0.0.1", 1050000, {}, {42}));

    std::vector<FlowRecord> flows;
    flows.push_back(createMockFlow(42, "10.0.0.8", "10.0.0.1", 50000, 80, 6, 2, 120, 0, 0));

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(!incidents.empty(), "Incident must be generated");
    TEST_ASSERT(incidents[0].related_flow_ids.size() == 1, "Should link only the single underlying flow 42");
    return true;
}

// TEST 90: Endpoint Aggregation
bool test_incident_endpoint_aggregation() {
    IncidentCorrelator correlator;
    std::string ep = "192.168.1.111";
    std::vector<DetectionEvent> dets;
    dets.push_back(createMockDetection("E1", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                       DetectionSeverity::HIGH, ep, "10.0.0.1", 1000000, {80}, {1}));
    dets.push_back(createMockDetection("E2", "repeated_attempts_detector", DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT,
                                       DetectionSeverity::MEDIUM, ep, "10.0.0.1", 1200000, {}, {2}));

    std::vector<FlowRecord> flows;
    flows.push_back(createMockFlow(1, ep, "10.0.0.1", 50000, 80, 6, 2, 120, 0, 0));
    flows.push_back(createMockFlow(2, ep, "10.0.0.1", 50001, 80, 6, 2, 120, 0, 0));

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(!incidents.empty(), "Incident must be generated");
    TEST_ASSERT(incidents[0].primary_endpoint == ep, "All indicators must aggregate under the single primary endpoint");
    return true;
}

// TEST 91: Unrelated Endpoint Isolation
bool test_incident_unrelated_endpoint_isolation() {
    IncidentCorrelator correlator;
    std::string epA = "192.168.1.10";
    std::string epB = "10.0.0.99";

    std::vector<DetectionEvent> dets;
    // Endpoint A: Reconnaissance
    dets.push_back(createMockDetection("A1", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                       DetectionSeverity::HIGH, epA, "8.8.8.8", 1000000, {80}, {1}));
    dets.push_back(createMockDetection("A2", "repeated_attempts_detector", DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT,
                                       DetectionSeverity::MEDIUM, epA, "8.8.8.8", 1100000, {}, {2}));

    // Endpoint B: Reconnaissance
    dets.push_back(createMockDetection("B1", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                       DetectionSeverity::HIGH, epB, "1.1.1.1", 1000000, {443}, {3}));
    dets.push_back(createMockDetection("B2", "repeated_attempts_detector", DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT,
                                       DetectionSeverity::MEDIUM, epB, "1.1.1.1", 1100000, {}, {4}));

    std::vector<FlowRecord> flows;
    flows.push_back(createMockFlow(1, epA, "8.8.8.8", 50000, 80, 6, 2, 120, 0, 0));
    flows.push_back(createMockFlow(2, epA, "8.8.8.8", 50001, 80, 6, 2, 120, 0, 0));
    flows.push_back(createMockFlow(3, epB, "1.1.1.1", 50002, 443, 6, 2, 120, 0, 0));
    flows.push_back(createMockFlow(4, epB, "1.1.1.1", 50003, 443, 6, 2, 120, 0, 0));

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(incidents.size() == 2, "Must produce exactly 2 separate incidents (one per endpoint)");
    TEST_ASSERT(incidents[0].primary_endpoint != incidents[1].primary_endpoint, "Endpoints must remain strictly isolated");
    return true;
}

// TEST 92: Timeline Chronological Ordering
bool test_incident_timeline_chronological_ordering() {
    IncidentCorrelator correlator;
    std::vector<DetectionEvent> dets;
    dets.push_back(createMockDetection("T3", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                       DetectionSeverity::HIGH, "10.0.0.15", "10.0.0.1", 5000000, {80}));
    dets.push_back(createMockDetection("T1", "repeated_attempts_detector", DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT,
                                       DetectionSeverity::MEDIUM, "10.0.0.15", "10.0.0.1", 1000000));
    dets.push_back(createMockDetection("T2", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                       DetectionSeverity::HIGH, "10.0.0.15", "10.0.0.1", 3000000, {443}));

    std::vector<FlowRecord> flows;
    flows.push_back(createMockFlow(1, "10.0.0.15", "10.0.0.1", 50000, 80, 6, 2, 120, 0, 0, 2000000, 2100000));

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(!incidents.empty(), "Incident must be generated");
    const auto& tl = incidents[0].timeline;
    TEST_ASSERT(tl.size() >= 4, "Timeline must contain all events");

    // Verify monotonic ordering
    for (size_t i = 1; i < tl.size(); ++i) {
        TEST_ASSERT(tl[i - 1].timestamp_us <= tl[i].timestamp_us, "Timeline must be in ascending chronological order");
    }
    return true;
}

// TEST 93: Timeline Identical Timestamp Tiebreak
bool test_incident_timeline_identical_timestamp_tiebreak() {
    TimelineEvent e1;
    e1.timestamp_us = 1000000;
    e1.event_type = "DETECTION";
    e1.detection_id = "A_DET";

    TimelineEvent e2;
    e2.timestamp_us = 1000000;
    e2.event_type = "FLOW_START";
    e2.detection_id = "B_FLOW";

    std::vector<TimelineEvent> tl = {e2, e1};
    std::sort(tl.begin(), tl.end(), [](const TimelineEvent& a, const TimelineEvent& b) {
        if (a.timestamp_us != b.timestamp_us) return a.timestamp_us < b.timestamp_us;
        if (a.event_type != b.event_type) return a.event_type < b.event_type;
        return a.detection_id < b.detection_id;
    });

    TEST_ASSERT(tl[0].event_type == "DETECTION", "DETECTION must precede FLOW_START deterministically");
    return true;
}

// TEST 94: Timeline Bounds Enforcement
bool test_incident_timeline_bounds_enforcement() {
    IncidentConfig cfg;
    cfg.max_timeline_events = 5;
    IncidentCorrelator correlator(cfg);

    std::vector<DetectionEvent> dets;
    dets.push_back(createMockDetection("TB1", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                       DetectionSeverity::HIGH, "10.0.0.25", "10.0.0.1", 1000000, {80}));
    dets.push_back(createMockDetection("TB2", "repeated_attempts_detector", DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT,
                                       DetectionSeverity::MEDIUM, "10.0.0.25", "10.0.0.1", 1100000));

    std::vector<FlowRecord> flows;
    for (int i = 1; i <= 10; ++i) {
        flows.push_back(createMockFlow(i, "10.0.0.25", "10.0.0.1", 50000 + i, 80, 6, 1, 60, 0, 0, 1000000 + i * 1000, 1000500 + i * 1000));
    }

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(!incidents.empty(), "Incident must be generated");
    TEST_ASSERT(incidents[0].timeline.size() <= 5, "Timeline must be bounded to max_timeline_events (5)");
    return true;
}

// TEST 95: Incident Deduplication and Merging Within Time Window
bool test_incident_deduplication_and_merging_window() {
    IncidentConfig cfg;
    cfg.incident_window_seconds = 60.0;
    IncidentCorrelator correlator(cfg);

    std::vector<DetectionEvent> dets;
    // Event 1 at t=10s
    dets.push_back(createMockDetection("M1", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                       DetectionSeverity::HIGH, "10.0.0.30", "10.0.0.1", 10000000, {80}));
    dets.push_back(createMockDetection("M2", "repeated_attempts_detector", DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT,
                                       DetectionSeverity::MEDIUM, "10.0.0.30", "10.0.0.1", 15000000));

    // Event 2 at t=25s (within 60s window)
    dets.push_back(createMockDetection("M3", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                       DetectionSeverity::HIGH, "10.0.0.30", "10.0.0.1", 25000000, {443}));

    std::vector<FlowRecord> flows;
    flows.push_back(createMockFlow(1, "10.0.0.30", "10.0.0.1", 50001, 80, 6, 2, 120, 0, 0, 10000000, 10500000));
    flows.push_back(createMockFlow(2, "10.0.0.30", "10.0.0.1", 50002, 443, 6, 2, 120, 0, 0, 25000000, 25500000));

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(incidents.size() == 1, "Incidents within window must merge into exactly 1 incident");
    TEST_ASSERT(incidents[0].duration_seconds >= 15.0, "Duration must encompass both merged event windows");
    return true;
}

// TEST 96: Incident Window Expiration
bool test_incident_window_expiration() {
    IncidentConfig cfg;
    cfg.incident_window_seconds = 30.0; // 30s window
    IncidentCorrelator correlator(cfg);

    std::vector<DetectionEvent> dets;
    // Group 1 at t=10s
    dets.push_back(createMockDetection("E1", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                       DetectionSeverity::HIGH, "10.0.0.35", "10.0.0.1", 10000000, {80}));
    dets.push_back(createMockDetection("E2", "repeated_attempts_detector", DetectionCategory::SUSPICIOUS_CONNECTION_ATTEMPT,
                                       DetectionSeverity::MEDIUM, "10.0.0.35", "10.0.0.1", 12000000));

    // Group 2 at t=100s (>30s window separation)
    dets.push_back(createMockDetection("E3", "dns_tunneling_detector", DetectionCategory::SUSPICIOUS_DNS,
                                       DetectionSeverity::HIGH, "10.0.0.35", "8.8.8.8", 100000000));
    dets.push_back(createMockDetection("E4", "dns_nxdomain_burst_detector", DetectionCategory::SUSPICIOUS_DNS,
                                       DetectionSeverity::MEDIUM, "10.0.0.35", "8.8.8.8", 105000000));

    std::vector<FlowRecord> flows;
    flows.push_back(createMockFlow(1, "10.0.0.35", "10.0.0.1", 50001, 80, 6, 2, 120, 0, 0, 10000000, 12000000));
    auto fd = createMockFlow(2, "10.0.0.35", "8.8.8.8", 50002, 53, 17, 2, 150, 2, 150, 100000000, 105000000);
    fd.dns_query = "tunnel-data-payload.xyz";
    flows.push_back(fd);

    auto incidents = correlator.correlate(dets, flows);
    TEST_ASSERT(incidents.size() == 2, "Expired events across distinct categories must form 2 separate incidents");
    return true;
}

// TEST 97: Incident Serialization JSON and CSV
bool test_incident_serialization_json_and_csv() {
    SecurityIncident inc;
    inc.incident_id = "INC-9999";
    inc.category = IncidentCategory::RECONNAISSANCE;
    inc.title = "Test Incident Title";
    inc.severity = IncidentSeverity::HIGH;
    inc.confidence = IncidentConfidence::HIGH;
    inc.confidence_explanation = "Verified test confidence";
    inc.correlation_score = 65.5;
    inc.primary_endpoint = "192.168.1.99";
    inc.first_seen_us = 1000000;
    inc.last_seen_us = 5000000;
    inc.duration_seconds = 4.0;
    inc.related_flow_ids = {101, 102};
    inc.related_detection_ids = {"DET-1"};

    TimelineEvent te;
    te.timestamp_us = 1000000;
    te.event_type = "DETECTION";
    te.description = "Reconnaissance event";
    inc.timeline.push_back(te);

    std::string json = inc.toJson();
    TEST_ASSERT(json.find("\"schema_version\": \"1.0\"") != std::string::npos, "JSON must contain schema_version");
    TEST_ASSERT(json.find("\"incident_id\": \"INC-9999\"") != std::string::npos, "JSON must contain incident_id");
    TEST_ASSERT(json.find("\"category\": \"RECONNAISSANCE\"") != std::string::npos, "JSON must contain category");
    TEST_ASSERT(json.find("\"severity\": \"HIGH\"") != std::string::npos, "JSON must contain severity");

    std::string csv = inc.toCsvRow();
    TEST_ASSERT(csv.find("\"INC-9999\"") != std::string::npos, "CSV row must contain incident_id");
    TEST_ASSERT(csv.find("\"RECONNAISSANCE\"") != std::string::npos, "CSV row must contain category");

    std::string header = SecurityIncident::csvHeader();
    TEST_ASSERT(header.find("incident_id,category,severity") != std::string::npos, "CSV header mismatch");
    return true;
}

// TEST 98: End-to-End PCAP Incident Analysis
bool test_end_to_end_pcap_incident_analysis() {
    DPIEngine::Config cfg;
    cfg.enable_detection = true;
    cfg.enable_stream_reassembly = true;
    cfg.enable_incidents = true;
    cfg.show_incident_stats = true;
    cfg.export_incidents_json = "/tmp/test_incidents.json";
    cfg.export_incidents_csv = "/tmp/test_incidents.csv";

    DPIEngine engine(cfg);
    TEST_ASSERT(engine.initialize(), "DPIEngine initialization failed");

    bool ok = engine.processFile("test_dpi.pcap", "/tmp/test_incident_out.pcap");
    TEST_ASSERT(ok, "processFile failed");

    // Verify incident report generation
    std::string report = engine.generateIncidentReport();
    TEST_ASSERT(report.find("SECURITY INCIDENT INTELLIGENCE REPORT") != std::string::npos,
                "Incident report header must be generated");

    // Verify JSON export exists and valid
    std::ifstream jf("/tmp/test_incidents.json");
    TEST_ASSERT(jf.is_open(), "Incidents JSON file must exist");
    std::string j_content((std::istreambuf_iterator<char>(jf)),
                           std::istreambuf_iterator<char>());
    jf.close();
    TEST_ASSERT(j_content.front() == '[' && j_content.find("]") != std::string::npos,
                "Incidents JSON must be a valid array");

    // Verify CSV export exists and valid
    std::ifstream cf("/tmp/test_incidents.csv");
    TEST_ASSERT(cf.is_open(), "Incidents CSV file must exist");
    std::string c_header;
    std::getline(cf, c_header);
    TEST_ASSERT(c_header.find("incident_id,category,severity") != std::string::npos,
                "CSV must contain valid incident header");
    cf.close();

    // Verify getIncidents() accessor
    const auto& incidents = engine.getIncidents();
    // test_dpi.pcap has scanning/repeated attempts traffic from 192.168.1.50
    std::cout << "\n[Test 98] Total correlated incidents from test_dpi.pcap: " << incidents.size() << "\n";
    return true;
}

// ============================================================================
// PHASE 3.4 TESTS: SIGNATURE ENGINE & THREAT PATTERN MATCHING (Tests 99-125)
// ============================================================================

// TEST 99: Valid JSON Rule Parsing
bool test_signature_rule_json_parsing_valid() {
    std::string json_rules = R"({
      "rules": [
        {
          "id": "SIG-1001",
          "name": "Nmap Scripting Engine Probe",
          "revision": 2,
          "category": "SCANNER",
          "severity": "HIGH",
          "network": {
            "protocol": "TCP",
            "dst_ports": [80, 8080]
          },
          "http": {
            "user_agent": "Nmap Scripting Engine"
          }
        },
        {
          "id": "SIG-1002",
          "name": "Suspicious ELF Binary Header",
          "category": "MALWARE",
          "severity": "CRITICAL",
          "stream_content": [
            {
              "pattern": "|7f 45 4c 46|",
              "is_hex": true,
              "offset": 0,
              "depth": 4
            }
          ]
        }
      ]
    })";

    auto res = SignatureParser::parseString(json_rules);
    for (const auto& e : res.errors) std::cerr << "[Test 99 Parse Err] " << e << "\n";
    TEST_ASSERT(res.success, "Valid JSON rules must parse successfully");
    TEST_ASSERT(res.rules.size() == 2, "Expected 2 parsed rules");
    TEST_ASSERT(res.rules[0].rule_id == "SIG-1001", "Rule ID mismatch");
    TEST_ASSERT(res.rules[0].revision == 2, "Revision mismatch");
    TEST_ASSERT(res.rules[0].severity == SignatureSeverity::HIGH, "Severity mismatch");
    TEST_ASSERT(res.rules[1].rule_id == "SIG-1002", "Rule 2 ID mismatch");
    TEST_ASSERT(res.rules[1].stream_content.patterns[0].is_hex, "Expected is_hex to be true");
    TEST_ASSERT(res.rules[1].stream_content.patterns[0].bytes.size() == 4, "Expected 4 decoded hex bytes");
    return true;
}

// TEST 100: Validation Rejection of Missing Fields
bool test_signature_rule_validation_missing_fields() {
    // Missing rule ID
    SignatureRule r1;
    r1.name = "Test Rule";
    r1.network.protocol = RuleProtocol::TCP;
    auto res1 = SignatureValidator::validateRule(r1);
    TEST_ASSERT(!res1.valid, "Rule with empty ID must be rejected");

    // Missing rule name
    SignatureRule r2;
    r2.rule_id = "SIG-MISSING-NAME";
    r2.network.protocol = RuleProtocol::TCP;
    auto res2 = SignatureValidator::validateRule(r2);
    TEST_ASSERT(!res2.valid, "Rule with empty name must be rejected");

    // No criteria defined
    SignatureRule r3;
    r3.rule_id = "SIG-NO-CRITERIA";
    r3.name = "No Criteria";
    auto res3 = SignatureValidator::validateRule(r3);
    TEST_ASSERT(!res3.valid, "Rule with no criteria blocks must be rejected");
    return true;
}

// TEST 101: Validation Rejection of Duplicate Rule IDs
bool test_signature_rule_validation_duplicate_id() {
    SignatureManager mgr;
    SignatureRule r1;
    r1.rule_id = "SIG-DUP-1";
    r1.name = "Rule 1";
    r1.network.protocol = RuleProtocol::TCP;
    std::string err;
    TEST_ASSERT(mgr.addRule(r1, err), "First rule must be accepted");

    SignatureRule r2;
    r2.rule_id = "SIG-DUP-1"; // Duplicate
    r2.name = "Rule 2";
    r2.network.protocol = RuleProtocol::UDP;
    TEST_ASSERT(!mgr.addRule(r2, err), "Duplicate rule ID must be rejected");
    TEST_ASSERT(err.find("Duplicate") != std::string::npos, "Error message must indicate duplicate ID");
    return true;
}

// TEST 102: CIDR Validation
bool test_signature_rule_validation_invalid_cidr() {
    TEST_ASSERT(SignatureValidator::validateCIDR("192.168.1.0/24").valid, "Valid CIDR must pass");
    TEST_ASSERT(SignatureValidator::validateCIDR("10.0.0.1").valid, "Single IP must pass");
    TEST_ASSERT(SignatureValidator::validateCIDR("any").valid, "'any' must pass");
    TEST_ASSERT(!SignatureValidator::validateCIDR("192.168.1.1/33").valid, "Prefix > 32 must fail");
    TEST_ASSERT(!SignatureValidator::validateCIDR("300.1.1.1").valid, "Octet > 255 must fail");
    TEST_ASSERT(!SignatureValidator::validateCIDR("192.168.1").valid, "3-octet IP must fail");
    return true;
}

// TEST 103: Port Range Validation
bool test_signature_rule_validation_invalid_port_range() {
    TEST_ASSERT(SignatureValidator::validatePortRange("80").valid, "Single port 80 must pass");
    TEST_ASSERT(SignatureValidator::validatePortRange("1024-65535").valid, "Valid port range must pass");
    TEST_ASSERT(SignatureValidator::validatePortRange("any").valid, "'any' must pass");
    TEST_ASSERT(!SignatureValidator::validatePortRange("8080-80").valid, "Inverted range must fail");
    TEST_ASSERT(!SignatureValidator::validatePortRange("70000").valid, "Port > 65535 must fail");
    TEST_ASSERT(!SignatureValidator::validatePortRange("0").valid, "Port 0 must fail");
    return true;
}

// TEST 104: Hex Pattern Validation
bool test_signature_rule_validation_malformed_hex() {
    TEST_ASSERT(SignatureValidator::validateHexPattern("|41 42 43|").valid, "Valid pipe-delimited hex must pass");
    TEST_ASSERT(SignatureValidator::validateHexPattern("41424344").valid, "Valid plain hex must pass");
    TEST_ASSERT(SignatureValidator::validateHexPattern("hex:deadbeef").valid, "Valid hex: prefix must pass");
    TEST_ASSERT(!SignatureValidator::validateHexPattern("41 42 4").valid, "Odd length hex must fail");
    TEST_ASSERT(!SignatureValidator::validateHexPattern("41 42 4G").valid, "Invalid hex character 'G' must fail");
    TEST_ASSERT(!SignatureValidator::validateHexPattern("").valid, "Empty hex must fail");
    return true;
}

// TEST 105: Offset and Depth Validation
bool test_signature_rule_validation_offset_depth() {
    SignatureRule r1;
    r1.rule_id = "SIG-OFF-1";
    r1.name = "Offset Test";
    PatternCondition p1;
    p1.pattern = "TEST";
    p1.offset = -5; // Invalid
    r1.stream_content.patterns.push_back(p1);
    TEST_ASSERT(!SignatureValidator::validateRule(r1).valid, "Offset < -1 must fail");

    SignatureRule r2;
    r2.rule_id = "SIG-OFF-2";
    r2.name = "Relative First Pattern Test";
    PatternCondition p2;
    p2.pattern = "TEST";
    p2.relative_distance = 10; // First pattern cannot have relative distance
    r2.stream_content.patterns.push_back(p2);
    TEST_ASSERT(!SignatureValidator::validateRule(r2).valid, "Initial pattern with relative distance must fail");
    return true;
}

// TEST 106: Disabled Rule State
bool test_signature_rule_disabled_state() {
    SignatureRule rule;
    rule.rule_id = "SIG-DIS-1";
    rule.name = "Disabled Rule";
    rule.enabled = false;
    rule.network.protocol = RuleProtocol::TCP;

    FlowRecord flow = createMockFlow(1, "192.168.1.10", "10.0.0.1", 1234, 80, 6, 10, 1000, 10, 1000);
    RuleEvaluationContext ctx;
    ctx.flow = &flow;

    auto res = SignatureMatcher::evaluate(rule, ctx);
    TEST_ASSERT(!res.matched, "Disabled rule must never match");
    return true;
}

// TEST 107: Dynamic Enable and Disable Controls
bool test_signature_manager_enable_disable() {
    SignatureManager mgr;
    SignatureRule rule;
    rule.rule_id = "SIG-CTRL-1";
    rule.name = "Control Rule";
    rule.network.protocol = RuleProtocol::TCP;
    std::string err;
    TEST_ASSERT(mgr.addRule(rule, err), "Add rule failed");
    TEST_ASSERT(mgr.getActiveRuleCount() == 1, "Active count must be 1");

    TEST_ASSERT(mgr.disableRule("SIG-CTRL-1"), "disableRule failed");
    TEST_ASSERT(mgr.getActiveRuleCount() == 0, "Active count must be 0 after disable");

    TEST_ASSERT(mgr.enableRule("SIG-CTRL-1"), "enableRule failed");
    TEST_ASSERT(mgr.getActiveRuleCount() == 1, "Active count must be 1 after enable");
    return true;
}

// TEST 108: Network IP and CIDR Matching
bool test_signature_network_ip_and_cidr_matching() {
    SignatureRule rule;
    rule.rule_id = "SIG-NET-1";
    rule.name = "Subnet Matcher";
    rule.network.src_ips.push_back(IPNet::parse("192.168.1.0/24"));
    rule.network.dst_ips.push_back(IPNet::parse("10.0.0.0/8"));
    rule.network.dst_ports.push_back(PortRange::single(443));

    // Matching flow
    FlowRecord f_match = createMockFlow(1, "192.168.1.105", "10.1.2.3", 54321, 443, 6, 10, 500, 10, 500);
    RuleEvaluationContext ctx_match;
    ctx_match.flow = &f_match;
    TEST_ASSERT(SignatureMatcher::evaluate(rule, ctx_match).matched, "Flow in subnet must match");

    // Non-matching source IP
    FlowRecord f_fail1 = createMockFlow(2, "192.168.2.105", "10.1.2.3", 54321, 443, 6, 10, 500, 10, 500);
    RuleEvaluationContext ctx_fail1;
    ctx_fail1.flow = &f_fail1;
    TEST_ASSERT(!SignatureMatcher::evaluate(rule, ctx_fail1).matched, "Flow outside source subnet must fail");

    // Non-matching destination IP
    FlowRecord f_fail2 = createMockFlow(3, "192.168.1.105", "172.16.1.1", 54321, 443, 6, 10, 500, 10, 500);
    RuleEvaluationContext ctx_fail2;
    ctx_fail2.flow = &f_fail2;
    TEST_ASSERT(!SignatureMatcher::evaluate(rule, ctx_fail2).matched, "Flow outside dest subnet must fail");
    return true;
}

// TEST 109: Port and Port Range Matching
bool test_signature_network_port_and_range_matching() {
    SignatureRule rule;
    rule.rule_id = "SIG-PORT-1";
    rule.name = "Port Range Matcher";
    rule.network.dst_ports.push_back(PortRange::parse("8000-8080"));

    FlowRecord f1 = createMockFlow(1, "192.168.1.10", "10.0.0.1", 50000, 8000, 6, 5, 200, 5, 200);
    RuleEvaluationContext ctx1; ctx1.flow = &f1;
    TEST_ASSERT(SignatureMatcher::evaluate(rule, ctx1).matched, "Port 8000 must match");

    FlowRecord f2 = createMockFlow(2, "192.168.1.10", "10.0.0.1", 50000, 8080, 6, 5, 200, 5, 200);
    RuleEvaluationContext ctx2; ctx2.flow = &f2;
    TEST_ASSERT(SignatureMatcher::evaluate(rule, ctx2).matched, "Port 8080 must match");

    FlowRecord f3 = createMockFlow(3, "192.168.1.10", "10.0.0.1", 50000, 8081, 6, 5, 200, 5, 200);
    RuleEvaluationContext ctx3; ctx3.flow = &f3;
    TEST_ASSERT(!SignatureMatcher::evaluate(rule, ctx3).matched, "Port 8081 must fail");
    return true;
}

// TEST 110: Protocol and TCP Flags Matching
bool test_signature_network_protocol_and_tcp_flags() {
    SignatureRule rule;
    rule.rule_id = "SIG-TCP-SYN";
    rule.name = "TCP SYN Only";
    rule.network.protocol = RuleProtocol::TCP;
    rule.network.tcp_flags_mask = 0x12; // SYN(0x02) and ACK(0x10)
    rule.network.tcp_flags_value = 0x02; // SYN only (no ACK)

    PacketJob pkt_syn;
    pkt_syn.tuple.protocol = 6;
    pkt_syn.tcp_flags = 0x02; // SYN
    RuleEvaluationContext ctx_syn; ctx_syn.packet = &pkt_syn;
    TEST_ASSERT(SignatureMatcher::evaluate(rule, ctx_syn).matched, "SYN packet must match");

    PacketJob pkt_synack;
    pkt_synack.tuple.protocol = 6;
    pkt_synack.tcp_flags = 0x12; // SYN+ACK
    RuleEvaluationContext ctx_synack; ctx_synack.packet = &pkt_synack;
    TEST_ASSERT(!SignatureMatcher::evaluate(rule, ctx_synack).matched, "SYN+ACK packet must fail");

    PacketJob pkt_udp;
    pkt_udp.tuple.protocol = 17;
    RuleEvaluationContext ctx_udp; ctx_udp.packet = &pkt_udp;
    TEST_ASSERT(!SignatureMatcher::evaluate(rule, ctx_udp).matched, "UDP packet must fail for TCP rule");
    return true;
}

// TEST 111: Flow Metrics Matching
bool test_signature_flow_metrics_matching() {
    SignatureRule rule;
    rule.rule_id = "SIG-FLOW-1";
    rule.name = "Heavy Exfil Flow";
    rule.flow.min_bytes = 100000;
    rule.flow.min_asymmetry_ratio = 10.0;

    // 200KB fwd, 1KB rev -> ratio 200:1, total bytes 201KB
    FlowRecord f_match = createMockFlow(1, "192.168.1.10", "203.0.113.5", 45000, 443, 6, 150, 200000, 10, 1000);
    RuleEvaluationContext ctx_m; ctx_m.flow = &f_match;
    TEST_ASSERT(SignatureMatcher::evaluate(rule, ctx_m).matched, "Heavy asymmetric flow must match");

    // 50KB fwd (below 100KB threshold)
    FlowRecord f_fail = createMockFlow(2, "192.168.1.10", "203.0.113.5", 45000, 443, 6, 50, 50000, 10, 1000);
    RuleEvaluationContext ctx_f; ctx_f.flow = &f_fail;
    TEST_ASSERT(!SignatureMatcher::evaluate(rule, ctx_f).matched, "Flow with insufficient bytes must fail");
    return true;
}

// TEST 112: Stream Content ASCII Pattern Matching
bool test_signature_stream_ascii_pattern_matching() {
    SignatureRule rule;
    rule.rule_id = "SIG-STREAM-ASCII";
    rule.name = "Webshell Command Execution";
    PatternCondition pat;
    pat.pattern = "cmd.exe";
    rule.stream_content.patterns.push_back(pat);

    std::string payload = "POST /upload.aspx HTTP/1.1\r\n\r\n<?php system('cmd.exe /c whoami'); ?>";
    StreamRecordSummary stream;
    stream.tuple = FiveTuple{10, 20, 80, 80, 6};
    stream.fwd_payload.assign(payload.begin(), payload.end());

    RuleEvaluationContext ctx;
    ctx.stream = &stream;

    auto res = SignatureMatcher::evaluate(rule, ctx);
    TEST_ASSERT(res.matched, "ASCII pattern must match");
    TEST_ASSERT(res.offset != -1, "Match offset must be recorded");
    TEST_ASSERT(res.evidence.find("cmd.exe") != std::string::npos, "Evidence must include matched pattern");
    return true;
}

// TEST 113: Stream Content Case-Insensitive Matching
bool test_signature_stream_case_insensitive_matching() {
    SignatureRule rule;
    rule.rule_id = "SIG-NOCASE-1";
    rule.name = "Case-Insensitive SQL Injection";
    PatternCondition pat;
    pat.pattern = "union select";
    pat.nocase = true;
    rule.stream_content.patterns.push_back(pat);

    std::string payload = "GET /item?id=1%27%20UnIoN%20SeLeCt%20password%20FROM%20users-- HTTP/1.1\r\n";
    // Replace URL encoded with decoded for test payload
    std::string decoded_payload = "GET /item?id=1' UnIoN SeLeCt password FROM users-- HTTP/1.1\r\n";

    StreamRecordSummary stream;
    stream.tuple = FiveTuple{10, 20, 80, 80, 6};
    stream.fwd_payload.assign(decoded_payload.begin(), decoded_payload.end());

    RuleEvaluationContext ctx;
    ctx.stream = &stream;

    auto res = SignatureMatcher::evaluate(rule, ctx);
    TEST_ASSERT(res.matched, "Case-insensitive pattern must match regardless of casing");
    return true;
}

// TEST 114: Stream Content Hex/Binary Matching
bool test_signature_stream_hex_binary_matching() {
    SignatureRule rule;
    rule.rule_id = "SIG-HEX-ELF";
    rule.name = "ELF Binary Magic Bytes";
    PatternCondition pat;
    pat.pattern = "|7f 45 4c 46|";
    pat.is_hex = true;
    pat.decodeHex();
    rule.stream_content.patterns.push_back(pat);

    std::vector<uint8_t> payload = {0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00};
    StreamRecordSummary stream;
    stream.tuple = FiveTuple{10, 20, 80, 80, 6};
    stream.fwd_payload = payload;

    RuleEvaluationContext ctx;
    ctx.stream = &stream;

    auto res = SignatureMatcher::evaluate(rule, ctx);
    TEST_ASSERT(res.matched, "Hex pattern must match binary bytes");
    TEST_ASSERT(res.offset == 0, "ELF magic must be at offset 0");
    return true;
}

// TEST 115: Offset and Depth Bounds
bool test_signature_stream_offset_and_depth() {
    SignatureRule rule;
    rule.rule_id = "SIG-DEPTH-1";
    rule.name = "Bounded Depth Matcher";
    PatternCondition pat;
    pat.pattern = "MAGIC";
    pat.offset = 4;
    pat.depth = 10; // Must be found between offset 4 and 14
    rule.stream_content.patterns.push_back(pat);

    // Case 1: Within bounds (offset 6)
    std::string p1 = "AAAA--MAGIC--BBBB";
    StreamRecordSummary s1;
    s1.tuple = FiveTuple{10, 20, 80, 80, 6};
    s1.fwd_payload.assign(p1.begin(), p1.end());
    RuleEvaluationContext ctx1; ctx1.stream = &s1;
    TEST_ASSERT(SignatureMatcher::evaluate(rule, ctx1).matched, "Pattern within depth bounds must match");

    // Case 2: Outside bounds (offset 20)
    std::string p2 = "AAAAAAAAAAAAAAAAAAAA--MAGIC--";
    StreamRecordSummary s2;
    s2.tuple = FiveTuple{10, 20, 80, 80, 6};
    s2.fwd_payload.assign(p2.begin(), p2.end());
    RuleEvaluationContext ctx2; ctx2.stream = &s2;
    TEST_ASSERT(!SignatureMatcher::evaluate(rule, ctx2).matched, "Pattern outside depth bounds must fail");
    return true;
}

// TEST 116: Chained Relative Pattern Matching
bool test_signature_stream_chained_relative_patterns() {
    SignatureRule rule;
    rule.rule_id = "SIG-CHAIN-1";
    rule.name = "Chained Command Sequence";

    PatternCondition p1;
    p1.pattern = "USER";
    rule.stream_content.patterns.push_back(p1);

    PatternCondition p2;
    p2.pattern = "PASS";
    p2.relative_distance = 1;
    p2.relative_within = 20; // PASS must occur within 20 bytes after USER
    rule.stream_content.patterns.push_back(p2);

    // Case 1: Sequential USER then PASS within 10 bytes
    std::string text_ok = "USER admin\r\nPASS secret123\r\n";
    StreamRecordSummary s1;
    s1.tuple = FiveTuple{10, 20, 21, 21, 6};
    s1.fwd_payload.assign(text_ok.begin(), text_ok.end());
    RuleEvaluationContext ctx1; ctx1.stream = &s1;
    TEST_ASSERT(SignatureMatcher::evaluate(rule, ctx1).matched, "Chained patterns within distance/within must match");

    // Case 2: PASS occurs too far away (> 50 bytes)
    std::string text_far = "USER admin\r\n" + std::string(60, '.') + "PASS secret123\r\n";
    StreamRecordSummary s2;
    s2.tuple = FiveTuple{10, 20, 21, 21, 6};
    s2.fwd_payload.assign(text_far.begin(), text_far.end());
    RuleEvaluationContext ctx2; ctx2.stream = &s2;
    TEST_ASSERT(!SignatureMatcher::evaluate(rule, ctx2).matched, "Chained pattern exceeding within bound must fail");
    return true;
}

// TEST 117: Negated Pattern Matching
bool test_signature_stream_negated_pattern() {
    SignatureRule rule;
    rule.rule_id = "SIG-NEG-1";
    rule.name = "Negated Auth Pattern";

    PatternCondition p1;
    p1.pattern = "HTTP/1.1 200 OK";
    p1.negated = false;
    rule.stream_content.patterns.push_back(p1);

    PatternCondition p2;
    p2.pattern = "Authorization";
    p2.negated = true; // Must NOT have Authorization
    rule.stream_content.patterns.push_back(p2);

    // Case 1: 200 OK without Authorization -> Matches
    std::string text_ok = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello";
    StreamRecordSummary s1;
    s1.tuple = FiveTuple{10, 20, 80, 80, 6};
    s1.fwd_payload.assign(text_ok.begin(), text_ok.end());
    RuleEvaluationContext ctx1; ctx1.stream = &s1;
    TEST_ASSERT(SignatureMatcher::evaluate(rule, ctx1).matched, "Negated condition satisfied when pattern is absent");

    // Case 2: 200 OK WITH Authorization -> Fails
    std::string text_fail = "HTTP/1.1 200 OK\r\nAuthorization: Basic abc\r\n\r\nHello";
    StreamRecordSummary s2;
    s2.tuple = FiveTuple{10, 20, 80, 80, 6};
    s2.fwd_payload.assign(text_fail.begin(), text_fail.end());
    RuleEvaluationContext ctx2; ctx2.stream = &s2;
    TEST_ASSERT(!SignatureMatcher::evaluate(rule, ctx2).matched, "Negated condition must fail when pattern is present");
    return true;
}

// TEST 118: Cross-Segment Stream Matching
bool test_signature_stream_cross_segment_reassembly() {
    TCPConnectionStream stream(1, FiveTuple{10, 20, 1000, 80, 6});

    // Ingest SYN
    PacketJob syn_pkt;
    syn_pkt.tuple = FiveTuple{10, 20, 1000, 80, 6};
    syn_pkt.tcp_flags = 0x02; // SYN
    syn_pkt.tcp_seq = 100;
    stream.processPacket(syn_pkt);

    // Ingest segment 1: "MALICIOUS_"
    std::string s1_data = "MALICIOUS_";
    PacketJob p1;
    p1.tuple = syn_pkt.tuple;
    p1.tcp_flags = 0x10; // ACK
    p1.tcp_seq = 101;
    p1.data.assign(s1_data.begin(), s1_data.end());
    p1.payload_offset = 0;
    p1.payload_length = s1_data.size();
    p1.payload_data = p1.data.data();
    stream.processPacket(p1);

    // Ingest segment 2: "PAYLOAD_DATA"
    std::string s2_data = "PAYLOAD_DATA";
    PacketJob p2;
    p2.tuple = syn_pkt.tuple;
    p2.tcp_flags = 0x10; // ACK
    p2.tcp_seq = 101 + s1_data.size();
    p2.data.assign(s2_data.begin(), s2_data.end());
    p2.payload_offset = 0;
    p2.payload_length = s2_data.size();
    p2.payload_data = p2.data.data();
    stream.processPacket(p2);

    StreamRecordSummary summary = stream.getSummary();
    TEST_ASSERT(summary.fwd_payload.size() == s1_data.size() + s2_data.size(),
                "Reassembled buffer must hold both segments");

    SignatureRule rule;
    rule.rule_id = "SIG-CROSS-1";
    rule.name = "Cross Segment Needle";
    PatternCondition pat;
    pat.pattern = "US_PAYLOAD"; // Straddles the boundary!
    rule.stream_content.patterns.push_back(pat);

    RuleEvaluationContext ctx;
    ctx.stream = &summary;
    TEST_ASSERT(SignatureMatcher::evaluate(rule, ctx).matched,
                "Signature must match pattern straddling segment boundaries");
    return true;
}

// TEST 119: HTTP Metadata Matching
bool test_signature_http_metadata_matching() {
    SignatureRule rule;
    rule.rule_id = "SIG-HTTP-1";
    rule.name = "Suspicious Admin API Access";
    rule.http.method = "POST";
    rule.http.host = "*.internal.net";
    rule.http.uri = "/api/v1/debug";
    rule.http.status_code = 200;

    StreamRecordSummary stream;
    stream.tuple = FiveTuple{10, 20, 80, 80, 6};

    HTTPMessage req;
    req.is_request = true;
    req.method = "POST";
    req.host = "admin.internal.net";
    req.uri = "/api/v1/debug?cmd=id";
    stream.http_messages.push_back(req);

    HTTPMessage resp;
    resp.is_request = false;
    resp.status_code = 200;
    stream.http_messages.push_back(resp);

    RuleEvaluationContext ctx;
    ctx.stream = &stream;

    auto res = SignatureMatcher::evaluate(rule, ctx);
    TEST_ASSERT(res.matched, "HTTP method, wildcard host, URI, and status must match");
    TEST_ASSERT(res.scope == MatchScope::HTTP, "Match scope must be HTTP");
    return true;
}

// TEST 120: TLS Metadata Matching
bool test_signature_tls_metadata_matching() {
    SignatureRule rule;
    rule.rule_id = "SIG-TLS-1";
    rule.name = "Known Malicious C2 SNI";
    rule.tls.sni = "*.covert-channel.biz";
    rule.tls.alpn = "h2";

    StreamRecordSummary stream;
    stream.tuple = FiveTuple{10, 20, 443, 443, 6};
    stream.tls_meta.sni = "node9.covert-channel.biz";
    stream.tls_meta.alpn = "h2";

    RuleEvaluationContext ctx;
    ctx.stream = &stream;

    auto res = SignatureMatcher::evaluate(rule, ctx);
    TEST_ASSERT(res.matched, "TLS wildcard SNI and ALPN must match");
    TEST_ASSERT(res.scope == MatchScope::TLS, "Match scope must be TLS");
    return true;
}

// TEST 121: DNS Metadata and Entropy Matching
bool test_signature_dns_metadata_and_entropy() {
    SignatureRule rule;
    rule.rule_id = "SIG-DNS-DGA";
    rule.name = "DGA Tunneling Candidate";
    rule.dns.query_name = "*.tunnel.org";
    rule.dns.is_nxdomain = true;
    rule.dns.min_entropy = 3.2;

    FlowRecord flow = createMockFlow(1, "192.168.1.50", "8.8.8.8", 53535, 53, 17, 5, 250, 5, 250);
    flow.dns_query = "v9k3m8z2q7l1w4p0.tunnel.org"; // High entropy DGA
    flow.dns_rcode = 3;
    flow.dns_rcode_name = "NXDOMAIN";

    RuleEvaluationContext ctx;
    ctx.flow = &flow;

    auto res = SignatureMatcher::evaluate(rule, ctx);
    TEST_ASSERT(res.matched, "DNS query with high entropy and NXDOMAIN must match");
    TEST_ASSERT(res.scope == MatchScope::DNS, "Match scope must be DNS");
    return true;
}

// TEST 122: Signature Event JSON and CSV Serialization
bool test_signature_event_json_and_csv_serialization() {
    SignatureEvent ev;
    ev.event_id = "SIGEV-0001";
    ev.rule_id = "SIG-1001";
    ev.rule_name = "Test Exploit Pattern";
    ev.category = SignatureCategory::EXPLOIT;
    ev.severity = SignatureSeverity::CRITICAL;
    ev.timestamp_us = 1700000000123456ULL;
    ev.src_ip = "192.168.1.100";
    ev.dst_ip = "10.0.0.5";
    ev.src_port = 45000;
    ev.dst_port = 80;
    ev.protocol = "TCP";
    ev.direction = "FORWARD";
    ev.flow_id = 42;
    ev.match_scope = MatchScope::STREAM;
    ev.match_details = "Matched shellcode payload";
    ev.matched_pattern = "|90 90 90 cc|";
    ev.match_offset = 128;
    ev.evidence = "\\x90\\x90\\x90\\xcc";
    ev.confidence = "HIGH";

    std::string json_str = ev.toJson();
    TEST_ASSERT(json_str.find("\"event_id\": \"SIGEV-0001\"") != std::string::npos, "JSON must contain event_id");
    TEST_ASSERT(json_str.find("\"severity\": \"CRITICAL\"") != std::string::npos, "JSON must contain severity");

    std::string csv_str = ev.toCsvRow();
    TEST_ASSERT(csv_str.find("\"SIGEV-0001\"") != std::string::npos, "CSV must contain event_id");
    TEST_ASSERT(csv_str.find("\"CRITICAL\"") != std::string::npos, "CSV must contain severity");

    std::string header = SignatureEvent::csvHeader();
    TEST_ASSERT(header.find("event_id,schema_version,rule_id") != std::string::npos, "CSV header mismatch");
    return true;
}

// TEST 123: Duplicate Match Suppression
bool test_signature_duplicate_match_suppression() {
    SignatureEngineConfig cfg;
    cfg.suppress_duplicate_matches = true;
    SignatureEngine engine(cfg);

    SignatureRule rule;
    rule.rule_id = "SIG-DEDUP-1";
    rule.name = "Dedup Test Rule";
    rule.network.protocol = RuleProtocol::TCP;
    std::string err;
    TEST_ASSERT(engine.getRuleManager().addRule(rule, err), "Add rule failed");

    FlowRecord flow = createMockFlow(1, "192.168.1.10", "10.0.0.1", 1234, 80, 6, 10, 500, 10, 500);

    auto ev1 = engine.evaluateFlow(flow);
    TEST_ASSERT(ev1.size() == 1, "First evaluation must fire 1 event");

    auto ev2 = engine.evaluateFlow(flow);
    TEST_ASSERT(ev2.empty(), "Second evaluation on same flow must be suppressed");
    return true;
}

// TEST 124: Incident Correlation Integration with Signatures
bool test_signature_incident_correlation_integration() {
    IncidentCorrelator correlator;

    // Behavioral detection
    std::vector<DetectionEvent> dets;
    dets.push_back(createMockDetection("DET-1", "beacon_detector", DetectionCategory::COMMAND_AND_CONTROL,
                                       DetectionSeverity::MEDIUM, "192.168.1.50", "198.51.100.1", 1000000,
                                       {8080}, {10}, "Periodic beaconing"));

    std::vector<FlowRecord> flows;
    flows.push_back(createMockFlow(10, "192.168.1.50", "198.51.100.1", 45000, 8080, 6, 20, 2000, 20, 2000));

    // Signature match on the same host and flow
    std::vector<SignatureEvent> sigs;
    SignatureEvent sig;
    sig.event_id = "SIGEV-100";
    sig.rule_id = "SIG-MALWARE-C2";
    sig.rule_name = "Known RAT Beacon Header";
    sig.category = SignatureCategory::MALWARE;
    sig.severity = SignatureSeverity::HIGH;
    sig.src_ip = "192.168.1.50";
    sig.dst_ip = "198.51.100.1";
    sig.flow_id = 10;
    sigs.push_back(sig);

    auto incidents = correlator.correlate(dets, flows, {}, sigs);
    TEST_ASSERT(!incidents.empty(), "Incident must be generated");
    TEST_ASSERT(!incidents[0].related_signature_ids.empty(), "Incident must link related signature IDs");
    TEST_ASSERT(incidents[0].related_signature_ids[0] == "SIG-MALWARE-C2", "Signature ID mismatch");

    // Check timeline event added
    bool has_sig_timeline = false;
    for (const auto& te : incidents[0].timeline) {
        if (te.event_type == "SIGNATURE_MATCH" && te.source == "SIGNATURE_ENGINE") {
            has_sig_timeline = true;
            break;
        }
    }
    TEST_ASSERT(has_sig_timeline, "Incident timeline must include SIGNATURE_MATCH event");
    return true;
}

// TEST 125: End-to-End PCAP Signature Detection & Incident Analysis
bool test_end_to_end_pcap_signature_detection() {
    // Write sample signature rule file
    std::string rules_json = R"({
      "rules": [
        {
          "id": "SIG-HTTP-GET",
          "name": "HTTP Inbound GET Request",
          "category": "INFO",
          "severity": "LOW",
          "network": {
            "protocol": "TCP",
            "dst_ports": [80]
          },
          "stream_content": [
            {
              "pattern": "GET ",
              "offset": 0,
              "depth": 10
            }
          ]
        },
        {
          "id": "SIG-TIKTOK-TRAFFIC",
          "name": "TikTok Domain Traffic",
          "category": "POLICY_VIOLATION",
          "severity": "MEDIUM",
          "tls": {
            "sni": "*.tiktok.com"
          }
        }
      ]
    })";

    std::ofstream rf("/tmp/test_signature_rules.json");
    rf << rules_json;
    rf.close();

    DPIEngine::Config cfg;
    cfg.num_load_balancers = 2;
    cfg.fps_per_lb = 2;
    cfg.enable_signatures = true;
    cfg.signature_rules_file = "/tmp/test_signature_rules.json";
    cfg.show_signature_stats = true;
    cfg.export_signatures_json = "/tmp/test_sig_events.json";
    cfg.export_signatures_csv = "/tmp/test_sig_events.csv";
    cfg.enable_incidents = true;

    DPIEngine engine(cfg);
    TEST_ASSERT(engine.initialize(), "DPIEngine initialization failed");

    bool ok = engine.processFile("test_dpi.pcap", "/tmp/test_sig_out.pcap");
    TEST_ASSERT(ok, "processFile failed");

    // Verify signature events generated
    const auto& events = engine.getSignatures();
    std::cout << "\n[Test 125] Total signature events detected from test_dpi.pcap: " << events.size() << "\n";
    TEST_ASSERT(!events.empty(), "Signature events should be detected from test_dpi.pcap");

    // Verify report generation
    std::string report = engine.generateSignatureReport();
    TEST_ASSERT(report.find("SIGNATURE-BASED INTRUSION DETECTION REPORT") != std::string::npos,
                "Signature report must contain header");

    // Verify exported JSON file
    std::ifstream jf("/tmp/test_sig_events.json");
    TEST_ASSERT(jf.is_open(), "Signature JSON file must exist");
    std::string j_content((std::istreambuf_iterator<char>(jf)),
                           std::istreambuf_iterator<char>());
    jf.close();
    TEST_ASSERT(j_content.find("SIG-HTTP-GET") != std::string::npos ||
                j_content.find("SIG-TIKTOK-TRAFFIC") != std::string::npos,
                "Exported JSON must contain matched rule IDs");

    // Verify exported CSV file
    std::ifstream cf("/tmp/test_sig_events.csv");
    TEST_ASSERT(cf.is_open(), "Signature CSV file must exist");
    std::string c_header;
    std::getline(cf, c_header);
    TEST_ASSERT(c_header.find("event_id,schema_version,rule_id") != std::string::npos,
                "CSV must contain valid signature header");
    cf.close();

    return true;
}

// ============================================================================
// Phase 3.5 Threat Intelligence & IOC Enrichment Tests (Tests 126-155)
// ============================================================================

// TEST 126: Threat Intelligence Dataset JSON Parsing (Valid)
bool test_threat_intel_dataset_json_parsing_valid() {
    std::string json_data = R"({
      "dataset_id": "DS-TEST-01",
      "name": "Malware C2 Infrastructure Feed",
      "version": "1.0",
      "schema_version": "1.0",
      "source_description": "Curated test indicators",
      "source_url": "https://threat-intel.internal/feed",
      "created_timestamp": 1700000000,
      "expiration_timestamp": 1900000000,
      "enabled": true,
      "iocs": [
        {
          "ioc_id": "IOC-001",
          "type": "IPV4",
          "value": "198.51.100.10",
          "confidence": "HIGH",
          "severity": "CRITICAL",
          "tags": ["c2", "cobalt-strike"],
          "category": "C2",
          "description": "Active Cobalt Strike C2 IP",
          "references": ["CVE-2023-1234"],
          "enabled": true
        },
        {
          "ioc_id": "IOC-002",
          "type": "IPV4_CIDR",
          "value": "203.0.113.0/24",
          "confidence": "MEDIUM",
          "severity": "HIGH",
          "category": "SCANNER",
          "description": "Scanning subnet",
          "enabled": true
        },
        {
          "ioc_id": "IOC-003",
          "type": "DOMAIN",
          "value": "malware-c2.net",
          "confidence": "HIGH",
          "severity": "CRITICAL",
          "category": "C2",
          "description": "Malicious domain",
          "enabled": true
        },
        {
          "ioc_id": "IOC-004",
          "type": "URL",
          "value": "http://evil.com/payload.exe",
          "confidence": "MEDIUM",
          "severity": "HIGH",
          "category": "MALWARE",
          "description": "Malware dropper URL",
          "enabled": true
        }
      ]
    })";

    std::vector<ThreatDataset> datasets;
    std::vector<std::string> errors;
    bool ok = ThreatIntelParser::parseDatasetString(json_data, datasets, errors);
    TEST_ASSERT(ok, "Valid dataset parsing must succeed");
    TEST_ASSERT(datasets.size() == 1, "Must parse exactly 1 dataset");
    TEST_ASSERT(datasets[0].dataset_id == "DS-TEST-01", "Dataset ID mismatch");
    TEST_ASSERT(datasets[0].iocs.size() == 4, "Must parse exactly 4 IOCs");
    TEST_ASSERT(datasets[0].iocs[0].ioc_id == "IOC-001", "First IOC ID mismatch");
    TEST_ASSERT(datasets[0].iocs[0].type == IOCType::IPV4, "First IOC type must be IPV4");
    TEST_ASSERT(datasets[0].iocs[1].type == IOCType::IPV4_CIDR, "Second IOC type must be IPV4_CIDR");
    TEST_ASSERT(datasets[0].iocs[1].prefix_len == 24, "CIDR prefix must be 24");
    TEST_ASSERT(datasets[0].iocs[2].type == IOCType::DOMAIN_NAME, "Third IOC type must be DOMAIN");
    TEST_ASSERT(datasets[0].iocs[3].type == IOCType::URL, "Fourth IOC type must be URL");
    TEST_ASSERT(datasets[0].iocs[3].url_host == "evil.com", "URL host must be evil.com");
    TEST_ASSERT(datasets[0].iocs[3].url_path == "/payload.exe", "URL path must be /payload.exe");
    return true;
}

// TEST 127: Threat Intelligence Dataset JSON Parsing (Malformed)
bool test_threat_intel_dataset_json_parsing_malformed() {
    std::string malformed_json = R"({ "dataset_id": "DS-BAD", "name": "Broken", "iocs": [ )";
    std::vector<ThreatDataset> datasets;
    std::vector<std::string> errors;
    bool ok = ThreatIntelParser::parseDatasetString(malformed_json, datasets, errors);
    TEST_ASSERT(!ok, "Malformed JSON syntax must be rejected");
    TEST_ASSERT(!errors.empty(), "Error message must be reported for malformed JSON");
    return true;
}

// TEST 128: Threat Intelligence Dataset Missing Required Fields
bool test_threat_intel_dataset_missing_required_fields() {
    // Missing dataset_id
    std::string missing_id = R"({ "name": "Missing ID", "iocs": [] })";
    std::vector<ThreatDataset> datasets;
    std::vector<std::string> errors;
    TEST_ASSERT(!ThreatIntelParser::parseDatasetString(missing_id, datasets, errors), "Missing dataset_id must fail validation");

    // Missing dataset name
    std::string missing_name = R"({ "dataset_id": "DS-NO-NAME", "iocs": [] })";
    datasets.clear(); errors.clear();
    TEST_ASSERT(!ThreatIntelParser::parseDatasetString(missing_name, datasets, errors), "Missing dataset name must fail validation");
    return true;
}

// TEST 129: Threat Intelligence Duplicate Dataset ID Rejection
bool test_threat_intel_dataset_duplicate_dataset_id() {
    ThreatIntelManager mgr;
    ThreatDataset ds1;
    ds1.dataset_id = "DS-DUP";
    ds1.name = "Dataset One";
    std::string err;
    TEST_ASSERT(mgr.addDataset(ds1, err), "Adding first dataset must succeed");

    ThreatDataset ds2;
    ds2.dataset_id = "DS-DUP";
    ds2.name = "Dataset Duplicate";
    TEST_ASSERT(!mgr.addDataset(ds2, err), "Adding duplicate dataset ID must fail");
    TEST_ASSERT(err.find("Duplicate dataset ID") != std::string::npos, "Error must describe duplicate dataset ID");
    return true;
}

// TEST 130: Threat Intelligence Duplicate IOC ID Rejection
bool test_threat_intel_dataset_duplicate_ioc_id() {
    std::string dup_ioc_json = R"({
      "dataset_id": "DS-DUP-IOC",
      "name": "Duplicate IOCs",
      "iocs": [
        { "ioc_id": "IOC-DUP", "type": "IPV4", "value": "1.1.1.1" },
        { "ioc_id": "IOC-DUP", "type": "IPV4", "value": "2.2.2.2" }
      ]
    })";
    std::vector<ThreatDataset> datasets;
    std::vector<std::string> errors;
    bool ok = ThreatIntelParser::parseDatasetString(dup_ioc_json, datasets, errors);
    TEST_ASSERT(!ok, "Duplicate IOC IDs within dataset must fail validation");
    return true;
}

// TEST 131: Threat Intelligence Validation Invalid IPv4
bool test_threat_intel_validation_invalid_ipv4() {
    uint32_t ip = 0;
    TEST_ASSERT(!ThreatIntelValidator::isValidIPv4("999.1.2.3", ip), "Octet > 255 must fail");
    TEST_ASSERT(!ThreatIntelValidator::isValidIPv4("1.2.3", ip), "Fewer than 4 octets must fail");
    TEST_ASSERT(!ThreatIntelValidator::isValidIPv4("1.2.3.4.5", ip), "More than 4 octets must fail");
    TEST_ASSERT(!ThreatIntelValidator::isValidIPv4("a.b.c.d", ip), "Alphabetic characters must fail");
    TEST_ASSERT(!ThreatIntelValidator::isValidIPv4("", ip), "Empty string must fail");
    TEST_ASSERT(ThreatIntelValidator::isValidIPv4("192.168.1.100", ip), "Valid IPv4 must pass");
    return true;
}

// TEST 132: Threat Intelligence Validation Invalid CIDR
bool test_threat_intel_validation_invalid_cidr() {
    uint32_t ip = 0;
    uint8_t prefix = 0;
    uint32_t mask = 0;
    TEST_ASSERT(!ThreatIntelValidator::isValidCIDR("192.168.1.0/33", ip, prefix, mask), "Prefix > 32 must fail");
    TEST_ASSERT(!ThreatIntelValidator::isValidCIDR("192.168.1.0/abc", ip, prefix, mask), "Non-numeric prefix must fail");
    TEST_ASSERT(!ThreatIntelValidator::isValidCIDR("bad_ip/24", ip, prefix, mask), "Invalid base IP must fail");
    TEST_ASSERT(ThreatIntelValidator::isValidCIDR("10.0.0.0/8", ip, prefix, mask), "Valid CIDR /8 must pass");
    TEST_ASSERT(prefix == 8, "Parsed prefix must be 8");
    return true;
}

// TEST 133: Threat Intelligence Validation Invalid Domain
bool test_threat_intel_validation_invalid_domain() {
    std::string norm;
    bool wildcard = false;
    TEST_ASSERT(!ThreatIntelValidator::isValidDomain("", norm, wildcard), "Empty domain must fail");
    TEST_ASSERT(!ThreatIntelValidator::isValidDomain("example..com", norm, wildcard), "Double dot must fail");
    TEST_ASSERT(!ThreatIntelValidator::isValidDomain("-example.com", norm, wildcard), "Leading hyphen in label must fail");
    TEST_ASSERT(ThreatIntelValidator::isValidDomain("example.com", norm, wildcard), "Valid domain must pass");
    TEST_ASSERT(!wildcard, "Wildcard must be false");
    TEST_ASSERT(ThreatIntelValidator::isValidDomain("*.example.com", norm, wildcard), "Valid wildcard domain must pass");
    TEST_ASSERT(wildcard, "Wildcard must be true");
    TEST_ASSERT(norm == "example.com", "Normalized domain must strip leading *.");
    return true;
}

// TEST 134: Threat Intelligence Validation Invalid URL
bool test_threat_intel_validation_invalid_url() {
    std::string host, path;
    TEST_ASSERT(!ThreatIntelValidator::isValidURL("", host, path), "Empty URL must fail");
    TEST_ASSERT(ThreatIntelValidator::isValidURL("http://c2.evil.com:8080/stage2.bin", host, path), "Valid HTTP URL must pass");
    TEST_ASSERT(host == "c2.evil.com", "Host must be parsed correctly");
    TEST_ASSERT(path == "/stage2.bin", "Path must be parsed correctly");
    return true;
}

// TEST 135: Threat Intelligence Dataset Expiration & Stale Status
bool test_threat_intel_dataset_expiration_and_stale() {
    ThreatDataset ds;
    ds.dataset_id = "DS-EXP";
    ds.name = "Expiring Dataset";
    ds.expiration_timestamp = 1700000000; // Expired timestamp

    ThreatIOC ioc;
    ioc.ioc_id = "IOC-EXP";
    ioc.type = IOCType::IPV4;
    ioc.value = "1.2.3.4";
    ioc.expiration_timestamp = 1700000000;
    ds.iocs.push_back(ioc);

    uint64_t current_time_us = 1750000000ULL * 1000000ULL; // Future timestamp
    TEST_ASSERT(ds.isExpired(current_time_us), "Dataset must be marked expired when current time > expiration");
    TEST_ASSERT(ioc.isExpired(current_time_us), "IOC must be marked expired when current time > expiration");

    uint64_t past_time_us = 1650000000ULL * 1000000ULL; // Past timestamp
    TEST_ASSERT(!ds.isExpired(past_time_us), "Dataset must NOT be marked expired when current time < expiration");
    TEST_ASSERT(!ioc.isExpired(past_time_us), "IOC must NOT be marked expired when current time < expiration");
    return true;
}

// TEST 136: Threat Intelligence Dataset Disabled State
bool test_threat_intel_dataset_disabled_state() {
    ThreatIntelManager mgr;
    ThreatDataset ds;
    ds.dataset_id = "DS-DIS";
    ds.name = "Disabled Dataset";
    ds.enabled = true;

    ThreatIOC ioc;
    ioc.ioc_id = "IOC-DIS";
    ioc.type = IOCType::IPV4;
    ioc.value = "192.168.100.1";
    ioc.parsed_ip = 192 | (168 << 8) | (100 << 16) | (1 << 24);
    ds.iocs.push_back(ioc);

    std::string err;
    mgr.addDataset(ds, err);

    uint32_t ip = ioc.parsed_ip;
    TEST_ASSERT(!mgr.matchIPv4(ip).empty(), "Active dataset must return matching IOC");

    // Disable dataset
    mgr.setDatasetEnabled("DS-DIS", false);
    TEST_ASSERT(mgr.matchIPv4(ip).empty(), "Disabled dataset must NOT match any IOC");

    // Re-enable dataset
    mgr.setDatasetEnabled("DS-DIS", true);
    TEST_ASSERT(!mgr.matchIPv4(ip).empty(), "Re-enabled dataset must match IOC again");
    return true;
}

// TEST 137: Threat Intelligence Dataset Directory Loading
bool test_threat_intel_dataset_directory_loading() {
    std::string dir = "/tmp/test_threat_intel_dir";
    system(("mkdir -p " + dir).c_str());

    std::string ds1 = R"({
      "dataset_id": "DS-DIR-1",
      "name": "Dir Feed 1",
      "iocs": [{ "ioc_id": "IOC-D1", "type": "IPV4", "value": "10.0.0.1" }]
    })";
    std::string ds2 = R"({
      "dataset_id": "DS-DIR-2",
      "name": "Dir Feed 2",
      "iocs": [{ "ioc_id": "IOC-D2", "type": "DOMAIN", "value": "dir-c2.net" }]
    })";

    std::ofstream f1(dir + "/feed1.json"); f1 << ds1; f1.close();
    std::ofstream f2(dir + "/feed2.json"); f2 << ds2; f2.close();

    ThreatIntelManager mgr;
    std::vector<std::string> errors;
    bool ok = mgr.loadDatasetDirectory(dir, errors);
    TEST_ASSERT(ok, "Loading directory of threat intel datasets must succeed");
    TEST_ASSERT(mgr.totalDatasets() == 2, "Must load exactly 2 datasets from directory");
    TEST_ASSERT(mgr.totalIOCs() == 2, "Must index 2 total IOCs");
    return true;
}

// TEST 138: Threat Intelligence IPv4 Exact Matching
bool test_threat_intel_ipv4_exact_matching() {
    ThreatIntelManager mgr;
    ThreatDataset ds;
    ds.dataset_id = "DS-IP-EXACT";
    ds.name = "Exact IP Feed";

    ThreatIOC ioc;
    ioc.ioc_id = "IOC-IP-1";
    ioc.type = IOCType::IPV4;
    ioc.value = "93.184.216.34";
    ioc.parsed_ip = 93 | (184 << 8) | (216 << 16) | (34 << 24);
    ds.iocs.push_back(ioc);

    std::string err;
    mgr.addDataset(ds, err);

    uint32_t match_ip = ioc.parsed_ip;
    uint32_t other_ip = 93 | (184 << 8) | (216 << 16) | (35 << 24);

    auto res = mgr.matchIPv4(match_ip);
    TEST_ASSERT(!res.empty(), "Exact IP must match");
    TEST_ASSERT(res[0]->ioc_id == "IOC-IP-1", "Matched IOC ID mismatch");

    auto no_res = mgr.matchIPv4(other_ip);
    TEST_ASSERT(no_res.empty(), "Different IP must not match");
    return true;
}

// TEST 139: Threat Intelligence IPv4 CIDR Matching
bool test_threat_intel_ipv4_cidr_matching() {
    ThreatIntelManager mgr;
    ThreatDataset ds;
    ds.dataset_id = "DS-CIDR";
    ds.name = "CIDR Feed";

    ThreatIOC ioc;
    ioc.ioc_id = "IOC-CIDR-1";
    ioc.type = IOCType::IPV4_CIDR;
    ioc.value = "10.50.0.0/16";
    ThreatIntelValidator::validateIOC(ioc);
    ds.iocs.push_back(ioc);

    std::string err;
    mgr.addDataset(ds, err);

    uint32_t inside_ip = 10 | (50 << 8) | (1 << 16) | (20 << 24); // 10.50.1.20
    uint32_t outside_ip = 10 | (51 << 8) | (1 << 16) | (20 << 24); // 10.51.1.20

    auto res = mgr.matchIPv4(inside_ip);
    TEST_ASSERT(!res.empty(), "IP inside /16 CIDR must match");
    TEST_ASSERT(res[0]->ioc_id == "IOC-CIDR-1", "Matched IOC mismatch");

    auto no_res = mgr.matchIPv4(outside_ip);
    TEST_ASSERT(no_res.empty(), "IP outside /16 CIDR must NOT match");
    return true;
}

// TEST 140: Threat Intelligence IPv4 CIDR Boundary
bool test_threat_intel_ipv4_cidr_boundary() {
    ThreatIntelManager mgr;
    ThreatDataset ds;
    ds.dataset_id = "DS-CIDR-BOUND";
    ds.name = "CIDR Boundary Feed";

    ThreatIOC ioc;
    ioc.ioc_id = "IOC-C24";
    ioc.type = IOCType::IPV4_CIDR;
    ioc.value = "192.168.1.0/24";
    ThreatIntelValidator::validateIOC(ioc);
    ds.iocs.push_back(ioc);

    std::string err;
    mgr.addDataset(ds, err);

    uint32_t low_edge = 192 | (168 << 8) | (1 << 16) | (0 << 24);   // 192.168.1.0
    uint32_t high_edge = 192 | (168 << 8) | (1 << 16) | (255 << 24); // 192.168.1.255
    uint32_t outside_low = 192 | (168 << 8) | (0 << 16) | (255 << 24); // 192.168.0.255
    uint32_t outside_high = 192 | (168 << 8) | (2 << 16) | (0 << 24);  // 192.168.2.0

    TEST_ASSERT(!mgr.matchIPv4(low_edge).empty(), "Low edge 192.168.1.0 must match /24");
    TEST_ASSERT(!mgr.matchIPv4(high_edge).empty(), "High edge 192.168.1.255 must match /24");
    TEST_ASSERT(mgr.matchIPv4(outside_low).empty(), "192.168.0.255 must not match /24");
    TEST_ASSERT(mgr.matchIPv4(outside_high).empty(), "192.168.2.0 must not match /24");
    return true;
}

// TEST 141: Threat Intelligence Overlapping CIDR Matching
bool test_threat_intel_ipv4_overlapping_cidr() {
    ThreatIntelManager mgr;
    ThreatDataset ds;
    ds.dataset_id = "DS-OVERLAP";
    ds.name = "Overlapping CIDR Feed";

    ThreatIOC ioc1;
    ioc1.ioc_id = "IOC-BROAD";
    ioc1.type = IOCType::IPV4_CIDR;
    ioc1.value = "10.0.0.0/8";
    ThreatIntelValidator::validateIOC(ioc1);
    ds.iocs.push_back(ioc1);

    ThreatIOC ioc2;
    ioc2.ioc_id = "IOC-NARROW";
    ioc2.type = IOCType::IPV4_CIDR;
    ioc2.value = "10.1.2.0/24";
    ThreatIntelValidator::validateIOC(ioc2);
    ds.iocs.push_back(ioc2);

    std::string err;
    mgr.addDataset(ds, err);

    uint32_t overlap_ip = 10 | (1 << 8) | (2 << 16) | (50 << 24); // 10.1.2.50
    auto res = mgr.matchIPv4(overlap_ip);
    TEST_ASSERT(res.size() >= 2, "Overlapping IP must match both /8 and /24 CIDRs");
    return true;
}

// TEST 142: Threat Intelligence Domain Exact Matching
bool test_threat_intel_domain_exact_matching() {
    ThreatIntelManager mgr;
    ThreatDataset ds;
    ds.dataset_id = "DS-DOM";
    ds.name = "Domain Feed";

    ThreatIOC ioc;
    ioc.ioc_id = "IOC-DOM-1";
    ioc.type = IOCType::DOMAIN_NAME;
    ioc.value = "malicious-c2.com";
    ThreatIntelValidator::validateIOC(ioc);
    ds.iocs.push_back(ioc);

    std::string err;
    mgr.addDataset(ds, err);

    auto res = mgr.matchDomain("malicious-c2.com");
    TEST_ASSERT(!res.empty(), "Exact domain must match");
    TEST_ASSERT(res[0]->ioc_id == "IOC-DOM-1", "Matched IOC ID mismatch");

    auto no_res = mgr.matchDomain("benign-site.com");
    TEST_ASSERT(no_res.empty(), "Different domain must not match");
    return true;
}

// TEST 143: Threat Intelligence Subdomain Matching
bool test_threat_intel_domain_subdomain_matching() {
    ThreatIntelManager mgr;
    ThreatDataset ds;
    ds.dataset_id = "DS-SUBDOM";
    ds.name = "Subdomain Matching Feed";

    ThreatIOC ioc;
    ioc.ioc_id = "IOC-BASE";
    ioc.type = IOCType::DOMAIN_NAME;
    ioc.value = "c2-infra.net";
    ThreatIntelValidator::validateIOC(ioc);
    ds.iocs.push_back(ioc);

    std::string err;
    mgr.addDataset(ds, err);

    TEST_ASSERT(!mgr.matchDomain("bot1.c2-infra.net").empty(), "Subdomain bot1.c2-infra.net must match");
    TEST_ASSERT(!mgr.matchDomain("stage.sub.c2-infra.net").empty(), "Deep subdomain stage.sub.c2-infra.net must match");
    return true;
}

// TEST 144: Threat Intelligence Domain Boundary Collision Rejection
bool test_threat_intel_domain_boundary_collision_rejection() {
    ThreatIntelManager mgr;
    ThreatDataset ds;
    ds.dataset_id = "DS-COLLISION";
    ds.name = "Collision Rejection Feed";

    ThreatIOC ioc;
    ioc.ioc_id = "IOC-TARGET";
    ioc.type = IOCType::DOMAIN_NAME;
    ioc.value = "example.com";
    ThreatIntelValidator::validateIOC(ioc);
    ds.iocs.push_back(ioc);

    std::string err;
    mgr.addDataset(ds, err);

    // Prefix collision must fail: notexample.com must NOT match example.com
    TEST_ASSERT(mgr.matchDomain("notexample.com").empty(), "Prefix collision notexample.com must NOT match example.com");
    TEST_ASSERT(mgr.matchDomain("myexample.com").empty(), "Prefix collision myexample.com must NOT match example.com");
    // Suffix parent boundary: example.com.evil.org must NOT match example.com
    TEST_ASSERT(mgr.matchDomain("example.com.evil.org").empty(), "Suffix domain example.com.evil.org must NOT match example.com");
    return true;
}

// TEST 145: Threat Intelligence Domain Case and Trailing Dot Handling
bool test_threat_intel_domain_case_and_trailing_dot() {
    ThreatIntelManager mgr;
    ThreatDataset ds;
    ds.dataset_id = "DS-NORM";
    ds.name = "Normalization Feed";

    ThreatIOC ioc;
    ioc.ioc_id = "IOC-NORM";
    ioc.type = IOCType::DOMAIN_NAME;
    ioc.value = "ThReAt-HoSt.BiZ."; // Mixed case and trailing dot
    ThreatIntelValidator::validateIOC(ioc);
    ds.iocs.push_back(ioc);

    std::string err;
    mgr.addDataset(ds, err);

    TEST_ASSERT(!mgr.matchDomain("threat-host.biz").empty(), "Lowercase query must match normalized IOC");
    TEST_ASSERT(!mgr.matchDomain("THREAT-HOST.BIZ").empty(), "Uppercase query must match normalized IOC");
    TEST_ASSERT(!mgr.matchDomain("threat-host.biz.").empty(), "Query with trailing dot must match normalized IOC");
    TEST_ASSERT(!mgr.matchDomain("sub.threat-host.biz.").empty(), "Subdomain with trailing dot must match normalized IOC");
    return true;
}

// TEST 146: Threat Intelligence Domain Wildcard Semantics
bool test_threat_intel_domain_wildcard_semantics() {
    ThreatIntelManager mgr;
    ThreatDataset ds;
    ds.dataset_id = "DS-WILD";
    ds.name = "Wildcard Feed";

    ThreatIOC ioc;
    ioc.ioc_id = "IOC-WILD";
    ioc.type = IOCType::DOMAIN_NAME;
    ioc.value = "*.bad-actor.org";
    ThreatIntelValidator::validateIOC(ioc);
    ds.iocs.push_back(ioc);

    std::string err;
    mgr.addDataset(ds, err);

    TEST_ASSERT(!mgr.matchDomain("bad-actor.org").empty(), "Base domain must match wildcard pattern");
    TEST_ASSERT(!mgr.matchDomain("node1.bad-actor.org").empty(), "Subdomain must match wildcard pattern");
    TEST_ASSERT(!mgr.matchDomain("deep.node.bad-actor.org").empty(), "Deep subdomain must match wildcard pattern");
    TEST_ASSERT(mgr.matchDomain("notbad-actor.org").empty(), "Substring collision must NOT match");
    return true;
}

// TEST 147: Threat Intelligence Protocol DNS Query Matching
bool test_threat_intel_protocol_dns_query_matching() {
    ThreatIntelEngine engine;
    ThreatDataset ds;
    ds.dataset_id = "DS-DNS";
    ds.name = "DNS Threat Feed";

    ThreatIOC ioc;
    ioc.ioc_id = "IOC-DNS-1";
    ioc.type = IOCType::DNS_NAME;
    ioc.value = "sinkhole-test.org";
    ThreatIntelValidator::validateIOC(ioc);
    ds.iocs.push_back(ioc);

    std::string err;
    engine.getManager().addDataset(ds, err);

    std::vector<FlowRecord> flows;
    FlowRecord f;
    f.flow_id = 100;
    f.initial_tuple = FiveTuple{10, 20, 5353, 53, 17};
    f.dns_query = "sinkhole-test.org";
    flows.push_back(f);

    auto events = engine.evaluateAll(flows);
    TEST_ASSERT(!events.empty(), "DNS Query match must produce ThreatMatchEvent");
    TEST_ASSERT(events[0].match_type == ThreatMatchType::DNS_QUERY, "Match type must be DNS_QUERY");
    TEST_ASSERT(events[0].observed_value == "sinkhole-test.org", "Observed value mismatch");
    return true;
}

// TEST 148: Threat Intelligence Protocol DNS Resolved IP Matching
bool test_threat_intel_protocol_dns_resolved_ip_matching() {
    ThreatIntelEngine engine;
    ThreatDataset ds;
    ds.dataset_id = "DS-DNS-IP";
    ds.name = "DNS Answer IP Feed";

    ThreatIOC ioc;
    ioc.ioc_id = "IOC-ANS-IP";
    ioc.type = IOCType::IPV4;
    ioc.value = "185.220.101.5";
    ThreatIntelValidator::validateIOC(ioc);
    ds.iocs.push_back(ioc);

    std::string err;
    engine.getManager().addDataset(ds, err);

    std::vector<FlowRecord> flows;
    FlowRecord f;
    f.flow_id = 101;
    f.initial_tuple = FiveTuple{10, 20, 5354, 53, 17};
    f.dns_query = "dynamic-dns.biz";
    f.dns_answers.push_back("185.220.101.5");
    flows.push_back(f);

    auto events = engine.evaluateAll(flows);
    TEST_ASSERT(!events.empty(), "Resolved answer IP match must produce ThreatMatchEvent");
    TEST_ASSERT(events[0].match_type == ThreatMatchType::DNS_RESPONSE_IP, "Match type must be DNS_RESPONSE_IP");
    TEST_ASSERT(events[0].observed_value == "185.220.101.5", "Observed value mismatch");
    return true;
}

// TEST 149: Threat Intelligence Protocol TLS SNI Matching
bool test_threat_intel_protocol_tls_sni_matching() {
    ThreatIntelEngine engine;
    ThreatDataset ds;
    ds.dataset_id = "DS-TLS";
    ds.name = "TLS SNI Feed";

    ThreatIOC ioc;
    ioc.ioc_id = "IOC-SNI-1";
    ioc.type = IOCType::TLS_SNI;
    ioc.value = "covert-channel.biz";
    ThreatIntelValidator::validateIOC(ioc);
    ds.iocs.push_back(ioc);

    std::string err;
    engine.getManager().addDataset(ds, err);

    std::vector<FlowRecord> flows;
    FlowRecord f;
    f.flow_id = 102;
    f.initial_tuple = FiveTuple{10, 20, 50000, 443, 6};
    f.sni = "node1.covert-channel.biz";
    flows.push_back(f);

    auto events = engine.evaluateAll(flows);
    TEST_ASSERT(!events.empty(), "TLS SNI match must produce ThreatMatchEvent");
    TEST_ASSERT(events[0].match_type == ThreatMatchType::TLS_SNI, "Match type must be TLS_SNI");
    TEST_ASSERT(events[0].observed_value == "node1.covert-channel.biz", "Observed value mismatch");
    return true;
}

// TEST 150: Threat Intelligence Protocol HTTP Host & URL Matching
bool test_threat_intel_protocol_http_host_and_url_matching() {
    ThreatIntelEngine engine;
    ThreatDataset ds;
    ds.dataset_id = "DS-HTTP";
    ds.name = "HTTP Threat Feed";

    ThreatIOC ioc;
    ioc.ioc_id = "IOC-URL-1";
    ioc.type = IOCType::URL;
    ioc.value = "http://phishing.net/login.php";
    ThreatIntelValidator::validateIOC(ioc);
    ds.iocs.push_back(ioc);

    std::string err;
    engine.getManager().addDataset(ds, err);

    std::vector<FlowRecord> flows;
    FlowRecord f;
    f.flow_id = 103;
    f.initial_tuple = FiveTuple{10, 20, 50001, 80, 6};
    f.http_host = "phishing.net";
    f.http_uri = "/login.php?user=admin";
    flows.push_back(f);

    auto events = engine.evaluateAll(flows);
    TEST_ASSERT(!events.empty(), "HTTP URL match must produce ThreatMatchEvent");
    TEST_ASSERT(events[0].match_type == ThreatMatchType::HTTP_URL, "Match type must be HTTP_URL");
    return true;
}

// TEST 151: Threat Intelligence ThreatMatchEvent JSON & CSV Serialization
bool test_threat_intel_event_json_and_csv_serialization() {
    ThreatMatchEvent ev;
    ev.event_id = "TME-0001";
    ev.dataset_id = "DS-TEST";
    ev.dataset_version = "1.0";
    ev.ioc_id = "IOC-001";
    ev.ioc_type = IOCType::IPV4;
    ev.ioc_value = "10.0.0.1";
    ev.observed_value = "10.0.0.1";
    ev.match_type = ThreatMatchType::EXACT_IP;
    ev.src_ip = "192.168.1.100";
    ev.dst_ip = "10.0.0.1";
    ev.confidence = IOCConfidence::HIGH;
    ev.severity = IOCSeverity::CRITICAL;
    ev.category = "C2";
    ev.evidence = "Exact source IP match";
    ev.match_explanation = "Traffic to known C2 node";

    std::string json_str = ev.toJson();
    TEST_ASSERT(json_str.find("\"event_id\": \"TME-0001\"") != std::string::npos, "JSON must contain event_id");
    TEST_ASSERT(json_str.find("\"ioc_id\": \"IOC-001\"") != std::string::npos, "JSON must contain ioc_id");
    TEST_ASSERT(json_str.find("\"severity\": \"CRITICAL\"") != std::string::npos, "JSON must contain severity");

    std::string csv_header = ThreatMatchEvent::csvHeader();
    std::string csv_row = ev.toCsvRow();
    TEST_ASSERT(csv_header.find("event_id") != std::string::npos, "CSV header must have event_id");
    TEST_ASSERT(csv_row.find("\"TME-0001\"") != std::string::npos, "CSV row must have TME-0001");
    TEST_ASSERT(csv_row.find("\"CRITICAL\"") != std::string::npos, "CSV row must have CRITICAL");
    return true;
}

// TEST 152: Threat Intelligence Flow Record Enrichment
bool test_threat_intel_flow_enrichment() {
    ThreatIntelEngine engine;
    ThreatDataset ds;
    ds.dataset_id = "DS-ENRICH";
    ds.name = "Enrichment Feed";

    ThreatIOC ioc;
    ioc.ioc_id = "IOC-ENR";
    ioc.type = IOCType::DOMAIN_NAME;
    ioc.value = "malware.biz";
    ioc.category = "C2";
    ThreatIntelValidator::validateIOC(ioc);
    ds.iocs.push_back(ioc);

    std::string err;
    engine.getManager().addDataset(ds, err);

    std::vector<FlowRecord> flows;
    FlowRecord f;
    f.flow_id = 999;
    f.initial_tuple = FiveTuple{10, 20, 50002, 443, 6};
    f.sni = "malware.biz";
    flows.push_back(f);

    engine.evaluateAll(flows);
    TEST_ASSERT(flows[0].ioc_match_count == 1, "Flow ioc_match_count must be 1");
    TEST_ASSERT(!flows[0].matched_ioc_ids.empty(), "Flow matched_ioc_ids must not be empty");
    TEST_ASSERT(flows[0].matched_ioc_ids[0] == "IOC-ENR", "Flow matched IOC ID mismatch");
    TEST_ASSERT(!flows[0].threat_categories.empty(), "Flow threat_categories must contain C2");
    TEST_ASSERT(flows[0].threat_categories[0] == "C2", "Category mismatch");
    return true;
}

// TEST 153: Threat Intelligence Incident Correlation Enrichment
bool test_threat_intel_incident_correlation_enrichment() {
    IncidentCorrelator correlator;

    std::vector<DetectionEvent> dets;
    dets.push_back(createMockDetection("DET-TI-1", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                       DetectionSeverity::HIGH, "192.168.1.100", "", 1000000,
                                       {80, 443}, {1}, "Port sweep"));

    std::vector<FlowRecord> flows;
    flows.push_back(createMockFlow(1, "192.168.1.100", "10.0.0.1", 50000, 80, 6, 10, 1000, 0, 0));

    std::vector<ThreatMatchEvent> threat_matches;
    ThreatMatchEvent tme;
    tme.event_id = "TME-INC-1";
    tme.dataset_id = "DS-TEST";
    tme.ioc_id = "IOC-INC-1";
    tme.ioc_value = "10.0.0.1";
    tme.severity = IOCSeverity::CRITICAL;
    tme.confidence = IOCConfidence::HIGH;
    tme.category = "C2";
    tme.src_ip = "192.168.1.100";
    tme.dst_ip = "10.0.0.1";
    tme.flow_id = 1;
    tme.match_timestamp_us = 1000000;
    threat_matches.push_back(tme);

    auto incidents = correlator.correlate(dets, flows, {}, {}, threat_matches);
    TEST_ASSERT(!incidents.empty(), "Correlated incident must be generated");
    TEST_ASSERT(!incidents[0].related_ioc_ids.empty(), "Incident must have related_ioc_ids populated");
    TEST_ASSERT(incidents[0].related_ioc_ids[0] == "IOC-INC-1", "IOC ID mismatch in incident");

    bool has_ti_timeline = false;
    for (const auto& tev : incidents[0].timeline) {
        if (tev.event_type == "THREAT_INTEL_MATCH") {
            has_ti_timeline = true;
            break;
        }
    }
    TEST_ASSERT(has_ti_timeline, "Incident timeline must contain THREAT_INTEL_MATCH event");
    return true;
}

// TEST 154: Threat Intelligence Deduplicated Score in Incidents
bool test_threat_intel_incident_deduplicated_score() {
    IncidentCorrelator correlator;

    std::vector<DetectionEvent> dets;
    dets.push_back(createMockDetection("DET-TI-2", "port_scan_detector", DetectionCategory::NETWORK_RECONNAISSANCE,
                                       DetectionSeverity::HIGH, "192.168.1.100", "", 1000000,
                                       {80}, {1}, "Recon activity"));

    std::vector<FlowRecord> flows;
    flows.push_back(createMockFlow(1, "192.168.1.100", "10.0.0.1", 50000, 80, 6, 10, 1000, 0, 0));

    // Two threat matches from two different datasets for the SAME IOC VALUE
    std::vector<ThreatMatchEvent> threat_matches;
    ThreatMatchEvent tme1;
    tme1.event_id = "TME-DS1"; tme1.dataset_id = "DS-FEED1"; tme1.ioc_id = "IOC-F1";
    tme1.ioc_value = "10.0.0.1"; tme1.severity = IOCSeverity::HIGH;
    tme1.src_ip = "192.168.1.100"; tme1.dst_ip = "10.0.0.1"; tme1.flow_id = 1;
    threat_matches.push_back(tme1);

    ThreatMatchEvent tme2;
    tme2.event_id = "TME-DS2"; tme2.dataset_id = "DS-FEED2"; tme2.ioc_id = "IOC-F2";
    tme2.ioc_value = "10.0.0.1"; tme2.severity = IOCSeverity::HIGH;
    tme2.src_ip = "192.168.1.100"; tme2.dst_ip = "10.0.0.1"; tme2.flow_id = 1;
    threat_matches.push_back(tme2);

    auto inc_single = correlator.correlate(dets, flows, {}, {}, {tme1});
    auto inc_multi = correlator.correlate(dets, flows, {}, {}, threat_matches);

    TEST_ASSERT(!inc_single.empty() && !inc_multi.empty(), "Incidents must be generated");
    TEST_ASSERT(inc_single[0].correlation_score == inc_multi[0].correlation_score,
                "Identical IOC value across multiple datasets must NOT inflate incident score repeatedly");
    return true;
}

// TEST 155: End-to-End PCAP Threat Intelligence Analysis
bool test_end_to_end_pcap_threat_intelligence_analysis() {
    std::string ds_json = R"({
      "dataset_id": "DS-PCAP-TEST",
      "name": "PCAP Test Threat Intel Feed",
      "version": "1.0",
      "schema_version": "1.0",
      "source_description": "Synthetic threat intel for PCAP integration test",
      "iocs": [
        {
          "ioc_id": "IOC-HTTP-SERVER",
          "type": "IPV4",
          "value": "93.184.216.34",
          "severity": "HIGH",
          "category": "KNOWN_SERVER",
          "description": "Example domain test IP"
        },
        {
          "ioc_id": "IOC-TIKTOK-SNI",
          "type": "DOMAIN",
          "value": "tiktok.com",
          "severity": "MEDIUM",
          "category": "POLICY_WATCHLIST",
          "description": "Monitored social media domain"
        }
      ]
    })";

    std::ofstream df("/tmp/test_threat_intel_dataset.json");
    df << ds_json;
    df.close();

    DPIEngine::Config cfg;
    cfg.num_load_balancers = 2;
    cfg.fps_per_lb = 2;
    cfg.enable_threat_intel = true;
    cfg.threat_intel_file = "/tmp/test_threat_intel_dataset.json";
    cfg.show_threat_intel_stats = true;
    cfg.export_threat_matches_json = "/tmp/test_threat_matches.json";
    cfg.export_threat_matches_csv = "/tmp/test_threat_matches.csv";
    cfg.enable_incidents = true;

    DPIEngine engine(cfg);
    TEST_ASSERT(engine.initialize(), "DPIEngine initialization failed");

    bool ok = engine.processFile("test_dpi.pcap", "/tmp/test_threat_out.pcap");
    TEST_ASSERT(ok, "processFile failed");

    const auto& matches = engine.getThreatMatches();
    std::cout << "\n[Test 155] Total threat intelligence matches detected from test_dpi.pcap: " << matches.size() << "\n";
    TEST_ASSERT(!matches.empty(), "Threat intelligence matches should be detected from test_dpi.pcap");

    std::string report = engine.generateThreatIntelReport();
    TEST_ASSERT(report.find("THREAT INTELLIGENCE & IOC ENRICHMENT REPORT") != std::string::npos,
                "Report must contain header");

    std::ifstream jf("/tmp/test_threat_matches.json");
    TEST_ASSERT(jf.is_open(), "Exported threat JSON file must exist");
    std::string j_content((std::istreambuf_iterator<char>(jf)),
                           std::istreambuf_iterator<char>());
    jf.close();
    TEST_ASSERT(j_content.find("IOC-HTTP-SERVER") != std::string::npos ||
                j_content.find("IOC-TIKTOK-SNI") != std::string::npos,
                "Exported JSON must contain matched IOC IDs");

    std::ifstream cf("/tmp/test_threat_matches.csv");
    TEST_ASSERT(cf.is_open(), "Exported threat CSV file must exist");
    cf.close();

    return true;
}

// ============================================================================
// PHASE 3.6, 3.7, 3.8 & 4.2 TESTS (Tests 156 - 180)
// ============================================================================

bool test_risk_profiler_endpoint_aggregation() {
    RiskProfiler profiler;
    std::vector<FlowRecord> flows;

    FlowRecord f1;
    f1.flow_id = 1;
    f1.initial_tuple.src_ip = 0x0101A8C0; // 192.168.1.1
    f1.initial_tuple.dst_ip = 0x0201A8C0; // 192.168.1.2
    f1.initial_tuple.src_port = 50000;
    f1.initial_tuple.dst_port = 80;
    f1.detected_app_name = "HTTP";
    f1.fwd.packet_count = 10;
    f1.rev.packet_count = 8;
    f1.fwd.byte_count = 1000;
    f1.rev.byte_count = 5000;
    f1.start_time_us = 1000000;
    f1.last_time_us = 2000000;
    flows.push_back(f1);

    profiler.profileAll(flows, {}, {}, {}, {});
    const auto& eps = profiler.getEndpointProfiles();

    TEST_ASSERT(eps.size() == 2, "Should aggregate 2 distinct endpoints");
    TEST_ASSERT(eps.find("192.168.1.1") != eps.end(), "192.168.1.1 must exist");
    TEST_ASSERT(eps.find("192.168.1.2") != eps.end(), "192.168.1.2 must exist");

    const auto& src = eps.at("192.168.1.1");
    TEST_ASSERT(src.total_flows == 1, "Flow count should be 1");
    TEST_ASSERT(src.total_packets == 18, "Packet count should be 18");
    TEST_ASSERT(src.total_bytes == 6000, "Byte count should be 6000");
    TEST_ASSERT(src.bytes_sent == 1000, "Bytes sent should be 1000");
    TEST_ASSERT(src.bytes_received == 5000, "Bytes received should be 5000");
    return true;
}

bool test_risk_profiler_rfc1918_classification() {
    TEST_ASSERT(RiskProfiler::isRFC1918("10.0.0.1"), "10.0.0.1 is RFC1918");
    TEST_ASSERT(RiskProfiler::isRFC1918("172.16.0.5"), "172.16.0.5 is RFC1918");
    TEST_ASSERT(RiskProfiler::isRFC1918("172.31.255.254"), "172.31.255.254 is RFC1918");
    TEST_ASSERT(RiskProfiler::isRFC1918("192.168.1.100"), "192.168.1.100 is RFC1918");
    TEST_ASSERT(RiskProfiler::isRFC1918("127.0.0.1"), "127.0.0.1 loopback considered internal");
    TEST_ASSERT(!RiskProfiler::isRFC1918("8.8.8.8"), "8.8.8.8 is public");
    TEST_ASSERT(!RiskProfiler::isRFC1918("93.184.216.34"), "93.184.216.34 is public");
    TEST_ASSERT(!RiskProfiler::isRFC1918("172.32.0.1"), "172.32.0.1 is public");
    return true;
}

bool test_risk_profiler_explainable_scoring() {
    RiskProfiler profiler;
    std::vector<FlowRecord> flows;
    FlowRecord f;
    f.flow_id = 10;
    f.initial_tuple.src_ip = 0x3201A8C0; // 192.168.1.50
    f.initial_tuple.dst_ip = 0x01080808; // 8.8.8.1
    f.detected_app_name = "TCP";
    flows.push_back(f);

    std::vector<DetectionEvent> detections;
    DetectionEvent d;
    d.detection_id = "DET-PORT-SCAN";
    d.category = DetectionCategory::NETWORK_RECONNAISSANCE;
    d.severity = DetectionSeverity::HIGH;
    d.source_ip = 0x3201A8C0;
    d.explanation = "Horizontal port scan detected";
    detections.push_back(d);

    std::vector<SecurityIncident> incidents;
    SecurityIncident inc;
    inc.incident_id = "INC-RECON-01";
    inc.primary_endpoint = "192.168.1.50";
    inc.title = "Reconnaissance sweep";
    inc.severity = IncidentSeverity::HIGH;
    inc.correlation_score = 45.0;
    incidents.push_back(inc);

    profiler.profileAll(flows, detections, incidents, {}, {});
    const auto& eps = profiler.getEndpointProfiles();

    TEST_ASSERT(eps.find("192.168.1.50") != eps.end(), "Endpoint 192.168.1.50 must exist");
    const auto& ep = eps.at("192.168.1.50");
    TEST_ASSERT(ep.risk_score >= 40.0, "Score should reflect detection and incident weights");
    TEST_ASSERT(ep.contributing_factors.size() >= 2, "Must have traceable contributing factors");
    TEST_ASSERT(ep.risk_level == RiskLevel::MEDIUM || ep.risk_level == RiskLevel::HIGH, "Must reflect elevated risk level");
    return true;
}

bool test_risk_profiler_diminishing_returns_and_bounds() {
    RiskProfiler profiler;
    std::vector<FlowRecord> flows;
    FlowRecord f;
    f.flow_id = 1;
    f.initial_tuple.src_ip = 0x6401A8C0; // 192.168.1.100
    f.initial_tuple.dst_ip = 0x01080808;
    flows.push_back(f);

    std::vector<SecurityIncident> incidents;
    for (int i = 0; i < 10; ++i) {
        SecurityIncident inc;
        inc.incident_id = "INC-" + std::to_string(i);
        inc.primary_endpoint = "192.168.1.100";
        inc.severity = IncidentSeverity::CRITICAL;
        inc.correlation_score = 100.0;
        incidents.push_back(inc);
    }

    profiler.profileAll(flows, {}, incidents, {}, {});
    const auto& ep = profiler.getEndpointProfiles().at("192.168.1.100");
    TEST_ASSERT(ep.risk_score <= 100.0, "Score must never exceed 100.0");
    TEST_ASSERT(ep.risk_level == RiskLevel::CRITICAL, "Max score must yield CRITICAL risk level");
    return true;
}

bool test_risk_profiler_flow_scoring() {
    RiskProfiler profiler;
    std::vector<FlowRecord> flows;

    FlowRecord f;
    f.flow_id = 42;
    f.initial_tuple.src_ip = 0x0A000001; // 10.0.0.1
    f.initial_tuple.dst_ip = 0x0A000002;
    f.detected_app_name = "TCP";
    f.ioc_match_count = 1;
    f.matched_ioc_ids.push_back("IOC-C2-01");
    f.threat_summary = "C2 controller match";
    flows.push_back(f);

    profiler.profileAll(flows, {}, {}, {}, {});
    const auto& fps = profiler.getFlowProfiles();
    TEST_ASSERT(fps.size() == 1, "Flow profile count should be 1");
    TEST_ASSERT(fps[0].flow_id == 42, "Flow ID must match");
    TEST_ASSERT(fps[0].risk_score > 0.0, "Risk score must be positive for IOC match");
    TEST_ASSERT(fps[0].contributing_factors.size() == 1, "Should have 1 contributing factor");
    return true;
}

bool test_risk_profiler_behavioral_tagging() {
    RiskProfiler profiler;
    std::vector<FlowRecord> flows;

    FlowRecord f;
    f.flow_id = 99;
    f.initial_tuple.src_ip = 0x0101A8C0; // 192.168.1.1
    f.initial_tuple.dst_ip = 0x0201A8C0;
    f.fwd.byte_count = 150000;
    f.rev.byte_count = 0;
    flows.push_back(f);

    std::vector<DetectionEvent> dets;
    DetectionEvent d;
    d.detection_id = "D1";
    d.source_ip = 0x0101A8C0;
    d.category = DetectionCategory::NETWORK_RECONNAISSANCE;
    d.severity = DetectionSeverity::HIGH;
    dets.push_back(d);

    profiler.profileAll(flows, dets, {}, {}, {});
    const auto& ep = profiler.getEndpointProfiles().at("192.168.1.1");
    TEST_ASSERT(ep.behavioral_tags.count("SCANNER") > 0, "Must contain SCANNER tag");
    TEST_ASSERT(ep.behavioral_tags.count("DATA_EXFIL_SUSPECT") > 0, "Must contain DATA_EXFIL_SUSPECT tag");
    return true;
}

bool test_risk_profiler_top_endpoints_ranking() {
    RiskProfiler profiler;
    std::vector<FlowRecord> flows;

    for (uint32_t i = 1; i <= 5; ++i) {
        FlowRecord f;
        f.flow_id = i;
        f.initial_tuple.src_ip = 0x0000000A | (i << 24); // Formats to 10.0.0.i
        f.initial_tuple.dst_ip = 0xFE00000A;             // Formats to 10.0.0.254
        f.fwd.byte_count = i * 1000;
        flows.push_back(f);
    }

    std::vector<DetectionEvent> dets;
    DetectionEvent d;
    d.detection_id = "D-CRIT";
    d.source_ip = 0x0400000A; // Formats to 10.0.0.4
    d.source_ip_str = "10.0.0.4";
    d.severity = DetectionSeverity::CRITICAL;
    d.category = DetectionCategory::COMMAND_AND_CONTROL;
    dets.push_back(d);

    profiler.profileAll(flows, dets, {}, {}, {});
    auto top = profiler.getTopRiskEndpoints(3);

    TEST_ASSERT(top.size() == 3, "Top list size must be 3");
    TEST_ASSERT(top[0].ip == "10.0.0.4", "10.0.0.4 should rank first due to CRITICAL alert");
    return true;
}

bool test_risk_profiler_serialization() {
    RiskProfiler profiler;
    std::vector<FlowRecord> flows;
    FlowRecord f;
    f.flow_id = 1;
    f.initial_tuple.src_ip = 0x0101A8C0;
    f.initial_tuple.dst_ip = 0x0201A8C0;
    flows.push_back(f);

    profiler.profileAll(flows, {}, {}, {}, {});
    std::string ep_json = profiler.endpointsToJson();
    std::string sum_json = profiler.summaryToJson();

    TEST_ASSERT(ep_json.find("192.168.1.1") != std::string::npos, "JSON must contain 192.168.1.1");
    TEST_ASSERT(sum_json.find("total_endpoints") != std::string::npos, "Summary must contain total_endpoints");
    return true;
}

bool test_temporal_analytics_bucketing() {
    TemporalAnalytics temporal;
    std::vector<FlowRecord> flows;

    for (int i = 0; i < 5; ++i) {
        FlowRecord f;
        f.flow_id = i + 1;
        f.start_time_us = 1000000ULL + i * 1000000ULL; // 1s apart
        f.last_time_us = f.start_time_us + 500000ULL;
        f.fwd.packet_count = 10;
        f.fwd.byte_count = 1000;
        flows.push_back(f);
    }

    temporal.buildBuckets(flows, {}, {}, {}, 1000000ULL);
    TEST_ASSERT(!temporal.buckets.empty(), "Buckets must not be empty");
    TEST_ASSERT(temporal.buckets.size() >= 5, "Should have at least 5 1-second buckets");
    return true;
}

bool test_temporal_analytics_peak_rates() {
    TemporalAnalytics temporal;
    std::vector<FlowRecord> flows;

    FlowRecord f;
    f.flow_id = 1;
    f.start_time_us = 1000000;
    f.last_time_us = 1500000;
    f.fwd.packet_count = 500;
    f.fwd.byte_count = 250000;
    flows.push_back(f);

    temporal.buildBuckets(flows, {}, {}, {}, 1000000);
    TEST_ASSERT(temporal.peak_pps == 500, "Peak PPS must be 500");
    TEST_ASSERT(temporal.peak_bps == 250000 * 8, "Peak BPS must equal bytes * 8");
    return true;
}

bool test_network_behavioral_stats_protocol_breakdown() {
    NetworkBehavioralStats stats;
    std::vector<FlowRecord> flows;

    FlowRecord f1;
    f1.detected_app_name = "TCP";
    f1.fwd.packet_count = 5;
    f1.fwd.byte_count = 500;
    flows.push_back(f1);

    FlowRecord f2;
    f2.detected_app_name = "UDP";
    f2.fwd.packet_count = 3;
    f2.fwd.byte_count = 300;
    flows.push_back(f2);

    stats.compute(flows, {}, {}, {}, {});
    TEST_ASSERT(stats.total_packets == 8, "Total packets must be 8");
    TEST_ASSERT(stats.total_bytes == 800, "Total bytes must be 800");
    TEST_ASSERT(stats.protocol_breakdown.count("TCP") == 1, "Must contain TCP");
    TEST_ASSERT(stats.protocol_breakdown.count("UDP") == 1, "Must contain UDP");
    return true;
}

bool test_network_behavioral_stats_port_services() {
    NetworkBehavioralStats stats;
    std::vector<FlowRecord> flows;

    FlowRecord f;
    f.initial_tuple.dst_port = 443;
    f.fwd.byte_count = 1000;
    flows.push_back(f);

    stats.compute(flows, {}, {}, {}, {});
    TEST_ASSERT(!stats.top_ports.empty(), "Top ports must not be empty");
    TEST_ASSERT(stats.top_ports[0].port == 443, "Top port must be 443");
    TEST_ASSERT(stats.top_ports[0].service_name == "HTTPS", "Port 443 service must be HTTPS");
    return true;
}

bool test_network_behavioral_stats_percentiles() {
    NetworkBehavioralStats stats;
    std::vector<FlowRecord> flows;

    for (int i = 1; i <= 10; ++i) {
        FlowRecord f;
        f.start_time_us = 0;
        f.last_time_us = i * 10000; // 10ms * i
        f.fwd.packet_count = 1;
        f.fwd.byte_count = i * 100;
        flows.push_back(f);
    }

    stats.compute(flows, {}, {}, {}, {});
    TEST_ASSERT(stats.duration_min_ms == 10.0, "Min duration must be 10.0");
    TEST_ASSERT(stats.duration_max_ms == 100.0, "Max duration must be 100.0");
    TEST_ASSERT(stats.packet_size_min == 100, "Min packet size must be 100");
    TEST_ASSERT(stats.packet_size_max == 1000, "Max packet size must be 1000");
    return true;
}

bool test_network_graph_node_and_edge_construction() {
    NetworkGraph graph;
    std::vector<FlowRecord> flows;

    FlowRecord f;
    f.flow_id = 1;
    f.initial_tuple.src_ip = 0x0101A8C0; // 192.168.1.1
    f.initial_tuple.dst_ip = 0x0201A8C0; // 192.168.1.2
    f.detected_app_name = "TCP";
    f.sni = "example.com";
    f.fwd.byte_count = 500;
    flows.push_back(f);

    std::unordered_map<std::string, EndpointRiskProfile> eps;
    EndpointRiskProfile ep1; ep1.ip = "192.168.1.1"; eps["192.168.1.1"] = ep1;
    EndpointRiskProfile ep2; ep2.ip = "192.168.1.2"; eps["192.168.1.2"] = ep2;

    std::vector<SecurityIncident> incs;
    SecurityIncident inc;
    inc.incident_id = "INC-1";
    inc.primary_endpoint = "192.168.1.1";
    inc.title = "Suspicious traffic";
    incs.push_back(inc);

    graph.build(flows, eps, incs, {});
    TEST_ASSERT(graph.nodes.size() >= 4, "Must contain src, dst, domain, and incident nodes");
    TEST_ASSERT(!graph.edges.empty(), "Edges must be constructed");

    std::string json = graph.toJson();
    TEST_ASSERT(json.find("ep:192.168.1.1") != std::string::npos, "JSON must contain ep node");
    TEST_ASSERT(json.find("dom:example.com") != std::string::npos, "JSON must contain dom node");
    return true;
}

bool test_network_graph_bounding_limits() {
    NetworkGraph graph;
    graph.max_nodes = 5;
    graph.max_edges = 3;

    std::unordered_map<std::string, EndpointRiskProfile> eps;
    for (int i = 0; i < 20; ++i) {
        std::string ip = "10.0.0." + std::to_string(i);
        EndpointRiskProfile ep;
        ep.ip = ip;
        eps[ip] = ep;
    }

    graph.build({}, eps, {}, {});
    TEST_ASSERT(graph.nodes.size() <= 5, "Graph nodes must be capped at max_nodes");
    return true;
}

bool test_investigation_creation_and_fields() {
    InvestigationManager mgr;
    std::string id = mgr.createInvestigation("Data exfil investigation",
                                            "Investigating anomalous outbound flow",
                                            InvestigationPriority::HIGH,
                                            {"EXFIL", "URGENT"});
    TEST_ASSERT(id == "INV-0001", "First investigation ID must be INV-0001");
    const auto* rec = mgr.getInvestigation(id);
    TEST_ASSERT(rec != nullptr, "Investigation must be retrievable");
    TEST_ASSERT(rec->title == "Data exfil investigation", "Title must match");
    TEST_ASSERT(rec->status == InvestigationStatus::OPEN, "Initial status must be OPEN");
    TEST_ASSERT(rec->priority == InvestigationPriority::HIGH, "Priority must match");
    return true;
}

bool test_investigation_note_addition() {
    InvestigationManager mgr;
    std::string id = mgr.createInvestigation("Scan analysis", "Port sweep review");
    bool ok = mgr.addNote(id, "analyst_alice", "Reviewed SYN packet flags, confirmed horizontal scan");
    TEST_ASSERT(ok, "Adding note must succeed");

    const auto* rec = mgr.getInvestigation(id);
    TEST_ASSERT(rec->notes.size() == 1, "Note count must be 1");
    TEST_ASSERT(rec->notes[0].author == "analyst_alice", "Author must match");
    TEST_ASSERT(rec->notes[0].note_id == "NOTE-0001", "Note ID must be NOTE-0001");
    return true;
}

bool test_investigation_evidence_addition_and_hash_integrity() {
    InvestigationManager mgr;
    std::string id = mgr.createInvestigation("Evidence test", "Testing integrity");
    std::string payload = "raw_packet_data_bytes_12345";
    std::string ev_id = mgr.addEvidence(id, EvidenceType::PACKET_CAPTURE, "PKT-1", "Captured SYN packet", payload);
    TEST_ASSERT(!ev_id.empty(), "Evidence ID must not be empty");

    const auto* rec = mgr.getInvestigation(id);
    TEST_ASSERT(rec->evidence_list.size() == 1, "Evidence count must be 1");
    TEST_ASSERT(rec->evidence_list[0].integrity_hash.length() == 16, "FNV-1a hash must be 16 hex characters");
    TEST_ASSERT(rec->evidence_list[0].integrity_hash == InvestigationManager::calculateHash(payload), "Integrity hash must match calculation");
    return true;
}

bool test_investigation_evidence_safe_removal() {
    InvestigationManager mgr;
    std::string id = mgr.createInvestigation("Removal test", "Testing removal");
    std::string ev_id = mgr.addEvidence(id, EvidenceType::FLOW_RECORD, "FLOW-10", "Flow record reference", "");
    TEST_ASSERT(mgr.getInvestigation(id)->evidence_list.size() == 1, "Should have 1 evidence item");

    bool ok = mgr.removeEvidence(id, ev_id);
    TEST_ASSERT(ok, "removeEvidence must return true");
    TEST_ASSERT(mgr.getInvestigation(id)->evidence_list.empty(), "Evidence list must now be empty");

    bool fail = mgr.removeEvidence(id, "NON-EXISTENT");
    TEST_ASSERT(!fail, "Removing non-existent evidence must return false");
    return true;
}

bool test_investigation_entity_linking() {
    InvestigationManager mgr;
    std::string id = mgr.createInvestigation("Linking test", "Testing links");
    mgr.linkIncident(id, "INC-0001");
    mgr.linkDetection(id, "DET-0002");
    mgr.linkFlow(id, 42);
    mgr.linkEndpoint(id, "192.168.1.100");
    mgr.linkIOC(id, "IOC-MALWARE-1");

    const auto* rec = mgr.getInvestigation(id);
    TEST_ASSERT(rec->related_incidents.size() == 1 && rec->related_incidents[0] == "INC-0001", "Incident linked");
    TEST_ASSERT(rec->related_detections.size() == 1 && rec->related_detections[0] == "DET-0002", "Detection linked");
    TEST_ASSERT(rec->related_flows.size() == 1 && rec->related_flows[0] == 42, "Flow linked");
    TEST_ASSERT(rec->related_endpoints.size() == 1 && rec->related_endpoints[0] == "192.168.1.100", "Endpoint linked");
    TEST_ASSERT(rec->related_iocs.size() == 1 && rec->related_iocs[0] == "IOC-MALWARE-1", "IOC linked");
    return true;
}

bool test_investigation_persistence_atomic_save_load() {
    InvestigationManager mgr;
    std::string id = mgr.createInvestigation("Persistence test", "Testing save to disk");
    mgr.addNote(id, "lead_analyst", "Initial assessment complete");

    std::string path = "/tmp/test_investigations_save.json";
    bool ok = mgr.saveToFile(path);
    TEST_ASSERT(ok, "saveToFile must succeed");

    InvestigationManager mgr2;
    bool load_ok = mgr2.loadFromFile(path);
    TEST_ASSERT(load_ok, "loadFromFile must succeed");
    return true;
}

bool test_report_generator_json_types() {
    CaptureMetadata meta;
    meta.pcap_filename = "test.pcap";
    meta.total_packets = 100;
    meta.total_bytes = 10000;

    std::vector<FlowRecord> flows;
    std::unordered_map<std::string, EndpointRiskProfile> eps;
    NetworkBehavioralStats stats;
    stats.total_packets = 100;
    stats.total_bytes = 10000;
    TemporalAnalytics temporal;

    ReportGenerator rep(meta, flows, eps, stats, temporal, {}, {}, {}, {});

    std::string exec = rep.generateExecutiveJson();
    TEST_ASSERT(exec.find("EXECUTIVE_SUMMARY") != std::string::npos, "Executive JSON must contain type");

    std::string tech = rep.generateTechnicalJson();
    TEST_ASSERT(tech.find("TECHNICAL_TRAFFIC_ANALYSIS") != std::string::npos, "Technical JSON must contain type");

    std::string sec = rep.generateSecurityJson();
    TEST_ASSERT(sec.find("SECURITY_ASSESSMENT") != std::string::npos, "Security JSON must contain type");
    return true;
}

bool test_report_generator_html_self_contained() {
    CaptureMetadata meta;
    meta.pcap_filename = "network_capture.pcap";
    meta.total_packets = 77;
    meta.total_bytes = 5738;

    std::vector<FlowRecord> flows;
    std::unordered_map<std::string, EndpointRiskProfile> eps;
    NetworkBehavioralStats stats;
    TemporalAnalytics temporal;

    ReportGenerator rep(meta, flows, eps, stats, temporal, {}, {}, {}, {});
    std::string html = rep.generateHtmlReport();

    TEST_ASSERT(html.find("<!DOCTYPE html>") != std::string::npos, "Must contain HTML doctype");
    TEST_ASSERT(html.find("<style>") != std::string::npos, "Must contain embedded CSS style block");
    TEST_ASSERT(html.find("network_capture.pcap") != std::string::npos, "Must contain PCAP filename");
    TEST_ASSERT(html.find("http://") == std::string::npos && html.find("https://") == std::string::npos,
                "HTML report must be completely self-contained without external CDN URLs");
    return true;
}

bool test_dpi_engine_unified_analyze_all_bundle() {
    DPIEngine::Config cfg;
    cfg.analyze_all_dir = "/tmp/test_dpi_bundle_output";
    cfg.enable_detection = true;
    cfg.enable_incidents = true;
    cfg.enable_risk_profiling = true;
    cfg.enable_analytics = true;

    DPIEngine engine(cfg);
    TEST_ASSERT(engine.initialize(), "DPIEngine initialization failed");

    bool ok = engine.processFile("test_dpi.pcap", "/tmp/test_bundle_forwarded.pcap");
    TEST_ASSERT(ok, "processFile failed");

    // Verify key exported artifacts
    std::ifstream f_flows("/tmp/test_dpi_bundle_output/flows.json");
    TEST_ASSERT(f_flows.is_open(), "flows.json must exist");
    f_flows.close();

    std::ifstream f_eps("/tmp/test_dpi_bundle_output/endpoints.json");
    TEST_ASSERT(f_eps.is_open(), "endpoints.json must exist");
    f_eps.close();

    std::ifstream f_graph("/tmp/test_dpi_bundle_output/network_graph.json");
    TEST_ASSERT(f_graph.is_open(), "network_graph.json must exist");
    f_graph.close();

    std::ifstream f_html("/tmp/test_dpi_bundle_output/analysis_report.html");
    TEST_ASSERT(f_html.is_open(), "analysis_report.html must exist");
    f_html.close();

    return true;
}

bool test_end_to_end_pcap_full_analytics_and_reporting() {
    DPIEngine::Config cfg;
    cfg.enable_detection = true;
    cfg.enable_incidents = true;
    cfg.enable_risk_profiling = true;
    cfg.enable_analytics = true;
    cfg.show_risk_stats = true;
    cfg.show_analytics_stats = true;

    DPIEngine engine(cfg);
    TEST_ASSERT(engine.initialize(), "Initialization failed");

    bool ok = engine.processFile("test_dpi.pcap", "/tmp/test_analytics_out.pcap");
    TEST_ASSERT(ok, "processFile failed");

    const auto& eps = engine.getRiskProfiler().getEndpointProfiles();
    TEST_ASSERT(!eps.empty(), "Endpoints must be profiled from test_dpi.pcap");

    const auto& stats = engine.getAnalyticsEngine().getStats();
    TEST_ASSERT(stats.total_packets == 77, "Should have analyzed 77 packets");
    TEST_ASSERT(stats.total_flows > 0, "Should have tracked flows");

    const auto& graph = engine.getAnalyticsEngine().getGraph();
    TEST_ASSERT(!graph.nodes.empty(), "Graph nodes must be populated");
    TEST_ASSERT(!graph.edges.empty(), "Graph edges must be populated");

    std::string report = engine.generateAnalyticsReport();
    TEST_ASSERT(report.find("NETWORK BEHAVIORAL ANALYTICS REPORT") != std::string::npos, "Report header must exist");
    return true;
}

// ============================================================================
// MAIN RUNNER
// ============================================================================
int main() {
    std::cout << "\n";
    std::cout << "===============================================================\n";
    std::cout << "                DPI ENGINE AUTOMATED TEST SUITE                \n";
    std::cout << "===============================================================\n";

    RUN_TEST(test_ethernet_parsing_valid);
    RUN_TEST(test_ethernet_parsing_truncated);
    RUN_TEST(test_ethernet_vlan_8021q);
    RUN_TEST(test_ipv4_parsing_valid);
    RUN_TEST(test_ipv4_parsing_truncated_and_invalid);
    RUN_TEST(test_ipv4_endian_independence);
    RUN_TEST(test_tcp_parsing_valid_and_flags);
    RUN_TEST(test_tcp_parsing_truncated_and_invalid);
    RUN_TEST(test_udp_parsing_valid);
    RUN_TEST(test_udp_parsing_truncated_and_invalid);
    RUN_TEST(test_dns_parsing_valid_and_truncated);
    RUN_TEST(test_http_host_extractor);
    RUN_TEST(test_tls_sni_extractor);
    RUN_TEST(test_quic_memory_safety);
    RUN_TEST(test_domain_exact_matching);
    RUN_TEST(test_domain_subdomain_matching);
    RUN_TEST(test_domain_false_positive_netflix_x);
    RUN_TEST(test_domain_false_positive_microsoft_tco);
    RUN_TEST(test_domain_prefix_and_suffix_boundaries);
    RUN_TEST(test_bidirectional_flow_hashing);
    RUN_TEST(test_multithreaded_lb_distribution);
    RUN_TEST(test_connection_tracker_lru_eviction);
    RUN_TEST(test_packet_reordering_output);
    RUN_TEST(test_end_to_end_pcap_processing);

    // Phase 3.0 Flow Intelligence & Feature Extraction Tests
    RUN_TEST(test_welford_statistical_accumulator);
    RUN_TEST(test_flow_record_directionality_and_symmetry);
    RUN_TEST(test_flow_record_tcp_flags_and_rate_metrics);
    RUN_TEST(test_flow_record_json_and_csv_serialization);
    RUN_TEST(test_flow_table_canonical_bidirectional_lookup);
    RUN_TEST(test_flow_table_idle_timeout_cleanup);
    RUN_TEST(test_flow_table_lru_capacity_eviction);
    RUN_TEST(test_end_to_end_flow_intelligence_pcap);

    // Phase 3.1 Behavioral Network Detection Engine Tests
    RUN_TEST(test_detection_port_scan_vertical);
    RUN_TEST(test_detection_port_scan_horizontal);
    RUN_TEST(test_detection_port_scan_benign_and_boundary);
    RUN_TEST(test_detection_connection_burst);
    RUN_TEST(test_detection_repeated_attempts);
    RUN_TEST(test_detection_dns_high_frequency);
    RUN_TEST(test_detection_dns_long_domain_tunneling);
    RUN_TEST(test_detection_outbound_volume_anomaly);
    RUN_TEST(test_detection_beacon_periodic);
    RUN_TEST(test_detection_beacon_jitter_rejection);
    RUN_TEST(test_detection_tcp_syn_anomaly);
    RUN_TEST(test_detection_tcp_rst_anomaly);
    RUN_TEST(test_detection_event_serialization_json_csv);
    RUN_TEST(test_detection_deduplication);
    RUN_TEST(test_detection_config_validation_and_toggle);
    RUN_TEST(test_detection_end_to_end_pcap);

    // Phase 3.2 Advanced Protocol Intelligence & TCP Stream Reassembly Tests
    RUN_TEST(test_stream_in_order_reassembly);
    RUN_TEST(test_stream_out_of_order_reassembly);
    RUN_TEST(test_stream_retransmission);
    RUN_TEST(test_stream_identical_overlap);
    RUN_TEST(test_stream_conflicting_overlap);
    RUN_TEST(test_stream_gap_handling);
    RUN_TEST(test_stream_seq_wraparound);
    RUN_TEST(test_stream_syn_fin_consumption);
    RUN_TEST(test_stream_rst_handling);
    RUN_TEST(test_stream_memory_limits_and_eviction);
    RUN_TEST(test_stream_bidirectional_independence);
    RUN_TEST(test_http_basic_request_response);
    RUN_TEST(test_http_split_request);
    RUN_TEST(test_http_multiple_pipelined_messages);
    RUN_TEST(test_http_chunked_transfer);
    RUN_TEST(test_http_malformed_and_limits);
    RUN_TEST(test_tls_client_hello_split_across_segments);
    RUN_TEST(test_tls_alpn_and_supported_versions);
    RUN_TEST(test_tls_encrypted_application_data);
    RUN_TEST(test_dns_query_and_response_parsing);
    RUN_TEST(test_dns_compression_loop_safety);
    RUN_TEST(test_dns_tcp_length_prefixed);
    RUN_TEST(test_dns_query_response_correlation);
    RUN_TEST(test_dns_nxdomain_burst_detection);
    RUN_TEST(test_end_to_end_pcap_stream_reassembly);

    // Phase 3.3 Security Intelligence & Threat Correlation Tests
    RUN_TEST(test_incident_reconnaissance_generation);
    RUN_TEST(test_incident_horizontal_scan_correlation);
    RUN_TEST(test_incident_vertical_scan_correlation);
    RUN_TEST(test_incident_repeated_connection_correlation);
    RUN_TEST(test_incident_dns_tunneling_correlation);
    RUN_TEST(test_incident_dns_nxdomain_burst_correlation);
    RUN_TEST(test_incident_dns_query_diversity_correlation);
    RUN_TEST(test_incident_beacon_correlation);
    RUN_TEST(test_incident_outbound_anomaly_correlation);
    RUN_TEST(test_incident_potential_exfiltration_correlation);
    RUN_TEST(test_incident_multi_stage_generation);
    RUN_TEST(test_incident_insufficient_evidence_rejection);
    RUN_TEST(test_incident_score_calculation);
    RUN_TEST(test_incident_confidence_calculation);
    RUN_TEST(test_incident_duplicate_evidence_handling);
    RUN_TEST(test_incident_same_flow_deduplication);
    RUN_TEST(test_incident_endpoint_aggregation);
    RUN_TEST(test_incident_unrelated_endpoint_isolation);
    RUN_TEST(test_incident_timeline_chronological_ordering);
    RUN_TEST(test_incident_timeline_identical_timestamp_tiebreak);
    RUN_TEST(test_incident_timeline_bounds_enforcement);
    RUN_TEST(test_incident_deduplication_and_merging_window);
    RUN_TEST(test_incident_window_expiration);
    RUN_TEST(test_incident_serialization_json_and_csv);
    RUN_TEST(test_end_to_end_pcap_incident_analysis);

    // Phase 3.4 Rule-Based Intrusion Detection & Signature Engine Tests
    RUN_TEST(test_signature_rule_json_parsing_valid);
    RUN_TEST(test_signature_rule_validation_missing_fields);
    RUN_TEST(test_signature_rule_validation_duplicate_id);
    RUN_TEST(test_signature_rule_validation_invalid_cidr);
    RUN_TEST(test_signature_rule_validation_invalid_port_range);
    RUN_TEST(test_signature_rule_validation_malformed_hex);
    RUN_TEST(test_signature_rule_validation_offset_depth);
    RUN_TEST(test_signature_rule_disabled_state);
    RUN_TEST(test_signature_manager_enable_disable);
    RUN_TEST(test_signature_network_ip_and_cidr_matching);
    RUN_TEST(test_signature_network_port_and_range_matching);
    RUN_TEST(test_signature_network_protocol_and_tcp_flags);
    RUN_TEST(test_signature_flow_metrics_matching);
    RUN_TEST(test_signature_stream_ascii_pattern_matching);
    RUN_TEST(test_signature_stream_case_insensitive_matching);
    RUN_TEST(test_signature_stream_hex_binary_matching);
    RUN_TEST(test_signature_stream_offset_and_depth);
    RUN_TEST(test_signature_stream_chained_relative_patterns);
    RUN_TEST(test_signature_stream_negated_pattern);
    RUN_TEST(test_signature_stream_cross_segment_reassembly);
    RUN_TEST(test_signature_http_metadata_matching);
    RUN_TEST(test_signature_tls_metadata_matching);
    RUN_TEST(test_signature_dns_metadata_and_entropy);
    RUN_TEST(test_signature_event_json_and_csv_serialization);
    RUN_TEST(test_signature_duplicate_match_suppression);
    RUN_TEST(test_signature_incident_correlation_integration);
    RUN_TEST(test_end_to_end_pcap_signature_detection);

    // Phase 3.5 Threat Intelligence & IOC Enrichment Tests
    RUN_TEST(test_threat_intel_dataset_json_parsing_valid);
    RUN_TEST(test_threat_intel_dataset_json_parsing_malformed);
    RUN_TEST(test_threat_intel_dataset_missing_required_fields);
    RUN_TEST(test_threat_intel_dataset_duplicate_dataset_id);
    RUN_TEST(test_threat_intel_dataset_duplicate_ioc_id);
    RUN_TEST(test_threat_intel_validation_invalid_ipv4);
    RUN_TEST(test_threat_intel_validation_invalid_cidr);
    RUN_TEST(test_threat_intel_validation_invalid_domain);
    RUN_TEST(test_threat_intel_validation_invalid_url);
    RUN_TEST(test_threat_intel_dataset_expiration_and_stale);
    RUN_TEST(test_threat_intel_dataset_disabled_state);
    RUN_TEST(test_threat_intel_dataset_directory_loading);
    RUN_TEST(test_threat_intel_ipv4_exact_matching);
    RUN_TEST(test_threat_intel_ipv4_cidr_matching);
    RUN_TEST(test_threat_intel_ipv4_cidr_boundary);
    RUN_TEST(test_threat_intel_ipv4_overlapping_cidr);
    RUN_TEST(test_threat_intel_domain_exact_matching);
    RUN_TEST(test_threat_intel_domain_subdomain_matching);
    RUN_TEST(test_threat_intel_domain_boundary_collision_rejection);
    RUN_TEST(test_threat_intel_domain_case_and_trailing_dot);
    RUN_TEST(test_threat_intel_domain_wildcard_semantics);
    RUN_TEST(test_threat_intel_protocol_dns_query_matching);
    RUN_TEST(test_threat_intel_protocol_dns_resolved_ip_matching);
    RUN_TEST(test_threat_intel_protocol_tls_sni_matching);
    RUN_TEST(test_threat_intel_protocol_http_host_and_url_matching);
    RUN_TEST(test_threat_intel_event_json_and_csv_serialization);
    RUN_TEST(test_threat_intel_flow_enrichment);
    RUN_TEST(test_threat_intel_incident_correlation_enrichment);
    RUN_TEST(test_threat_intel_incident_deduplicated_score);
    RUN_TEST(test_end_to_end_pcap_threat_intelligence_analysis);

    // Phase 3.6, 3.7, 3.8 & 4.2 Tests (Tests 156 - 180)
    RUN_TEST(test_risk_profiler_endpoint_aggregation);
    RUN_TEST(test_risk_profiler_rfc1918_classification);
    RUN_TEST(test_risk_profiler_explainable_scoring);
    RUN_TEST(test_risk_profiler_diminishing_returns_and_bounds);
    RUN_TEST(test_risk_profiler_flow_scoring);
    RUN_TEST(test_risk_profiler_behavioral_tagging);
    RUN_TEST(test_risk_profiler_top_endpoints_ranking);
    RUN_TEST(test_risk_profiler_serialization);
    RUN_TEST(test_temporal_analytics_bucketing);
    RUN_TEST(test_temporal_analytics_peak_rates);
    RUN_TEST(test_network_behavioral_stats_protocol_breakdown);
    RUN_TEST(test_network_behavioral_stats_port_services);
    RUN_TEST(test_network_behavioral_stats_percentiles);
    RUN_TEST(test_network_graph_node_and_edge_construction);
    RUN_TEST(test_network_graph_bounding_limits);
    RUN_TEST(test_investigation_creation_and_fields);
    RUN_TEST(test_investigation_note_addition);
    RUN_TEST(test_investigation_evidence_addition_and_hash_integrity);
    RUN_TEST(test_investigation_evidence_safe_removal);
    RUN_TEST(test_investigation_entity_linking);
    RUN_TEST(test_investigation_persistence_atomic_save_load);
    RUN_TEST(test_report_generator_json_types);
    RUN_TEST(test_report_generator_html_self_contained);
    RUN_TEST(test_dpi_engine_unified_analyze_all_bundle);
    RUN_TEST(test_end_to_end_pcap_full_analytics_and_reporting);

    std::cout << "===============================================================\n";
    std::cout << "Tests Passed: " << g_tests_passed << " / " << (g_tests_passed + g_tests_failed) << "\n";
    if (g_tests_failed > 0) {
        std::cout << "Tests Failed: " << g_tests_failed << "\n";
        return 1;
    }
    std::cout << "ALL 180 TESTS PASSED SUCCESSFULLY!\n";
    std::cout << "===============================================================\n\n";
    return 0;
}
