# DPI Engine - Deep Packet Inspection System


This document explains **everything** about this project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)
12. [Network Flow Intelligence & Feature Extraction (Phase 3.0)](#12-network-flow-intelligence--feature-extraction-phase-30)
13. [Behavioral Network Detection Engine (Phase 3.1)](#13-behavioral-network-detection-engine-phase-31)
14. [TCP Stream Reassembly & Advanced Protocol Intelligence (Phase 3.2)](#14-tcp-stream-reassembly--advanced-protocol-intelligence-phase-32)
15. [Security Incident Intelligence & Threat Correlation (Phase 3.3)](#15-security-incident-intelligence--threat-correlation-phase-33)
16. [Rule-Based Intrusion Detection & Signature Engine (Phase 3.4)](#16-rule-based-intrusion-detection--signature-engine-phase-34)
17. [Threat Intelligence Enrichment, IOC Matching & Threat Context Engine (Phase 3.5)](#17-threat-intelligence-enrichment-ioc-matching--threat-context-engine-phase-35)
18. [Advanced Analytics, Forensics & Web Platform (Phases 3.6 - 4.4)](#18-advanced-analytics-forensics--web-platform-phases-36---44)
19. [Automated Test Suite (180 Tests)](#19-automated-test-suite-180-tests)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?** 
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### Two Versions

| Version | File | Use Case |
|---------|------|----------|
| Simple (Single-threaded) | `src/main_working.cpp` | Learning, small captures |
| Multi-threaded | `src/dpi_mt.cpp` | Production, large captures |

---

## 4. File Structure

```
packet_analyzer/
├── include/                    # Header files (declarations)
│   ├── pcap_reader.h          # PCAP file reading
│   ├── packet_parser.h        # Network protocol parsing (Ethernet, VLAN, IPv4, TCP, UDP)
│   ├── sni_extractor.h        # TLS, HTTP Host, and DNS inspection
│   ├── types.h                # Data structures (FiveTuple, AppType, etc.)
│   ├── rule_manager.h         # IP, App, Domain boundary, and Port blocking rules
│   ├── connection_tracker.h   # Bidirectional connection state tracking
│   ├── flow_record.h          # Flow metrics, directional telemetry, Welford variance
│   ├── flow_table.h           # Per-worker flow lifecycle manager & O(1) LRU
│   ├── detection_types.h      # Severity, Category, and DetectionEvent models
│   ├── detection_config.h     # Configurable behavioral detection thresholds
│   ├── detector.h             # Abstract base detector interface
│   ├── behavioral_detectors.h # 7 deterministic behavioral detector implementations
│   ├── detection_engine.h     # Detection orchestrator, deduplication & exports
│   ├── stream_types.h         # Stream states, RFC sequence comparison, HTTP/TLS/DNS structures
│   ├── tcp_stream_reassembler.h # Bidirectional stream reassembly, BSD overlap, gap handling
│   ├── http_stream_parser.h   # HTTP/1.x stream parsing, pipelining, chunked bodies
│   ├── tls_stream_parser.h    # Multi-segment TLS ClientHello, SNI, ALPN, cipher suites
│   ├── dns_intelligence.h     # UDP/TCP DNS parsing, pointer loops, TxID correlation
│   ├── incident_types.h       # SecurityIncident, TimelineEvent, categories, severities
│   ├── incident_config.h      # Incident correlation thresholds, weights, rule toggles
│   ├── incident_correlator.h  # Incident correlation engine, scoring, deduplication
│   ├── signature_types.h      # SignatureRule, SignatureEvent, enums, schemas v1.0
│   ├── signature_validator.h  # Deterministic signature rule schema validation
│   ├── signature_parser.h     # Zero-dependency JSON rule & directory parser
│   ├── signature_matcher.h    # Network, flow, stream content, HTTP, TLS, DNS matchers
│   ├── signature_manager.h    # In-memory rule manager, duplicate rejection, stats
│   ├── signature_engine.h     # Signature inspection orchestrator, ASCII report, JSON/CSV exports
│   ├── threat_intel_types.h   # ThreatIOC, ThreatDataset, ThreatMatchEvent, config schemas v1.0
│   ├── threat_intel_validator.h # Strict format validation for IPv4, CIDR, domain, URL, file hash
│   ├── threat_intel_parser.h  # Zero-dependency recursive JSON threat dataset parser & dir loader
│   ├── threat_intel_manager.h # In-memory threat datasets, fast IP/CIDR/domain/URL index lookups
│   ├── threat_intel_engine.h  # Threat intel matcher, flow/incident enricher, report & exports
│   ├── logger.h               # Thread-safe synchronized console logging
│   ├── load_balancer.h        # Multi-tier non-collapsing load balancer
│   ├── fast_path.h            # Fast Path worker thread pool & flow/stream management
│   ├── thread_safe_queue.h    # Bounded thread-safe concurrent queue
│   └── dpi_engine.h           # Main orchestrator & flow/stream/incident/signature/threat coordinator
│
├── src/                        # Implementation files
│   ├── main_dpi.cpp           # Production CLI entry point
│   ├── dpi_engine.cpp         # Orchestrator, reader, reorder buffer, output & export
│   ├── fast_path.cpp          # Classification, rule checks, flow telemetry, stream processing
│   ├── flow_record.cpp        # Numerically stable variance, JSON/CSV serialization
│   ├── flow_table.cpp         # Per-worker flow table, idle cleanup, O(1) LRU eviction
│   ├── detection_types.cpp    # JSON & CSV detection event serializers
│   ├── detection_config.cpp   # Detection configuration loader & validator
│   ├── behavioral_detectors.cpp # Behavioral detector algorithms & telemetry evaluation
│   ├── detection_engine.cpp   # Detection pipeline runner & deduplication window
│   ├── stream_types.cpp       # Sequence comparison helpers, stream summary JSON/CSV
│   ├── tcp_stream_reassembler.cpp # TCPHalfStream, TCPConnectionStream, TCPStreamManager
│   ├── http_stream_parser.cpp # HTTP/1.x message and stream deserializers
│   ├── tls_stream_parser.cpp  # TLS record & ClientHello multi-segment parser
│   ├── dns_intelligence.cpp   # DNS packet/stream parser & query-response correlator
│   ├── incident_types.cpp     # JSON/CSV serializers for incidents & timelines
│   ├── incident_config.cpp    # Incident configuration validation & toggles
│   ├── incident_correlator.cpp # Evidence correlation rules, scoring, deduplication
│   ├── signature_types.cpp    # JSON/CSV serializers for signature rules & events
│   ├── signature_validator.cpp # Rule syntax, CIDR, port, hex, bounds validation
│   ├── signature_parser.cpp   # Custom recursive descent JSON parser & file loader
│   ├── signature_matcher.cpp  # Payload search, chained patterns, entropy calculation
│   ├── signature_manager.cpp  # Rule indexing, activation toggles, performance counters
│   ├── signature_engine.cpp   # Multi-flow/stream evaluation, report generation, exports
│   ├── threat_intel_types.cpp # String conversions, JSON/CSV serialization for IOCs & matches
│   ├── threat_intel_validator.cpp # Validation logic for IP, CIDR, Domain, URL, Hash indicators
│   ├── threat_intel_parser.cpp # Lightweight recursive JSON parser for threat datasets
│   ├── threat_intel_manager.cpp # Index construction, label-stripping domain lookup, CIDR lookup
│   ├── threat_intel_engine.cpp # Indicator matching pipeline, flow/incident enrichment, reporting
│   ├── logger.cpp             # Synchronized logging implementation
│   ├── load_balancer.cpp      # Symmetrical 2-tier flow dispatch
│   ├── connection_tracker.cpp # Symmetrical connection table & state tracking
│   ├── rule_manager.cpp       # Exact & anchored wildcard domain matching
│   ├── packet_parser.cpp      # Safe byte-by-byte alignment-free protocol parser
│   ├── sni_extractor.cpp      # TLS extension parser, DNS query, and HTTP host extractor
│   ├── pcap_reader.cpp        # Binary PCAP format reader
│   └── types.cpp              # Canonical flow hashing & domain matching
│
├── tests/                      # Automated test suite
│   └── test_main.cpp          # Comprehensive unit & integration tests (155 test suites)
│
├── archive/                    # Archived early monolithic prototypes
│   └── legacy_monoliths/      # Retired prototypes (main_working.cpp, dpi_mt.cpp)
│
├── generate_test_pcap.py      # Creates test data
├── test_dpi.pcap              # Sample capture with various traffic
├── Makefile                   # Production build system (make, make asan, make test)
├── CMakeLists.txt             # Modern CMake build configuration
└── README.md                  # This file!
```

---

## 5. The Journey of a Packet (Simple Version)

Let's trace a single packet through `main_working.cpp`:

### Step 1: Read PCAP File

```cpp
PcapReader reader;
reader.open("capture.pcap");
```

**What happens:**
1. Open the file in binary mode
2. Read the 24-byte global header (magic number, version, etc.)
3. Verify it's a valid PCAP file

**PCAP File Format:**
```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp, length
│ Packet Data (variable)     │  ← Actual network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

### Step 2: Read Each Packet

```cpp
while (reader.readNextPacket(raw)) {
    // raw.data contains the packet bytes
    // raw.header contains timestamp and length
}
```

**What happens:**
1. Read 16-byte packet header
2. Read N bytes of packet data (N = header.incl_len)
3. Return false when no more packets

### Step 3: Parse Protocol Headers

```cpp
PacketParser::parse(raw, parsed);
```

**What happens (in packet_parser.cpp):**

```
raw.data bytes:
[0-13]   Ethernet Header
[14-33]  IP Header  
[34-53]  TCP Header
[54+]    Payload

After parsing:
parsed.src_mac  = "00:11:22:33:44:55"
parsed.dest_mac = "aa:bb:cc:dd:ee:ff"
parsed.src_ip   = "192.168.1.100"
parsed.dest_ip  = "172.217.14.206"
parsed.src_port = 54321
parsed.dest_port = 443
parsed.protocol = 6 (TCP)
parsed.has_tcp  = true
```

**Parsing the Ethernet Header (14 bytes):**
```
Bytes 0-5:   Destination MAC
Bytes 6-11:  Source MAC
Bytes 12-13: EtherType (0x0800 = IPv4)
```

**Parsing the IP Header (20+ bytes):**
```
Byte 0:      Version (4 bits) + Header Length (4 bits)
Byte 8:      TTL (Time To Live)
Byte 9:      Protocol (6=TCP, 17=UDP)
Bytes 12-15: Source IP
Bytes 16-19: Destination IP
```

**Parsing the TCP Header (20+ bytes):**
```
Bytes 0-1:   Source Port
Bytes 2-3:   Destination Port
Bytes 4-7:   Sequence Number
Bytes 8-11:  Acknowledgment Number
Byte 12:     Data Offset (header length)
Byte 13:     Flags (SYN, ACK, FIN, etc.)
```

### Step 4: Create Five-Tuple and Look Up Flow

```cpp
FiveTuple tuple;
tuple.src_ip = parseIP(parsed.src_ip);
tuple.dst_ip = parseIP(parsed.dest_ip);
tuple.src_port = parsed.src_port;
tuple.dst_port = parsed.dest_port;
tuple.protocol = parsed.protocol;

Flow& flow = flows[tuple];  // Get or create
```

**What happens:**
- The flow table is a hash map: `FiveTuple → Flow`
- If this 5-tuple exists, we get the existing flow
- If not, a new flow is created
- All packets with the same 5-tuple share the same flow

### Step 5: Extract SNI (Deep Packet Inspection)

```cpp
// For HTTPS traffic (port 443)
if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
    auto sni = SNIExtractor::extract(payload, payload_length);
    if (sni) {
        flow.sni = *sni;                    // "www.youtube.com"
        flow.app_type = sniToAppType(*sni); // AppType::YOUTUBE
    }
}
```

**What happens (in sni_extractor.cpp):**

1. **Check if it's a TLS Client Hello:**
   ```
   Byte 0: Content Type = 0x16 (Handshake) ✓
   Byte 5: Handshake Type = 0x01 (Client Hello) ✓
   ```

2. **Navigate to Extensions:**
   ```
   Skip: Version, Random, Session ID, Cipher Suites, Compression
   ```

3. **Find SNI Extension (type 0x0000):**
   ```
   Extension Type: 0x0000 (SNI)
   Extension Length: N
   SNI List Length: M
   SNI Type: 0x00 (hostname)
   SNI Length: L
   SNI Value: "www.youtube.com"  ← FOUND!
   ```

4. **Map SNI to App Type:**
   ```cpp
   // In types.cpp
   if (sni.find("youtube") != std::string::npos) {
       return AppType::YOUTUBE;
   }
   ```

### Step 6: Check Blocking Rules

```cpp
if (rules.isBlocked(tuple.src_ip, flow.app_type, flow.sni)) {
    flow.blocked = true;
}
```

**What happens:**
```cpp
// Check IP blacklist
if (blocked_ips.count(src_ip)) return true;

// Check app blacklist
if (blocked_apps.count(app)) return true;

// Check domain blacklist (substring match)
for (const auto& dom : blocked_domains) {
    if (sni.find(dom) != std::string::npos) return true;
}

return false;
```

### Step 7: Forward or Drop

```cpp
if (flow.blocked) {
    dropped++;
    // Don't write to output
} else {
    forwarded++;
    // Write packet to output file
    output.write(packet_header);
    output.write(packet_data);
}
```

### Step 8: Generate Report

After processing all packets:
```cpp
// Count apps
for (const auto& [tuple, flow] : flows) {
    app_stats[flow.app_type]++;
}

// Print report
"YouTube: 150 packets (15%)"
"Facebook: 80 packets (8%)"
...
```

---

## 6. The Journey of a Packet (Multi-threaded Version)

The multi-threaded version (`dpi_mt.cpp`) adds **parallelism** for high performance:

### Architecture Overview

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % 2      │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │hash % 2     │               │hash % 2     │
      ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
│(Fast Path)│ │(Fast Path)│   │(Fast Path)│ │(Fast Path)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      │            │              │            │
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Output Queue        │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Output Writer Thread │
              │  (writes to PCAP)     │
              └───────────────────────┘
```

### Why This Design?

1. **Load Balancers (LBs):** Distribute work across FPs
2. **Fast Paths (FPs):** Do the actual DPI processing
3. **Consistent Hashing:** Same 5-tuple always goes to same FP

**Why consistent hashing matters:**
```
Connection: 192.168.1.100:54321 → 142.250.185.206:443

Packet 1 (SYN):         hash → FP2
Packet 2 (SYN-ACK):     hash → FP2  (same FP!)
Packet 3 (Client Hello): hash → FP2  (same FP!)
Packet 4 (Data):        hash → FP2  (same FP!)

All packets of this connection go to FP2.
FP2 can track the flow state correctly.
```

### Detailed Flow

#### Step 1: Reader Thread

```cpp
// Main thread reads PCAP
while (reader.readNextPacket(raw)) {
    Packet pkt = createPacket(raw);
    
    // Hash to select Load Balancer
    size_t lb_idx = hash(pkt.tuple) % num_lbs;
    
    // Push to LB's queue
    lbs_[lb_idx]->queue().push(pkt);
}
```

#### Step 2: Load Balancer Thread

```cpp
void LoadBalancer::run() {
    while (running_) {
        // Pop from my input queue
        auto pkt = input_queue_.pop();
        
        // Hash to select Fast Path
        size_t fp_idx = hash(pkt.tuple) % num_fps_;
        
        // Push to FP's queue
        fps_[fp_idx]->queue().push(pkt);
    }
}
```

#### Step 3: Fast Path Thread

```cpp
void FastPath::run() {
    while (running_) {
        // Pop from my input queue
        auto pkt = input_queue_.pop();
        
        // Look up flow (each FP has its own flow table)
        Flow& flow = flows_[pkt.tuple];
        
        // Classify (SNI extraction)
        classifyFlow(pkt, flow);
        
        // Check rules
        if (rules_->isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni)) {
            stats_->dropped++;
        } else {
            // Forward: push to output queue
            output_queue_->push(pkt);
        }
    }
}
```

#### Step 4: Output Writer Thread

```cpp
void outputThread() {
    while (running_ || output_queue_.size() > 0) {
        auto pkt = output_queue_.pop();
        
        // Write to output file
        output_file.write(packet_header);
        output_file.write(pkt.data);
    }
}
```

### Thread-Safe Queue

The magic that makes multi-threading work:

```cpp
template<typename T>
class TSQueue {
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    
    void push(T item) {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(item);
        not_empty_.notify_one();  // Wake up waiting consumer
    }
    
    T pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [&]{ return !queue_.empty(); });
        T item = queue_.front();
        queue_.pop();
        return item;
    }
};
```

**How it works:**
- `push()`: Producer adds item, signals waiting consumers
- `pop()`: Consumer waits until item available, then takes it
- `mutex`: Only one thread can access at a time
- `condition_variable`: Efficient waiting (no busy-loop)

---

## 7. Deep Dive: Each Component

### pcap_reader.h / pcap_reader.cpp

**Purpose:** Read network captures saved by Wireshark

**Key structures:**
```cpp
struct PcapGlobalHeader {
    uint32_t magic_number;   // 0xa1b2c3d4 identifies PCAP
    uint16_t version_major;  // Usually 2
    uint16_t version_minor;  // Usually 4
    uint32_t snaplen;        // Max packet size captured
    uint32_t network;        // 1 = Ethernet
};

struct PcapPacketHeader {
    uint32_t ts_sec;         // Timestamp (seconds)
    uint32_t ts_usec;        // Timestamp (microseconds)
    uint32_t incl_len;       // Bytes saved in file
    uint32_t orig_len;       // Original packet size
};
```

**Key functions:**
- `open(filename)`: Open PCAP, validate header
- `readNextPacket(raw)`: Read next packet into buffer
- `close()`: Clean up

### packet_parser.h / packet_parser.cpp

**Purpose:** Extract protocol fields from raw bytes

**Key function:**
```cpp
bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    parseEthernet(...);  // Extract MACs, EtherType
    parseIPv4(...);      // Extract IPs, protocol, TTL
    parseTCP(...);       // Extract ports, flags, seq numbers
    // OR
    parseUDP(...);       // Extract ports
}
```

**Important concepts:**

*Network Byte Order:* Network protocols use big-endian (most significant byte first). Your computer might use little-endian. We use `ntohs()` and `ntohl()` to convert:
```cpp
// ntohs = Network TO Host Short (16-bit)
uint16_t port = ntohs(*(uint16_t*)(data + offset));

// ntohl = Network TO Host Long (32-bit)
uint32_t seq = ntohl(*(uint32_t*)(data + offset));
```

### sni_extractor.h / sni_extractor.cpp

**Purpose:** Extract domain names from TLS and HTTP

**For TLS (HTTPS):**
```cpp
std::optional<std::string> SNIExtractor::extract(
    const uint8_t* payload, 
    size_t length
) {
    // 1. Verify TLS record header
    // 2. Verify Client Hello handshake
    // 3. Skip to extensions
    // 4. Find SNI extension (type 0x0000)
    // 5. Extract hostname string
}
```

**For HTTP:**
```cpp
std::optional<std::string> HTTPHostExtractor::extract(
    const uint8_t* payload,
    size_t length
) {
    // 1. Verify HTTP request (GET, POST, etc.)
    // 2. Search for "Host: " header
    // 3. Extract value until newline
}
```

### types.h / types.cpp

**Purpose:** Define data structures used throughout

**FiveTuple:**
```cpp
struct FiveTuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    
    bool operator==(const FiveTuple& other) const;
};
```

**AppType:**
```cpp
enum class AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    GOOGLE,
    YOUTUBE,
    FACEBOOK,
    // ... more apps
};
```

**sniToAppType function:**
```cpp
AppType sniToAppType(const std::string& sni) {
    if (sni.find("youtube") != std::string::npos) 
        return AppType::YOUTUBE;
    if (sni.find("facebook") != std::string::npos) 
        return AppType::FACEBOOK;
    // ... more patterns
}
```

---

## 8. How SNI Extraction Works

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, everything is       │
     │       encrypted - we can't see it)      │
```

**We can only extract SNI from the Client Hello!**

### TLS Client Hello Structure

```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301 (TLS 1.0)
Bytes 3-4:  Record Length

-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length

-- Client Hello Body --
Bytes 9-10:  Client Version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID Length (N)
Bytes 44 to 44+N: Session ID
... Cipher Suites ...
... Compression Methods ...

-- Extensions --
Bytes X-X+1: Extensions Length
For each extension:
    Bytes: Extension Type (2)
    Bytes: Extension Length (2)
    Bytes: Extension Data

-- SNI Extension (Type 0x0000) --
Extension Type: 0x0000
Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (hostname)
  SNI Length: K
  SNI Value: "www.youtube.com" ← THE GOAL!
```

### Our Extraction Code (Simplified)

```cpp
std::optional<std::string> SNIExtractor::extract(
    const uint8_t* payload, size_t length
) {
    // Check TLS record header
    if (payload[0] != 0x16) return std::nullopt;  // Not handshake
    if (payload[5] != 0x01) return std::nullopt;  // Not Client Hello
    
    size_t offset = 43;  // Skip to session ID
    
    // Skip Session ID
    uint8_t session_len = payload[offset];
    offset += 1 + session_len;
    
    // Skip Cipher Suites
    uint16_t cipher_len = readUint16BE(payload + offset);
    offset += 2 + cipher_len;
    
    // Skip Compression Methods
    uint8_t comp_len = payload[offset];
    offset += 1 + comp_len;
    
    // Read Extensions Length
    uint16_t ext_len = readUint16BE(payload + offset);
    offset += 2;
    
    // Search for SNI extension
    size_t ext_end = offset + ext_len;
    while (offset + 4 <= ext_end) {
        uint16_t ext_type = readUint16BE(payload + offset);
        uint16_t ext_data_len = readUint16BE(payload + offset + 2);
        offset += 4;
        
        if (ext_type == 0x0000) {  // SNI!
            // Parse SNI structure
            uint16_t sni_len = readUint16BE(payload + offset + 3);
            return std::string(
                (char*)(payload + offset + 5), 
                sni_len
            );
        }
        
        offset += ext_data_len;
    }
    
    return std::nullopt;  // SNI not found
}
```

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `192.168.1.50` | All traffic from this source |
| App | `YouTube` | All YouTube connections |
| Domain | `tiktok` | Any SNI containing "tiktok" |

### The Blocking Flow

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?  │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is app type in blocked list?   │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does SNI match blocked domain? │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
            FORWARD
```

### Flow-Based Blocking

**Important:** We block at the *flow* level, not packet level.

```
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD  
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com
                           → App: YOUTUBE (blocked!)
                           → Mark flow as BLOCKED
                           → DROP this packet
  Packet 5 (Data)          → Flow is BLOCKED → DROP
  Packet 6 (Data)          → Flow is BLOCKED → DROP
  ...all subsequent packets → DROP
```

**Why this approach?**
- We can't identify the app until we see the Client Hello
- Once identified, we block all future packets of that flow
- The connection will fail/timeout on the client

---

## 10. Building and Running

### Prerequisites

- **macOS / Linux** with a C++17 compliant compiler (`clang++` or `g++`)
- **GNU Make** (3.81+) or **CMake** (3.16+)
- `pthread` support
- No external third-party library dependencies required!

### Build Commands (Makefile)

A standardized `Makefile` is provided in the project root:

```bash
# 1. Build the production modular DPI engine
make

# 2. Build with AddressSanitizer & Debug symbols
make asan

# 3. Build and execute the 32-suite automated test runner
make test

# 4. Build and run the test runner with AddressSanitizer
make test_asan

# 5. Clean build artifacts
make clean
```

### Build Commands (CMake)

Alternatively, using CMake:

```bash
mkdir -p build && cd build
cmake ..
make -j4
./dpi_engine ../test_dpi.pcap /tmp/output.pcap
ctest --output-on-failure
```

### Running the Engine

**Basic usage:**
```bash
./bin/dpi_engine test_dpi.pcap output.pcap
```

**With multi-dimensional filtering rules:**
```bash
./bin/dpi_engine test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-ip 192.168.1.50 \
    --block-domain *.tiktok.com \
    --block-port 80
```

**Configuring Load Balancers and Fast Path worker threads:**
```bash
./bin/dpi_engine test_dpi.pcap output.pcap --lbs 2 --fps 2
# Spawns 2 Load Balancers × 2 Fast Path workers per LB = 4 concurrent Fast Path workers
```

**Network Flow Intelligence & Export (Phase 3.0):**
```bash
# Export flow records to JSON & CSV and print detailed flow intelligence report
./bin/dpi_engine test_dpi.pcap output.pcap \
    --export-flows flows.json \
    --export-csv flows.csv \
    --flow-stats
```

**Behavioral Network Detection (Phase 3.1):**
```bash
# Run behavioral detection algorithms on extracted flows and output summary report
./bin/dpi_engine test_dpi.pcap output.pcap \
    --detect \
    --export-detections detections.json \
    --export-detections-csv detections.csv \
    --detection-stats

# Fine-tune active detectors
./bin/dpi_engine test_dpi.pcap output.pcap \
    --detect \
    --disable-detector dns_anomaly_detector \
    --enable-detector port_scan_detector
```

**Generating Synthetic Test Data:**
```bash
python3 generate_test_pcap.py
# Generates test_dpi.pcap with diverse protocol traffic
```

---

## 11. Understanding the Output

### Sample Output (Phase 2 Stabilized Modular Engine)

```
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v1.0                            ║
║               Deep Packet Inspection System                   ║
╠══════════════════════════════════════════════════════════════╣
║ Configuration:                                                ║
║   Load Balancers:      2                                       ║
║   FPs per LB:          2                                       ║
║   Total FP threads:    4                                       ║
╚══════════════════════════════════════════════════════════════╝
[FPManager] Created 4 fast path processors
[LBManager] Created 2 load balancers, 2 FPs each (total FPs: 4)
[DPIEngine] Initialized successfully
[RuleManager] Blocked IP: 192.168.1.50
[RuleManager] Blocked app: YouTube

[DPIEngine] Processing: test_dpi.pcap
[DPIEngine] Output to:  /tmp/test_out.pcap

[FP0] Started
[FP1] Started
[FP2] Started
[FP3] Started
[LB0] Started (serving FP0-FP1)
[LB1] Started (serving FP2-FP3)
[DPIEngine] All threads started
Opened PCAP file: test_dpi.pcap
[Reader] Starting packet processing...
[FP0] BLOCKED packet: App YouTube
[FP3] BLOCKED packet: IP 192.168.1.50
[Reader] Finished reading 77 packets
[FP0] BLOCKED packet: IP 192.168.1.50
[FP1] BLOCKED packet: IP 192.168.1.50
[FP2] BLOCKED packet: IP 192.168.1.50
[FP1] BLOCKED packet: IP 192.168.1.50
[LB0] Stopped
[LB1] Stopped
[FP0] Stopped (processed 26 packets)
[FP1] Stopped (processed 17 packets)
[FP2] Stopped (processed 21 packets)
[FP3] Stopped (processed 13 packets)
[DPIEngine] All threads stopped

╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE STATISTICS                      ║
╠══════════════════════════════════════════════════════════════╣
║ PACKET STATISTICS                                             ║
║   Total Packets:                77                        ║
║   Total Bytes:                5738                        ║
║   TCP Packets:                  73                        ║
║   UDP Packets:                   4                        ║
╠══════════════════════════════════════════════════════════════╣
║ FILTERING STATISTICS                                          ║
║   Forwarded:                    71                        ║
║   Dropped/Blocked:               6                        ║
║   Drop Rate:                 7.79%                        ║
╠══════════════════════════════════════════════════════════════╣
║ LOAD BALANCER STATISTICS                                      ║
║   LB Received:                  77                        ║
║   LB Dispatched:                77                        ║
╠══════════════════════════════════════════════════════════════╣
║ FAST PATH STATISTICS                                          ║
║   FP Processed:                 77                        ║
║   FP Forwarded:                 71                        ║
║   FP Dropped:                    6                        ║
║   Active Connections:           27                        ║
╠══════════════════════════════════════════════════════════════╣
║ BLOCKING RULES                                                ║
║   Blocked IPs:                   1                        ║
║   Blocked Apps:                  1                        ║
║   Blocked Domains:               0                        ║
║   Blocked Ports:                 0                        ║
╚══════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════╗
║                 APPLICATION CLASSIFICATION REPORT             ║
╠══════════════════════════════════════════════════════════════╣
║ Total Connections:            27                           ║
║ Classified:                   22 (81.5%)                  ║
║ Unidentified:                  5 (18.5%)                  ║
╠══════════════════════════════════════════════════════════════╣
║                    APPLICATION DISTRIBUTION                   ║
╠══════════════════════════════════════════════════════════════╣
║ Unknown               5  18.5% ###                    ║
║ DNS                   4  14.8% ##                     ║
║ HTTP                  2   7.4% #                      ║
║ Netflix               1   3.7%                        ║
║ Zoom                  1   3.7%                        ║
║ TikTok                1   3.7%                        ║
║ Instagram             1   3.7%                        ║
║ Discord               1   3.7%                        ║
║ Twitter/X             1   3.7%                        ║
║ Amazon                1   3.7%                        ║
║ Microsoft             1   3.7%                        ║
║ Google                1   3.7%                        ║
║ YouTube               1   3.7%                        ║
║ GitHub                1   3.7%                        ║
║ Telegram              1   3.7%                        ║
║ Spotify               1   3.7%                        ║
║ Facebook              1   3.7%                        ║
║ Apple                 1   3.7%                        ║
║ Cloudflare            1   3.7%                        ║
╚══════════════════════════════════════════════════════════════╝
```

### Key Architectural Fixes & Verifications

1. **Deterministic Load Balancing (Zero Starvation):**
   - The original architecture suffered from a downstream modulo collapse (`hash % 2` at both tiers), starving FP1 and FP2 (0 packets).
   - The modular engine implements global symmetrical flow assignment `global_fp = hash % total_fps`, ensuring even traffic spread (26, 17, 21, 13 packets across all 4 workers) with 100% flow affinity.
2. **Domain Boundary Precision (Zero Substring Collisions):**
   - Naive `find()` checks caused `netflix.com` and `microsoft.com` to misclassify as `Twitter/X` (`x.com`, `t.co`).
   - The modular engine enforces exact hostname and valid dot-delimited subdomain suffix matching (`domainMatchesPattern`).
3. **Safe Memory & Parsing:**
   - Byte-by-byte safe integer reading eliminates unaligned memory access crashes on ARM64.
   - QUIC extraction underflow vulnerabilities and malformed DNS label overreads are strictly guarded.
4. **Packet Reordering Output Buffer:**
   - Output thread preserves exact input PCAP capture order across multi-threaded workers using monotonic sequence tracking.
5. **True $O(1)$ LRU Connection Tracking:**
   - Combines a hash map with a bidirectional linked list (`std::list::splice`) for true constant-time LRU updates and evictions.

---

## 12. Network Flow Intelligence & Feature Extraction (Phase 3.0)

Phase 3.0 evolves the DPI packet analyzer into a **Flow-Aware Network Intelligence Engine**. Rather than viewing packets in isolation, the engine constructs bidirectional flow records, computes statistical feature distributions, tracks flow lifecycles, and exports rich datasets for security analytics and future AI/ML models.

### Architectural Principles

```
                  Raw Network Packets
                          │
                          ▼
            ┌───────────────────────────┐
            │   FiveTuple Canonicalizer │
            │  (Symmetrical 5-Tuple)    │
            └─────────────┬─────────────┘
                          │
                          ▼
            ┌───────────────────────────┐
            │      Per-Worker Flow      │
            │     Lifecycle Manager     │
            │  (O(1) LRU & Idle Timer)  │
            └─────────────┬─────────────┘
                          │
        ┌─────────────────┴─────────────────┐
        ▼                                   ▼
┌───────────────────────────┐   ┌───────────────────────────┐
│     Forward Telemetry     │   │     Reverse Telemetry     │
│ (Client → Server Origin)  │   │  (Server → Client Reply)  │
│ - Packet / Byte Counts    │   │ - Packet / Byte Counts    │
│ - Welford Pkt Size Stats  │   │ - Welford Pkt Size Stats  │
│ - Welford IAT (μs) Stats  │   │ - Welford IAT (μs) Stats  │
│ - SYN, ACK, PSH Flags     │   │ - SYN, ACK, FIN, RST Flags│
└───────────────────────────┘   └───────────────────────────┘
        │                                   │
        └─────────────────┬─────────────────┘
                          │
                          ▼
            ┌───────────────────────────┐
            │  Comprehensive FlowRecord │
            │ - Duration & Rates        │
            │ - Byte/Pkt Asymmetry      │
            │ - L7 Metadata (SNI/DNS)   │
            │ - Enforcement Status      │
            └─────────────┬─────────────┘
                          │
             ┌────────────┴────────────┐
             ▼                         ▼
      JSON Export               CSV Data Matrix
   (Structured Schema)       (ML Feature Extraction)
```

### 1. Bidirectional Flow Tracking & Directionality
- **Strict Origin Accounting:** The very first observed packet strictly defines the `FORWARD` direction ($initial\_tuple.src \to initial\_tuple.dst$). All reverse packets from the responding endpoint are mapped to `REVERSE`.
- **Symmetrical Flow Hash & Table Indexing:** Flows are indexed symmetrically using canonical tuple representations (`tuple.toCanonical()`), guaranteeing bidirectional packet pairing regardless of arrival order or thread scheduling.

### 2. Numerically Stable Statistical Feature Extraction (Welford's Algorithm)
Computing packet size and inter-arrival time (IAT) variance dynamically across gigabytes of streaming data can cause catastrophic cancellation or excessive memory overhead with naive algorithms. We implement **Welford's One-Pass Recurrence**:
- Sample variance $s^2 = M_2 / (n - 1)$ where $M_{2,n} = M_{2,n-1} + (x_n - \bar{x}_{n-1})(x_n - \bar{x}_n)$.
- Runs in strictly $O(1)$ constant time and $O(1)$ constant space per flow.
- Tracks:
  - **Packet Length Distribution:** Min, Max, Sum, Mean, Sample Variance ($\sigma^2$), Sample StdDev ($\sigma$) for Forward, Reverse, and Combined traffic.
  - **Inter-Arrival Time (IAT):** Microsecond-precision IAT Mean and Variance for Forward, Reverse, and Combined traffic.
  - **Traffic Volume & Rates:** Duration (seconds, microseconds), Packets per Second, Bytes per Second.
  - **Asymmetry Ratios:** Forward/Reverse packet asymmetry and byte asymmetry.

### 3. Flow Lifecycle Management
- **States:** `NEW`, `ESTABLISHED`, `FIN_WAIT`, `CLOSED`, `TIMED_OUT`.
- **Termination Reasons:** `ACTIVE`, `NATURAL_FIN_RST`, `IDLE_TIMEOUT`, `ACTIVE_TIMEOUT`, `CAPACITY_EVICTION`, `END_OF_FILE`.
- **Capacity Management:** Symmetrical hash map paired with an embedded linked list (`std::list::splice`) ensures deterministic $O(1)$ eviction under memory pressure.

### 4. Structured Export Formats
- **JSON Export (`--export-flows <file.json>`):** Hierarchical JSON array containing complete directional telemetry, statistical matrices, and application metadata.
- **CSV Export (`--export-csv <file.csv>`):** Flat, feature-rich tabular matrix formatted specifically for model training (scikit-learn, XGBoost, PyTorch) with 32 statistical columns per row.
- **Flow Intelligence Report (`--flow-stats`):** Terminal dashboard summarizing tracked flows, packet volumes, protocol distributions, and lifecycle terminations.

---

## 13. Behavioral Network Detection Engine (Phase 3.1)

Phase 3.1 introduces a **Deterministic, Evidence-Based Behavioral Network Detection Subsystem** that operates on the bidirectional flow records produced by the Phase 3.0 Flow Intelligence engine.

Rather than relying on brittle signature matching or uncalibrated machine learning models, Phase 3.1 implements rigorous heuristic, statistical, and state-machine algorithms to detect anomalies, network reconnaissance, command-and-control beacons, and protocol deviations.

### Architectural Principles

```
                  Finalized FlowRecords (Phase 3.0)
                                 │
                                 ▼
                 ┌───────────────────────────────┐
                 │       DetectionEngine         │
                 │  - Configuration & Thresholds │
                 │  - Detector Registry          │
                 └───────────────┬───────────────┘
                                 │ Dispatches Flows
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ PortScanDetector │    │  BeaconDetector  │    │TCPAnomalyDetector│
│ (Vertical/Sweep) │    │  (Periodic CV)   │    │ (SYN/RST Floods) │
└────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘
        │                        │                        │
        └────────────────────────┼────────────────────────┘
                                 │ Emits Candidate Events
                                 ▼
                 ┌───────────────────────────────┐
                 │    Windowed Deduplication     │
                 │ (Suppresses Duplicate Events) │
                 └───────────────┬───────────────┘
                                 │ Final Validated Events
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
 ┌──────────────┐         ┌──────────────┐         ┌──────────────┐
 │ JSON Export  │         │  CSV Export  │         │ Terminal     │
 │ (Schema v1.0)│         │ (21 Columns) │         │ Report Table │
 └──────────────┘         └──────────────┘         └──────────────┘
```

1. **Decoupled Post-Processing:** Detections execute after capture completion over finalized flows. This guarantees **zero worker contention** and preserves maximum packet ingestion throughput during capture.
2. **Deterministic Evidence Model:** Every event produces structured, inspectable key-value evidence, human-readable explanations, documented limitations, and remediation guidance.
3. **No Automatic Blocking:** Detections are informational and analytical. The system alerts and exports findings without modifying firewall state or dropping traffic.

---

### The 7 Behavioral Detectors

| Detector | Category | Primary Target & Detection Logic | Default Severity |
| :--- | :--- | :--- | :--- |
| `port_scan_detector` | `NETWORK_RECONNAISSANCE` | **Vertical Scan:** Single source probes $\ge 15$ distinct ports on one destination.<br>**Horizontal Sweep:** Single source probes $\ge 10$ distinct hosts on the same service port.<br>*Severity escalates to HIGH if unanswered SYN ratio $\ge 80\%$.* | `MEDIUM` / `HIGH` |
| `connection_burst_detector` | `CONNECTION_ANOMALY` | Detects sudden flow initiation spikes within a sliding window ($\ge 25$ flows in $\le 2.0$ seconds). | `LOW` / `MEDIUM` |
| `repeated_attempts_detector` | `SUSPICIOUS_CONNECTION_ATTEMPT` | Repeated connection attempts ($\ge 5$ attempts) to the same target service with an incomplete handshake ratio $\ge 70\%$. | `MEDIUM` |
| `dns_anomaly_detector` | `SUSPICIOUS_DNS` | **Burst / Domain Flux:** $\ge 20$ queries or $\ge 15$ distinct domains in $\le 5$s.<br>**DNS Tunneling:** Query name length $\ge 50$ characters or subdomain depth $\ge 5$ labels. | `MEDIUM` / `HIGH` |
| `outbound_anomaly_detector` | `UNUSUAL_TRAFFIC_VOLUME` | Outbound byte transfer $\ge 5\text{ MB}$ with extreme byte asymmetry ($\text{FwdBytes} / \text{RevBytes} \ge 10.0$). Severity escalates on non-standard ports. | `LOW` / `MEDIUM` |
| `beacon_detector` | `COMMAND_AND_CONTROL` | Statistical periodicity analysis: evaluates $\ge 5$ flows between endpoint pairs. Computes inter-arrival time standard deviation ($\sigma$) and mean ($\mu$). Flags periodic beaconing if Coefficient of Variation $CV = \sigma / \mu \le 0.20$. | `HIGH` |
| `tcp_anomaly_detector` | `PROTOCOL_ANOMALY` | **SYN Flood:** $\ge 10$ unacknowledged SYN flows with incomplete handshakes.<br>**RST Flood / Teardown Anomaly:** Total flows $\ge 10$ with RST packet ratio $\ge 50\%$. | `MEDIUM` / `HIGH` |

---

### Beaconing Periodicity Mathematics

To identify automated Command and Control (C2) callback beacons invariant to polling frequency, the engine evaluates the **Coefficient of Variation ($CV$)** of inter-arrival times ($\Delta t$):

$$\mu = \frac{1}{N} \sum_{i=1}^N \Delta t_i, \quad \sigma = \sqrt{\frac{1}{N-1} \sum_{i=1}^N (\Delta t_i - \mu)^2}, \quad CV = \frac{\sigma}{\mu}$$

- **Periodic C2 Traffic:** $CV \le 0.20$ (low jitter, highly regular heartbeat).
- **Irregular / Benign User Traffic:** $CV > 0.35$ (bursty, high jitter; rejected as non-beaconing).

---

### Detection Schema & Exports

#### 1. JSON Export Schema (Version 1.0)
```json
[
  {
    "schema_version": "1.0",
    "event_id": "det-192.168.1.50-tcp_anomaly_detector-1700000000000000",
    "timestamp_first_us": 1700000000000000,
    "timestamp_last_us": 1700000005000000,
    "detector_name": "tcp_anomaly_detector",
    "category": "PROTOCOL_ANOMALY",
    "severity": "MEDIUM",
    "source_ip": "192.168.1.50",
    "destination_ip": "203.0.113.10",
    "destination_port": 80,
    "protocol": 6,
    "flow_count": 12,
    "packet_count": 12,
    "byte_count": 720,
    "evidence": {
      "syn_heavy_flows": "12",
      "syn_ratio": "1.00",
      "total_flows": "12"
    },
    "explanation": "Host 192.168.1.50 initiated 12 SYN-heavy flows with 0 acknowledged responses.",
    "limitations": "May indicate firewall silent drops or network reachability issues.",
    "recommended_actions": "Verify route to destination and check firewall state tables."
  }
]
```

#### 2. CSV Export Schema (21 Columns)
```csv
event_id,timestamp_first_us,timestamp_last_us,detector_name,category,severity,source_ip,destination_ip,destination_port,protocol,flow_count,packet_count,byte_count,evidence,explanation,limitations,recommended_actions
```

---

### Command-Line Usage

```bash
# Basic detection run with terminal report
./bin/dpi_engine capture.pcap /tmp/filtered.pcap --detect --detection-stats

# Export structured detections to JSON and CSV
./bin/dpi_engine capture.pcap /tmp/filtered.pcap \
    --detect \
    --export-detections /tmp/detections.json \
    --export-detections-csv /tmp/detections.csv

# Enable / Disable specific detector modules
./bin/dpi_engine capture.pcap /tmp/filtered.pcap \
    --detect \
    --disable-detector dns_anomaly_detector \
    --enable-detector beacon_detector
```

---

## 14. TCP Stream Reassembly & Advanced Protocol Intelligence (Phase 3.2)

Phase 3.2 enhances the DPI engine with deterministic, bounded TCP stream reassembly and advanced application-layer protocol parsing. Unlike naive packet-at-a-time inspectors that fail when application messages span across multiple TCP segments or arrive out-of-order, this subsystem reconstructs clean, ordered byte-streams directly within each Fast Path worker thread.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        FastPathProcessor (Thread-Local)                │
│                                                                        │
│   TCP Packets       ┌────────────────────────┐                         │
│  ─────────────►     │   TCPStreamManager     │                         │
│                     │                        │                         │
│                     │  ┌──────────────────┐  │                         │
│                     │  │ TCPConnection-   │  │                         │
│                     │  │ Stream           │  │                         │
│                     │  │  ├─ TCPHalfStream│  │                         │
│                     │  │  └─ TCPHalfStream│  │                         │
│                     │  └────────┬─────────┘  │                         │
│                     └───────────┼────────────┘                         │
│                                 ▼ Reassembled Linear Bytes             │
│                     ┌────────────────────────┐                         │
│                     │ Layer 7 Stream Parsers │                         │
│                     │  ├─ HTTPStreamParser   │                         │
│                     │  ├─ TLSStreamParser    │                         │
│                     │  └─ DNSParser (TCP)    │                         │
│                     └────────────────────────┘                         │
│                                                                        │
│   UDP DNS           ┌────────────────────────┐                         │
│  ─────────────►     │    DNSCorrelator       │                         │
│                     │ (TxID, Latency, RRs)   │                         │
│                     └────────────────────────┘                         │
└────────────────────────────────────────────────────────────────────────┘
```

### 14.1 Key Architecture & Design Decisions

1. **Zero Contention Thread-Local Execution:**  
   Because all packets belonging to any canonical 5-tuple hash to the exact same Fast Path processor thread via symmetrical load balancing, stream reconstruction runs strictly thread-locally. No global locks, mutexes, or synchronization overheads are incurred during reassembly.

2. **RFC 793 / RFC 1323 Sequence Number Comparison:**  
   TCP sequence numbers are 32-bit unsigned integers that wrap around at $2^{32}-1$. Standard integer comparison (`<`, `>`) breaks near the $0\text{xFFFFFFFF} \to 0\text{x00000000}$ boundary. We implement standard RFC modular sequence arithmetic:
   $$\text{seq\_lt}(s_1, s_2) \iff \text{int32\_t}(s_1 - s_2) < 0$$
   This safely handles full 32-bit boundary wraparounds and sequence space distance calculations.

3. **BSD-Style First-Come Overlap Policy with Conflict Detection:**  
   When an incoming segment overlaps with previously received byte ranges:
   - **Identical bytes:** The redundant prefix is trimmed, and new payload bytes are appended.
   - **Conflicting bytes:** If retransmitted bytes differ from previously seen bytes at the same sequence index (a common evasion technique), the reassembler favors the original bytes (BSD First-Come policy) and increments `conflict_count` in stream telemetry.
   - **Pure retransmissions:** Fully redundant segments are dropped with `retrans_count` incremented.

4. **Out-of-Order Queue & Gap Detection:**  
   Segments arriving ahead of the expected sequence number are buffered in an out-of-order segment queue sorted by sequence number. If a missing segment creates a hole, a gap is flagged (`gap_count` incremented), preventing head-of-line corruption until the missing sequence arrives.

5. **Bounded Resource Limits:**  
   - Per-stream buffer maximum: default 1 MB per direction (`max_stream_buffer_bytes`).
   - Global worker stream capacity: default 16,384 streams with LRU eviction.
   - Total engine memory ceiling: configurable via `--stream-max-mem <MB>` (default 64 MB).
   - Inactive stream timeout: expired streams are pruned automatically to prevent memory leaks from abandoned connections.

---

### 14.2 Protocol Intelligence Parsers

#### HTTP/1.x Stream Parser (`HTTPStreamParser`)
- **Pipelined Transactions:** Decodes multiple sequential requests and responses on persistent HTTP/1.1 connections.
- **Request / Response Dissection:** Extracts methods (`GET`, `POST`, `PUT`, `DELETE`), target URIs, status codes (`200`, `404`, etc.), reason phrases, and standard headers.
- **Chunked Transfer-Encoding:** Incrementally de-chunks hexadecimal length-prefixed bodies until terminal `0\r\n\r\n`.
- **Resource Protection:** Enforces maximum header size (16 KB) and maximum body size (1 MB) to prevent unbounded buffering.

#### TLS Stream Parser (`TLSStreamParser`)
- **Fragmented Handshake Reassembly:** Handles `ClientHello` messages split across arbitrary TCP segment boundaries.
- **Metadata Extraction:** Extracts Server Name Indication (SNI), Application-Layer Protocol Negotiation (ALPN: `h2`, `http/1.1`), TLS version (`supported_versions` extension), and cipher suites.
- **Encrypted Application Data Demarcation:** Identifies transition to TLS Record Type `0x17` (Application Data), tracking encrypted record count and encrypted payload bytes.

#### DNS Intelligence & Correlator (`DNSParser` & `DNSCorrelator`)
- **Dual Transport:** Transparently decodes UDP DNS datagrams and TCP DNS (2-byte length-prefixed RFC 1035 streams).
- **Compression Pointer Loop Safety:** Decompresses DNS domain names using visited-pointer set tracking and depth limit (max 16 jumps), preventing infinite compression loops.
- **Resource Record Extraction:** Parses Answer Resource Records (A, AAAA, CNAME, PTR, TXT, MX) into structured records.
- **Transaction Correlation & Latency:** Correlates queries and responses by Transaction ID and 5-tuple, measuring transaction latency in microseconds.
- **Malware & DGA Detection:** Tracks NXDOMAIN, SERVFAIL, and REFUSED error bursts, feeding behavioral detection for Domain Generation Algorithm (DGA) anomalies.

---

### 14.3 CLI Options & Configuration

| Flag | Parameter | Description |
|------|-----------|-------------|
| `--stream-reassembly` | None | Enable TCP stream reassembly (default) |
| `--no-stream-reassembly` | None | Disable TCP stream reassembly |
| `--stream-stats` | None | Output formatted ASCII stream reassembly summary report |
| `--export-streams <file>` | Path | Export reconstructed stream summaries to JSON |
| `--export-streams-csv <file>` | Path | Export reconstructed stream summaries to CSV |
| `--stream-max-mem <mb>` | Integer | Set maximum reassembly memory limit in MB (default: 64) |

#### Example Invocations

```bash
# Process PCAP with stream reassembly and display stream summary table
./bin/dpi_engine capture.pcap /tmp/filtered.pcap --stream-stats

# Full pipeline: Flow intelligence, behavioral detection, and stream reconstruction exports
./bin/dpi_engine capture.pcap /tmp/filtered.pcap \
    --flow-stats --export-flows /tmp/flows.json \
    --detect --detection-stats --export-detections /tmp/detections.json \
    --stream-stats --export-streams /tmp/streams.json --export-streams-csv /tmp/streams.csv
```

---

### 14.4 Stream Export Schemas

#### Stream JSON Schema (`streams.json`)

```json
[
  {
    "stream_id": 1,
    "tuple": "192.168.1.100:54321 -> 93.184.216.34:80 (TCP)",
    "state": "CLOSED",
    "fwd": {
      "bytes_reassembled": 185,
      "segments_received": 3,
      "out_of_order_count": 0,
      "retrans_count": 0,
      "overlap_count": 0,
      "conflict_count": 0,
      "gap_count": 0,
      "is_complete": true
    },
    "rev": {
      "bytes_reassembled": 450,
      "segments_received": 4,
      "out_of_order_count": 0,
      "retrans_count": 0,
      "overlap_count": 0,
      "conflict_count": 0,
      "gap_count": 0,
      "is_complete": true
    },
    "http_messages_count": 2,
    "http_messages": [
      {
        "is_request": true,
        "method": "GET",
        "uri": "/index.html",
        "version": "HTTP/1.1",
        "host": "example.com",
        "user_agent": "Mozilla/5.0",
        "content_length": 0,
        "is_complete": true
      },
      {
        "is_request": false,
        "status_code": 200,
        "reason_phrase": "OK",
        "version": "HTTP/1.1",
        "content_length": 1256,
        "is_complete": true
      }
    ],
    "tls": {
      "sni": "",
      "alpn": "",
      "supported_versions": [],
      "has_client_hello": false,
      "has_encrypted_data": false,
      "encrypted_records": 0,
      "encrypted_bytes": 0
    }
  }
]
```

#### Stream CSV Schema (`streams.csv`)

```csv
stream_id,tuple,state,fwd_bytes,rev_bytes,fwd_segments,rev_segments,fwd_ooo,rev_ooo,fwd_retrans,rev_retrans,fwd_overlaps,rev_overlaps,fwd_gaps,rev_gaps,http_count,tls_sni,tls_alpn,tls_encrypted_bytes
1,"192.168.1.100:54321 -> 93.184.216.34:80 (TCP)",CLOSED,185,450,3,4,0,0,0,0,0,0,0,0,2,"","",0
```

---

## 15. Security Incident Intelligence & Threat Correlation (Phase 3.3)

Phase 3.3 elevates the analyzer from isolated alert generation to an **evidence-based Security Incident Analysis Engine**. Individual behavioral alerts and enriched flow telemetry are correlated across network endpoints, temporal aggregation windows, Layer 7 protocol metrics, and multi-stage lifecycle progressions into structured, explainable security incidents.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        IncidentCorrelator Pipeline                     │
│                                                                        │
│   Behavioral Events     Enriched Flows        Reassembled Streams      │
│   (Phase 3.1)           (Phase 3.0)           (Phase 3.2)              │
│       │                      │                      │                  │
│       └──────────────┬───────┴──────────────────────┘                  │
│                      ▼                                                 │
│       ┌──────────────────────────────┐                                 │
│       │ Primary Endpoint Aggregation │ (Group by source host / client) │
│       └──────────────┬───────────────┘                                 │
│                      ▼                                                 │
│       ┌──────────────────────────────┐                                 │
│       │ Correlation Rules Engine     │                                 │
│       │  ├─ RuleReconnaissance       │ (Port scans, sweeps, RST ratio) │
│       │  ├─ RuleDNSSuspicious        │ (Tunneling, NXDOMAIN bursts)    │
│       │  ├─ RuleSuspiciousOutbound   │ (Beaconing, C2, rare ports)     │
│       │  ├─ RuleDataExfiltration     │ (Large egress, extreme asym)    │
│       │  ├─ RuleMultiStage           │ (Recon -> C2 -> Exfiltration)   │
│       │  └─ RuleTCPAnomalyCluster    │ (Handshake anomalies)           │
│       └──────────────┬───────────────┘                                 │
│                      ▼                                                 │
│       ┌──────────────────────────────┐                                 │
│       │ Transparent Evidence Scoring │ (Deduplicated flow weights)     │
│       │  & Severity / Confidence     │                                 │
│       └──────────────┬───────────────┘                                 │
│                      ▼                                                 │
│       ┌──────────────────────────────┐                                 │
│       │ Chronological Timeline Gen   │ (Deterministic microsecond sort)│
│       └──────────────┬───────────────┘                                 │
│                      ▼                                                 │
│       ┌──────────────────────────────┐                                 │
│       │ Deduplication & Window Merge │ (Merge within incident window)  │
│       └──────────────┬───────────────┘                                 │
│                      ▼                                                 │
│       ┌──────────────────────────────┐                                 │
│       │ SecurityIncident Outputs     │ (JSON v1.0, CSV, ASCII Report)  │
│       └──────────────────────────────┘                                 │
└────────────────────────────────────────────────────────────────────────┘
```

### 15.1 Incident Evidence Model & Schema

Each security incident is represented as a structured `SecurityIncident` containing:
- **Incident ID & Schema Version:** Stable identifier (e.g. `INC-0001`) with versioned schema (`1.0`).
- **Category:** One of `RECONNAISSANCE`, `DNS_SUSPICIOUS_ACTIVITY`, `SUSPICIOUS_OUTBOUND_COMMUNICATION`, `POTENTIAL_DATA_EXFILTRATION`, `MULTI_STAGE_ACTIVITY`, `TCP_ANOMALY_CLUSTER`, or `OTHER`.
- **Severity Level:** Deterministically mapped from correlation score: `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
- **Confidence Level & Explanation:** Separately distinguishes circumstantial evidence from rich, multi-flow corroborated evidence (`LOW`, `MEDIUM`, `HIGH`), accompanied by an auditable human-readable explanation.
- **Timing & Scope:** First seen microsecond timestamp, last seen timestamp, duration, primary endpoint IP, and related destination endpoints.
- **Correlated Identifiers:** Linked flow IDs and detection IDs.
- **Evidence Timeline:** Chronologically ordered array of microsecond-precision events (`DETECTION`, `FLOW_START`, `STAGE_TRANSITION`).
- **Investigative Guidance:** Actionable recommended investigation steps and explicit operational limitations.
- **Analytical Status:** `NEW`, `OBSERVED`, or `REVIEW_REQUIRED` (analytical only, no automated traffic blocking).

### 15.2 Correlation Rules

1. **Reconnaissance Correlation (`RuleReconnaissance`):**  
   Correlates horizontal IP sweeps, vertical port scans, repeated connection attempts, and SYN-heavy traffic patterns across multiple targets into a unified reconnaissance incident.
2. **DNS Suspicious Activity Correlation (`RuleDNSSuspicious`):**  
   Correlates long domain tunneling candidates, excessive lookup frequencies, high domain diversity, and NXDOMAIN error bursts. Explicitly avoids premature malware labelling.
3. **Suspicious Outbound Communication (`RuleSuspiciousOutbound`):**  
   Correlates periodic beacon-like polling (low jitter CV), destination consistency across multiple sessions, non-standard outbound ports, and TLS metadata (SNI, ALPN).
4. **Potential Data Exfiltration (`RuleDataExfiltration`):**  
   Correlates large outbound byte transfers with extreme directional asymmetry ($\ge 10.0$) and persistent outbound connections. Explicitly distinguishes observed egress volume from confirmed data loss.
5. **Multi-Stage Attack Progression (`RuleMultiStage`):**  
   Identifies temporal progression through distinct attack lifecycle stages:
   $$\text{Stage 1: Reconnaissance} \longrightarrow \text{Stage 2: Connection Surges} \longrightarrow \text{Stage 3: Suspicious DNS} \longrightarrow \text{Stage 4: C2 Beaconing} \longrightarrow \text{Stage 5: Data Transfer}$$
   Requires at least 2 distinct stages including post-access activity. Synthesizes constituent sub-incidents into a cohesive multi-stage sequence.
6. **TCP Anomaly Cluster (`RuleTCPAnomalyCluster`):**  
   Correlates isolated TCP handshake anomalies, SYN floods, and abnormal RST ratios across concurrent flows.

### 15.3 Evidence Scoring Methodology

Scoring is fully transparent and explainable:
$$\text{Score} = \sum_{d \in \text{Detections}} \text{Weight}(\text{severity}_d) \times \text{FlowUniqueness}(d) + \sum \text{FeatureBonuses}$$

- **Base Weights:** `CRITICAL` = 40.0, `HIGH` = 25.0, `MEDIUM` = 15.0, `LOW` = 8.0, `INFO` = 2.0.
- **Same-Flow Deduplication:** When multiple detection alerts stem from the exact same underlying flow, secondary alerts receive a 50% discount to prevent artificial score inflation from single connection anomalies.
- **Feature Bonuses:**
  * Multi-category diversity: +15.0
  * Multi-stage temporal sequence: +20.0
  * Extreme byte asymmetry ($\ge 10:1$): +10.0
  * Multi-destination fanout ($\ge 3$ endpoints): +10.0
  * Beacon consistency: +15.0
  * Large volume transfer: +15.0
- **Severity Mapping:** $\text{Score} \ge 80 \implies \text{CRITICAL}$, $\ge 50 \implies \text{HIGH}$, $\ge 25 \implies \text{MEDIUM}$, $< 25 \implies \text{LOW}$.

### 15.4 Severity vs. Confidence

| Dimension | Meaning | Evaluation Metric |
|---|---|---|
| **Severity** | Potential security impact | Numerical score based on indicator danger and magnitude |
| **Confidence** | Evidential certainty and breadth | Independent metric based on flow diversity ($\ge 3$ flows), category corroboration, and duration |

### 15.5 CLI Options & Configuration

| Flag | Parameter | Description |
|------|-----------|-------------|
| `--incidents` | None | Enable security incident correlation engine |
| `--incident-stats` | None | Print formatted ASCII Security Incident report |
| `--export-incidents <file>` | Path | Export correlated incidents to JSON v1.0 |
| `--export-incidents-csv <file>` | Path | Export correlated incidents to CSV |
| `--incident-window <seconds>` | Float | Set temporal aggregation window in seconds (default: 60) |
| `--incident-threshold <score>` | Float | Set minimum score threshold to promote to incident (default: 20) |
| `--enable-correlation-rule <r>` | String | Enable specific rule (`recon`, `dns`, `outbound`, `exfil`, `multistage`, `tcp`) |
| `--disable-correlation-rule <r>` | String | Disable specific rule |

#### Example Invocation

```bash
# Process PCAP with incident correlation and export all telemetry
./bin/dpi_engine capture.pcap /tmp/filtered.pcap \
    --flow-stats --export-flows /tmp/flows.json \
    --detect --detection-stats \
    --stream-stats --export-streams /tmp/streams.json \
    --incidents --incident-stats \
    --export-incidents /tmp/incidents.json \
    --export-incidents-csv /tmp/incidents.csv
```

---

## 16. Rule-Based Intrusion Detection & Signature Engine (Phase 3.4)

Phase 3.4 introduces a high-performance, deterministic, rule-based Signature Intrusion Detection Engine integrated directly alongside Behavioral Detection (Phase 3.1), TCP Stream Reassembly (Phase 3.2), and Threat Correlation (Phase 3.3).

The signature engine inspects network traffic across multiple OSI layers:
- **L3/L4 Network Metadata:** IP addresses, CIDR subnets, port ranges, protocols, TCP flags, packet sizes.
- **Flow Metadata:** Flow lifecycle state, total bytes, packet counts, duration, directional byte asymmetry.
- **L7 TCP Stream Payloads:** Full bidirectional reconstructed stream payloads (forward client-to-server and reverse server-to-client).
- **L7 Protocol Metadata:** Parsed HTTP/1.x requests and responses, TLS ClientHello handshake metadata, and DNS queries and responses.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SIGNATURE MATCHING ENGINE                       │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│   ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐   │
│   │ Network Criteria │   │  Flow Criteria   │   │  Stream Content  │   │
│   │ (IP/CIDR/Ports/  │   │ (State/Bytes/    │   │  (ASCII/Hex/     │   │
│   │  TCP Flags/Size) │   │  Packets/Dur)    │   │   Chained Dist)  │   │
│   └────────┬─────────┘   └────────┬─────────┘   └────────┬─────────┘   │
│            │                      │                      │             │
│            ▼                      ▼                      ▼             │
│   ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐   │
│   │  HTTP Criteria   │   │   TLS Criteria   │   │   DNS Criteria   │   │
│   │  (Method/Host/   │   │  (SNI/ALPN/Ver/  │   │  (Domain/Type/   │   │
│   │   URI/UA/Status) │   │   Cipher Suites) │   │   Entropy/RCode) │   │
│   └────────┬─────────┘   └────────┬─────────┘   └────────┬─────────┘   │
│            │                      │                      │             │
│            └──────────────────────┼──────────────────────┘             │
│                                   ▼                                    │
│                 ┌───────────────────────────────────┐                  │
│                 │      Rule Match Evaluator         │                  │
│                 │   (All criteria must satisfy)     │                  │
│                 └─────────────────┬─────────────────┘                  │
│                                   ▼                                    │
│                 ┌───────────────────────────────────┐                  │
│                 │ Deduplication & Bounds Guard      │                  │
│                 │ (1 match/rule/flow, max matches)  │                  │
│                 └─────────────────┬─────────────────┘                  │
│                                   ▼                                    │
│                 ┌───────────────────────────────────┐                  │
│                 │ SignatureEvent (Schema v1.0)      │                  │
│                 │ (JSON, CSV, Incident Timeline)    │                  │
│                 └───────────────────────────────────┘                  │
└────────────────────────────────────────────────────────────────────────┘
```

### 16.1 Signature Rule Schema (v1.0)

Rules are authored in JSON format (`.json`) and validated against strict schema rules upon loading:

```json
{
  "rules": [
    {
      "id": "SIG-WEB-SQLI-01",
      "name": "SQL Injection Attempt in HTTP Stream",
      "category": "INTRUSION_ATTEMPT",
      "severity": "HIGH",
      "enabled": true,
      "revision": 1,
      "description": "Detects classic SQL injection UNION SELECT patterns in inbound HTTP streams",
      "references": ["CVE-2023-XXXX", "CWE-89"],
      "network": {
        "protocol": "TCP",
        "direction": "FORWARD",
        "dst_ports": [80, 443, 8080]
      },
      "stream_content": [
        {
          "pattern": "union",
          "nocase": true,
          "offset": 0,
          "depth": 2048
        },
        {
          "pattern": "select",
          "nocase": true,
          "relative_distance": 1,
          "relative_within": 30
        }
      ],
      "http": {
        "method": "GET"
      }
    }
  ]
}
```

### 16.2 Supported Match Criteria

1. **Network Criteria (`network`):**
   - `src_ips`, `dst_ips`: Single IPv4 addresses or CIDR blocks (e.g. `["192.168.1.0/24", "10.0.0.1"]`).
   - `src_ports`, `dst_ports`: Specific ports or port ranges (e.g. `[80, 443, "8000-8080"]`).
   - `protocol`: `TCP`, `UDP`, or `ANY`.
   - `direction`: `FORWARD` (client $\to$ server), `REVERSE` (server $\to$ client), or `BIDIRECTIONAL`.
   - `tcp_flags_mask` & `tcp_flags_value`: Bitwise evaluation of TCP header flags.
   - `packet_size_min`, `packet_size_max`: Bounded packet size matching.

2. **Flow Criteria (`flow`):**
   - `flow_state`: Match on flow lifecycle state (`NEW`, `ESTABLISHED`, `CLOSED`, `RESET`, or `ANY`).
   - `min_bytes`, `max_bytes`: Total bidirectional byte thresholds.
   - `min_packets`, `max_packets`: Total bidirectional packet count thresholds.
   - `min_duration_sec`, `max_duration_sec`: Connection duration bounds in seconds.
   - `min_asymmetry_ratio`: Forward/reverse byte asymmetry threshold.

3. **Stream Content Criteria (`stream_content`):**
   - **Pattern Representation:** Plain ASCII strings or hexadecimal byte sequences enclosed in vertical bars (`|41 42 43|` or `hex: 41 42 43`).
   - **Case-Insensitivity (`nocase`):** Fast, branchless case-insensitive byte matching.
   - **Offset & Depth Bounds:** `offset` defines start search index; `depth` restricts search to $N$ bytes from offset.
   - **Chained Relative Matching:** `relative_distance` (search starts $D$ bytes after previous match) and `relative_within` (search must conclude within $W$ bytes after previous match).
   - **Negated Matching (`negated`):** Verifies that a required sequence is absent within the bounded inspection window.
   - **Stream Directionality:** Restricts pattern evaluation to `FORWARD`, `REVERSE`, or `BOTH` directions.

4. **HTTP Metadata Criteria (`http`):**
   - `method`: HTTP request method (e.g. `GET`, `POST`, `PUT`, `DELETE`).
   - `host`: Target host header with anchored subdomain wildcard matching (`*.internal.net`).
   - `uri`: Request URI path and query parameter substring matching.
   - `user_agent`: User-Agent header substring matching.
   - `status_code`: Exact integer response status code (e.g. `200`, `403`, `404`, `500`).
   - `headers`: Map of required header name/value substring conditions.

5. **TLS Handshake Criteria (`tls`):**
   - `sni`: Server Name Indication with anchored wildcard matching (`*.malware-c2.net`).
   - `alpn`: Application-Layer Protocol Negotiation string (`h2`, `http/1.1`).
   - `version`: TLS record/handshake version string (`TLS 1.2`, `TLS 1.3`).
   - `cipher_suites`: Specific TLS cipher suite hex IDs.

6. **DNS Intelligence Criteria (`dns`):**
   - `query_name`: Queried domain name with anchored wildcard matching.
   - `query_type`: Numeric DNS RR type code (e.g. `1` for A, `28` for AAAA, `16` for TXT).
   - `response_code`: DNS RCODE integer (e.g. `0` for NOERROR, `3` for NXDOMAIN).
   - `is_nxdomain`: Boolean flag specifically matching unresolved domain failures.
   - `entropy_threshold`: Shannon entropy calculation over domain query names ($\ge E$) to catch high-entropy algorithmic DGA domains and tunneling attempts.

### 16.3 Signature Event Schema (v1.0)

When a rule's criteria all evaluate to true, a structured `SignatureEvent` is emitted:

```json
{
  "event_id": "SIGEV-0001",
  "schema_version": "1.0",
  "rule_id": "SIG-HTTP-GET",
  "rule_name": "HTTP Inbound GET Request",
  "rule_revision": 1,
  "category": "INFO",
  "severity": "LOW",
  "timestamp_us": 1700000064303244,
  "src_ip": "192.168.1.100",
  "dst_ip": "93.184.216.34",
  "src_port": 58936,
  "dst_port": 80,
  "protocol": "TCP",
  "direction": "FORWARD",
  "flow_id": 4294967299,
  "incident_id": "INC-0003",
  "match_scope": "STREAM",
  "match_details": "Matched signature rule SIG-HTTP-GET (HTTP Inbound GET Request) [INFO/LOW]",
  "matched_pattern": "GET ",
  "match_offset": 0,
  "evidence": "GET / HTTP/1.1\\x0d\\x0aHost",
  "confidence": "HIGH"
}
```

### 16.4 Integration with Behavioral Detection & Incident Correlation

The Signature Engine directly enriches Phase 3.3 Security Incidents:
- **Correlation Evidence:** Signature matches are ingested by the `IncidentCorrelator`.
- **Score Contribution:** Signature events contribute deterministically to incident threat scores (`CRITICAL` +35, `HIGH` +25, `MEDIUM` +15, `LOW` +8).
- **Incident Timeline Enrichment:** Emits `SIGNATURE_MATCH` timeline events recording matched rule ID, pattern, and evidence snippet.
- **Incident Linkage:** Incident schema v1.0 records `related_signature_ids`, linking signature events directly to the overarching incident.

### 16.5 Performance, Bounding & Safe Execution

- **Bounded Stream Inspection:** Default `max_stream_inspection_bytes` is capped at 64 KB (65,536 bytes) to prevent Denial of Service from massive TCP streams.
- **Max Matches Cap:** Global match limit (`max_matches`, default: 10,000) prevents unbounded memory growth.
- **Per-Flow Deduplication:** A rule matches at most once per flow, suppressing alert storms.
- **Zero Heap Overhead in Search Loop:** Pattern searches avoid dynamic allocation during matching.

### 16.6 CLI Options & Usage

| Option | Argument | Description |
|---|---|---|
| `--signatures` | None | Enable signature-based intrusion detection engine |
| `--signature-stats` | None | Print formatted ASCII Signature Detection report |
| `--sig-rules <file>` | Path | Load signature rules from a JSON file |
| `--rules-dir <dir>` | Path | Load all `.json` rule files in a directory |
| `--export-signatures <file>` | Path | Export signature events to JSON v1.0 |
| `--export-signatures-csv <file>` | Path | Export signature events to tabular CSV |
| `--signature-max-matches <n>` | Integer | Set maximum signature matches (default: 10,000) |
| `--list-rules` | None | List loaded signature rules with status and exit |

#### Example Invocation

```bash
# Run full DPI inspection with signatures, behavioral detection, stream reassembly, and incidents
./bin/dpi_engine capture.pcap /tmp/filtered.pcap \
    --signatures \
    --sig-rules rules/intrusion_signatures.json \
    --signature-stats \
    --export-signatures /tmp/sig_events.json \
    --export-signatures-csv /tmp/sig_events.csv \
    --incidents --incident-stats
```

---

## 17. Threat Intelligence Enrichment, IOC Matching & Threat Context Engine (Phase 3.5)

The **Threat Intelligence Enrichment Engine** provides an offline, deterministic system that matches observed network flows, reconstructed streams, and protocol metadata against locally supplied Indicators of Compromise (IOCs). It correlates threat intelligence across flows, detections, signatures, and security incidents without relying on external network requests or third-party APIs.

### 17.1 Threat Intelligence Architecture & Pipeline

```
                ┌───────────────────────────────────────────────┐
                │ Locally Supplied Threat Datasets (JSON / Dir) │
                └───────────────────────┬───────────────────────┘
                                        │
                                        ▼
                ┌───────────────────────────────────────────────┐
                │   ThreatIntelParser & ThreatIntelValidator    │
                │   - Strict Schema v1.0 Validation             │
                │   - Duplicate Rejection & Format Normalization│
                └───────────────────────┬───────────────────────┘
                                        │
                                        ▼
                ┌───────────────────────────────────────────────┐
                │             ThreatIntelManager                │
                │   - Exact IPv4 Hash Map Index                 │
                │   - Sorted CIDR Mask Longest-Prefix Index     │
                │   - Domain & Subdomain Label-Stripping Index  │
                │   - URL Host & Path Prefix Index              │
                └───────────────────────┬───────────────────────┘
                                        │
   Observed Telemetry                   ▼
┌───────────────────────┐       ┌───────────────────────────────┐
│ - Bidirectional Flows │ ────► │      ThreatIntelEngine        │
│ - TCP Streams         │ ────► │   - Multi-Protocol Evaluator  │
│ - DNS Queries/Answers │ ────► │   - Duplicate Match Capping   │
│ - TLS SNI Metadata    │ ────► │   - Context Enrichment        │
│ - HTTP Host/URIs      │ ────► └───────────────┬───────────────┘
└───────────────────────┘                       │
                                                ▼
                        ┌───────────────────────────────────────────────┐
                        │              Enriched Outputs                 │
                        │   - FlowRecord Context (IOCs, Cats, Summs)   │
                        │   - ThreatMatchEvent (JSON & CSV v1.0)       │
                        │   - Security Incident Timeline & Scoring      │
                        │   - Formatted ASCII Threat Intelligence Report│
                        └───────────────────────────────────────────────┘
```

### 17.2 Threat Intelligence Dataset Schema (v1.0)

Threat datasets are specified in zero-dependency JSON conforming to Schema v1.0:

```json
{
  "id": "DS-MALWARE-FEED-01",
  "name": "C2 Infrastructure and Malware Distribution",
  "version": "1.0",
  "source": "Local Threat Research Team",
  "description": "High-confidence indicators of malicious command & control",
  "created_at": "2026-11-20T00:00:00Z",
  "valid_until": "2027-11-20T00:00:00Z",
  "enabled": true,
  "iocs": [
    {
      "ioc_id": "IOC-C2-IP-01",
      "type": "ipv4",
      "value": "198.51.100.25",
      "confidence": "HIGH",
      "severity": "CRITICAL",
      "category": "C2_SERVER",
      "description": "Active Cobalt Strike Team Server",
      "threat_actor": "APT29",
      "campaign": "Operation Stealth",
      "references": ["https://attack.mitre.org/software/S0154/"]
    },
    {
      "ioc_id": "IOC-EXFIL-CIDR-01",
      "type": "ipv4_cidr",
      "value": "203.0.113.0/24",
      "confidence": "MEDIUM",
      "severity": "HIGH",
      "category": "DATA_EXFILTRATION_HOST",
      "description": "Malicious subnet hosting exfiltration drops"
    },
    {
      "ioc_id": "IOC-MAL-DOMAIN-01",
      "type": "domain",
      "value": "malicious-c2.example.com",
      "confidence": "HIGH",
      "severity": "CRITICAL",
      "category": "MALICIOUS_DOMAIN"
    }
  ]
}
```

### 17.3 Supported Indicator of Compromise (IOC) Types & Matching Semantics

| Indicator Type | Canonical Identifier | Matching Logic & Boundary Protection |
|---|---|---|
| **IPv4 Address** | `ipv4` | Strict dotted-quad parsing (0-255, no leading zeros). Matches source and destination IPs via $O(1)$ hash map lookup. |
| **IPv4 CIDR** | `ipv4_cidr` | Network prefix mask evaluation ($0 \le \text{prefix} \le 32$). Evaluated in descending prefix order (longest prefix match). |
| **Domain** | `domain` | Case-insensitive normalized matching. Exact match and iterative label-stripping subdomain matching. Protects against boundary collisions (`notexample.com` never matches `example.com`). Supports wildcards (`*.c2.net`). |
| **DNS Query / Answer** | `dns` | Correlates observed DNS query names and resolved A-record answer IPs against domain and IP indicators. Matches CNAME referral chains. |
| **TLS SNI** | `tls_sni` | Matches client-requested Server Name Indication (SNI) from TLS ClientHello records against domain indicators. |
| **URL (Host / Path)** | `url` | Evaluates HTTP Host header and URI paths against host/path indexes. |
| **File Hash** | `file_hash` | Strictly validated and tracked (MD5, SHA1, SHA256). *Explicit limitation:* Raw packet fragments and partial streams are never hashed to avoid false attribution without complete file carving. |

### 17.4 Threat Context Provenance & Severity Model

When an indicator matches, the engine attaches rich threat context to the match event:
- **Dataset Provenance:** `dataset_id`, `dataset_version`, and dataset source.
- **Indicator Attribution:** `ioc_id`, `ioc_type`, `confidence` (`LOW`, `MEDIUM`, `HIGH`), and `severity` (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Threat Taxonomy:** `category` (e.g. `C2_SERVER`, `MALICIOUS_DOMAIN`, `BOTNET`), `threat_actor`, `campaign`, and contextual explanation.

### 17.5 Bi-directional Flow & Security Incident Enrichment

1. **Flow Record Context:** Injects `ioc_match_count`, `matched_ioc_ids`, `matched_ioc_values`, `threat_categories`, and human-readable `threat_summary` directly into `FlowRecord`.
2. **Behavioral Alert Evidence:** Injects threat intelligence indicators into `DetectionEvent::evidence["threat_intel_iocs"]` and detection explanations.
3. **Incident Timeline Integration:** Matches appear chronologically as `THREAT_INTEL_MATCH` events in `SecurityIncident::timeline`.
4. **Deduplicated Incident Scoring:** Adds a calibrated score boost (up to $+30.0$) strictly once per unique IOC value to prevent artificial inflation from overlapping feeds.
5. **Threat-Correlated Incidents:** Automatically generates focused incidents for high-confidence IOC matches even when behavioral detection thresholds are not exceeded.

### 17.6 Threat Match Event Schema (v1.0) JSON & CSV

#### JSON Export Schema (`--export-threat-matches <file>`)

```json
[
  {
    "event_id": "TME-0001",
    "schema_version": "1.0",
    "dataset_id": "DS-MALWARE-FEED-01",
    "dataset_version": "1.0",
    "ioc_id": "IOC-C2-IP-01",
    "ioc_type": "IPV4",
    "ioc_value": "198.51.100.25",
    "observed_value": "198.51.100.25",
    "match_type": "EXACT_IP",
    "match_timestamp_us": 1700000064303244,
    "src_ip": "192.168.1.100",
    "dst_ip": "198.51.100.25",
    "src_port": 58936,
    "dst_port": 443,
    "protocol": "TCP",
    "direction": "FORWARD",
    "flow_id": 4294967299,
    "related_incident_id": "INC-0003",
    "confidence": "HIGH",
    "severity": "CRITICAL",
    "category": "C2_SERVER",
    "evidence": "Destination IP matches threat intelligence indicator [IOC: 198.51.100.25 (C2_SERVER/CRITICAL)]",
    "match_explanation": "Observed traffic matched threat intelligence indicator IOC-C2-IP-01 from dataset DS-MALWARE-FEED-01."
  }
]
```

#### CSV Export Header (`--export-threat-matches-csv <file>`)

```csv
event_id,schema_version,dataset_id,dataset_version,ioc_id,ioc_type,ioc_value,observed_value,match_type,match_timestamp_us,src_ip,dst_ip,src_port,dst_port,protocol,direction,flow_id,related_incident_id,confidence,severity,category,evidence,match_explanation
```

### 17.7 CLI Options & Usage

| Option | Argument | Description |
|---|---|---|
| `--threat-intelligence` | None | Enable threat intelligence enrichment engine |
| `--threat-intel <file>` | Path | Load threat intelligence dataset from JSON file |
| `--threat-intel-dir <dir>` | Path | Load all `.json` threat dataset files in a directory |
| `--list-threat-datasets` | None | List loaded threat intelligence datasets and exit |
| `--threat-intel-stats` | None | Print formatted ASCII Threat Intelligence report |
| `--export-threat-matches <file>` | Path | Export threat match events to JSON v1.0 |
| `--export-threat-matches-csv <file>` | Path | Export threat match events to tabular CSV |
| `--enable-threat-dataset <id>` | ID | Enable specific threat dataset by ID |
| `--disable-threat-dataset <id>` | ID | Disable specific threat dataset by ID |
| `--threat-match-limit <n>` | Integer | Set maximum threat match events (default: 10,000) |

#### Example Invocation

```bash
# Run full DPI analysis with threat intelligence, signatures, and incident correlation
./bin/dpi_engine capture.pcap /tmp/filtered.pcap \
    --threat-intel threat_intel/c2_feeds.json \
    --threat-intel-stats \
    --export-threat-matches /tmp/threat_matches.json \
    --export-threat-matches-csv /tmp/threat_matches.csv \
    --signatures --sig-rules rules/intrusion_signatures.json \
    --incidents --incident-stats
```

---

## 18. Automated Test Suite

The project includes an extensive **155-test automated test suite** validating packet parsing, protocol extraction, multi-threaded load balancing, stateful flow tracking, Welford feature extraction, behavioral detection, TCP stream reassembly, security incident correlation, rule-based signature intrusion detection, and threat intelligence enrichment.

### Test Execution Commands

```bash
# 1. Run all 155 tests
make test

# 2. Run tests with AddressSanitizer (ASan)
make test_asan

# 3. Run tests with UndefinedBehaviorSanitizer (UBSan)
make test_ubsan

# 4. Run tests with ThreadSanitizer (TSan)
make test_tsan
```

# 2. Run with AddressSanitizer (ASan) & LeakSanitizer
make test_asan

# 3. Run with ThreadSanitizer (TSan) & Data Race Detection
make test_tsan

# 4. Run with UndefinedBehaviorSanitizer (UBSan)
make test_ubsan
```

### Complete Test Coverage (125 Suites)

#### Part 1: Core Parsing & Engine Stabilization (Tests 1-20)
1. Ethernet frame decoding and truncated packet rejection.
2. 802.1Q VLAN single-tag parsing and offset adjustment.
3. IPv4 header validation, minimum length, and option handling.
4. TCP segment parsing and flag verification.
5. UDP datagram parsing and length validation.
6. DNS query extraction, bounds validation, and pointer loop safety.
7. Case-insensitive HTTP `Host:` header extraction.
8. TLS ClientHello SNI extraction across complex multi-extension records.
9. QUIC Initial packet safety, payload bounds, and underflow rejection.
10. Exact domain rule matching (`domainMatchesPattern`).
11. Dot-delimited subdomain wildcard matching (`*.example.com`).
12. Suffix collision protection (`netflix.com` vs `x.com`, `microsoft.com` vs `t.co`).
13. Bidirectional canonical 5-tuple hashing consistency.
14. Multi-threaded load balancer worker distribution across 60+ synthetic flows.
15. Symmetrical flow mapping (client $\leftrightarrow$ server packet hashing).
16. True $O(1)$ LRU connection tracking and capacity eviction.
17. Monotonic packet reordering buffer sequence preservation.
18. End-to-end PCAP filtering and clean PCAP generation.
19. Truncated packet boundary and malformed length safety.
20. Large payload bounds enforcement.

#### Part 2: Flow Intelligence & Statistical Feature Extraction (Tests 21-32)
21. Welford's algorithm online variance, mean, and stddev accuracy.
22. Flow record directional attribution (forward vs reverse).
23. Microsecond-resolution inter-arrival time (IAT) statistics.
24. Directional TCP flag accumulators (SYN, ACK, PSH, FIN, RST).
25. Packet and byte asymmetry ratio computation.
26. Flow record JSON export schema and formatting.
27. Flow record CSV tabular export matrix formatting.
28. Symmetrical bidirectional flow table lookup and state pairing.
29. Inactive flow idle timeout expiration lifecycle.
30. Flow table capacity eviction with embedded $O(1)$ LRU linked list.
31. Flow telemetry counters and aggregated packet rate metrics.
32. End-to-end PCAP flow intelligence processing and artifact generation.

#### Part 3: Behavioral Network Detection Engine (Tests 33-48)
33. **Vertical Port Scan:** Probing $\ge 15$ ports on single target triggers reconnaissance alert.
34. **Horizontal Port Sweep:** Probing $\ge 10$ distinct hosts on port 80 triggers sweep alert.
35. **Scan Benign Boundary:** Scanning below threshold (e.g. 5 ports) generates 0 alerts.
36. **Connection Burst Anomaly:** High flow initiation rate ($\ge 25$ flows in $\le 2\text{s}$) triggers burst alert.
37. **Repeated Attempts Anomaly:** Repeated connection attempts with high incomplete handshake ratio triggers alert.
38. **High-Frequency DNS Anomaly:** Rapid domain lookup burst triggers suspicious DNS alert.
39. **DNS Tunneling Candidate:** Query length $\ge 50$ chars or subdomain depth $\ge 5$ triggers tunneling alert.
40. **Outbound Traffic Volume Anomaly:** Large egress transfer with extreme byte asymmetry triggers volume alert.
41. **Periodic Beaconing Detection:** Low inter-arrival jitter ($CV \le 0.20$) correctly triggers C2 beacon alert.
42. **Beaconing Jitter Rejection:** High inter-arrival jitter ($CV > 0.35$) correctly rejected without alert.
43. **TCP SYN Flood Anomaly:** Unacknowledged SYN flow flooding triggers protocol anomaly alert.
44. **TCP RST Ratio Anomaly:** Elevated reset ratio ($\ge 0.50$) triggers teardown anomaly alert.
45. **Detection Event Serialization:** Validates JSON schema v1.0 and CSV row serialization.
46. **Windowed Event Deduplication:** Duplicate events within time window are suppressed.
47. **DetectionConfig Validation & Toggling:** Validates boundary thresholds and runtime detector toggling.
48. **End-to-End PCAP Detection:** Full pipeline execution on PCAP verifying detection reporting and export.

#### Part 4: Advanced Protocol Intelligence & TCP Stream Reassembly (Tests 49-73)
49. **RFC 793 Modular Sequence Arithmetic:** Tests `seq_lt`, `seq_lte`, `seq_gt`, `seq_gte` under normal ordering and 32-bit boundary wraparound ($0\text{xFFFFFFF0} \to 0\text{x00000010}$).
50. **In-Order TCP Stream Reassembly:** Single continuous in-order payload assembly without segment buffering.
51. **Out-of-Order Segment Buffering & Reordering:** Out-of-order segment arrival (segments 2 and 3 before segment 1) correctly reordered into continuous stream.
52. **Duplicate Retransmission Discard:** Redundant segment with identical sequence number discarded without stream corruption.
53. **Identical Overlap Handling:** Partially overlapping segment with identical prefix trimmed and remaining bytes reassembled.
54. **Conflicting Overlap (BSD First-Come Policy):** Overlapping segment with modified bytes preserved original data and incremented `conflict_count`.
55. **Stream Gap Detection & Accounting:** Unreceived intermediate sequence range correctly flags gap without advancing head until resolved.
56. **32-Bit Sequence Number Wraparound:** Successful multi-segment reassembly across 32-bit sequence boundaries ($0\text{xFFFFFFF0}$ to $0\text{x00000020}$).
57. **SYN / FIN Sequence Space Consumption:** Validates RFC 793 SYN and FIN flag 1-byte sequence space consumption.
58. **RST Immediate Termination:** RST flag triggers immediate `CLOSED` transition and prevents further segment queuing.
59. **Per-Stream Memory Limit Enforcement:** Segments causing buffer to exceed `max_stream_buffer_bytes` rejected safely without heap exhaustion.
60. **HTTP/1.x Basic Request and Response Parsing:** Dissects HTTP GET request and JSON response into method, URI, headers, status code, and body.
61. **HTTP Message Split Across Segments:** Reassembles HTTP request payload fragmented across multiple TCP packets.
62. **HTTP Chunked Transfer-Encoding:** Incrementally de-chunks hex-prefixed chunked HTTP body into continuous stream.
63. **HTTP Pipelined Requests & Responses:** Dissects back-to-back pipelined HTTP requests on a persistent connection.
64. **HTTP Header Resource Limit Enforcement:** Rejects or truncates malformed requests exceeding maximum header length threshold.
65. **TLS Record Layer Deserialization:** Parses TLS record envelope, version, content type, and length.
66. **TLS ClientHello Split Across Segments:** Reassembles TLS ClientHello spanning across TCP packet boundary and extracts SNI and ALPN.
67. **TLS Encrypted Application Data Demarcation:** Detects transition to Record Type 0x17 and tracks encrypted record counts and bytes.
68. **DNS Query and Response Parsing:** Dissects DNS questions and Answer Resource Records across A, AAAA, and CNAME types.
69. **DNS Pointer Decompression Safety:** Safely parses compressed domain names and aborts circular pointer loops without recursion stack overflow.
70. **DNS Query-Response Transaction Correlation & Latency:** Correlates queries and responses by TxID, computing microsecond round-trip latency.
71. **DNS NXDOMAIN Burst Detection:** Monitors NXDOMAIN surges exceeding configured threshold to identify potential DGA malware activity.
72. **TCP Stream Manager Capacity & LRU Eviction:** Manages active connections, enforces table capacity, and evicts oldest idle streams via LRU.
73. **End-to-End PCAP Stream Reassembly:** Complete pipeline execution on PCAP capture, verifying stream tracking, telemetry aggregation, and JSON/CSV artifact generation.

#### Part 5: Security Incident Intelligence & Threat Correlation (Tests 74-98)
74. **Reconnaissance Incident Generation:** Correlates vertical port scans and repeated failed attempts into a unified `RECONNAISSANCE` incident.
75. **Horizontal Port Sweep Correlation:** Correlates multi-target port 80 sweeps, aggregating targeted endpoint hosts.
76. **Vertical Port Scan Correlation:** Correlates 20+ probed destination ports on a single host into reconnaissance findings.
77. **Repeated Connection Attempt Correlation:** Correlates connection attempts with incomplete handshakes and SYN-heavy anomalies.
78. **DNS Tunneling Candidate Correlation:** Correlates long domain query entropy with high query counts into `DNS_SUSPICIOUS_ACTIVITY`.
79. **DNS NXDOMAIN Burst Correlation:** Correlates unresolved lookup failure bursts, identifying possible DGA rendezvous activity.
80. **DNS Query Diversity Correlation:** Correlates high query frequencies across diverse domain names.
81. **Beacon-Like Communication Correlation:** Correlates low-jitter periodic polling with destination consistency into `SUSPICIOUS_OUTBOUND_COMMUNICATION`.
82. **Suspicious Outbound Anomaly & TLS Metadata Correlation:** Enriches outbound channel incidents with reassembled TLS SNI and ALPN metadata.
83. **Potential Data Exfiltration Correlation:** Correlates large outbound transfers ($\ge 150\text{ KB}$) with extreme directional asymmetry ($\ge 10:1$).
84. **Multi-Stage Suspicious Activity Generation:** Correlates sequential progression across Recon $\to$ Bursts $\to$ DNS $\to$ Beacon $\to$ Exfiltration into a `CRITICAL` `MULTI_STAGE_ACTIVITY` incident.
85. **Insufficient Evidence Rejection:** Safely suppresses isolated circumstantial events with scores below `min_incident_score`.
86. **Score Calculation Explainability:** Validates deterministic mathematical accumulation of detection weights and feature bonuses.
87. **Confidence Level Calculation:** Validates independent `HIGH`, `MEDIUM`, and `LOW` confidence evaluations based on flow breadth and category diversity.
88. **Duplicate Evidence Handling:** Deduplicates identical alert references and prevents redundant timeline inflation.
89. **Same-Flow Evidence Deduplication:** Correctly deduplicates score contributions when multiple alerts derive from the same flow.
90. **Endpoint Aggregation:** Aggregates multiple indicators originating from the same primary host into a single cohesive incident.
91. **Unrelated Endpoint Isolation:** Ensures distinct source endpoints are never merged into the same incident.
92. **Timeline Chronological Ordering:** Validates strict ascending chronological order of timeline events across microsecond timestamps.
93. **Timeline Identical Timestamp Tiebreak:** Validates deterministic ordering when timeline events share identical microsecond timestamps.
94. **Timeline Bounds Enforcement:** Ensures incident timeline length is capped at `max_timeline_events` to bound memory consumption.
95. **Incident Deduplication & Window Merging:** Merges related incidents occurring within `incident_window_seconds`.
96. **Incident Window Expiration:** Ensures events separated beyond the aggregation window remain separate, distinct incidents.
97. **Incident Serialization JSON and CSV:** Validates compliant JSON v1.0 and CSV tabular serialization.
98. **End-to-End PCAP Incident Analysis:** Complete pipeline execution on PCAP capture, verifying incident generation, reporting, and artifact exports.

#### Part 6: Rule-Based Intrusion Detection, Signature Engine & Threat Pattern Matching (Tests 99-125)
99. **JSON Rule Parsing Valid:** Parses valid single-rule and multi-rule JSON files with criteria blocks.
100. **JSON Rule Parsing Malformed:** Rejects syntax errors, unbalanced braces, and truncated JSON payloads safely.
101. **JSON Directory Rule Loading:** Discovers and loads multiple `.json` rule files across a directory.
102. **Rule Validation Valid Rule:** Validates properly structured rules across all criteria fields.
103. **Rule Validation Missing Required Fields:** Rejects rules missing mandatory `id`, `name`, or criteria.
104. **Rule Validation Invalid Port Range:** Rejects inverted port ranges ($> \text{max}$) or values $> 65535$.
105. **Rule Validation Invalid CIDR Prefix:** Rejects CIDR prefixes $> 32$.
106. **Rule Validation Malformed Hex String:** Rejects odd-length hex strings and invalid hex characters.
107. **Rule Validation Invalid Relative Offset:** Rejects initial patterns specifying relative offset or distance.
108. **Duplicate Rule ID Rejection:** Rejects colliding duplicate rule IDs while preserving loaded rules.
109. **Rule Enable and Disable Runtime Toggling:** Enables and disables rules dynamically at runtime.
110. **Network Criteria IP and Port Matching:** Matches IP addresses, CIDR blocks, port ranges, and protocols.
111. **Network Criteria TCP Flags and Packet Size:** Validates bitwise TCP flag masks and packet size boundaries.
112. **Stream Content ASCII Pattern Matching:** Searches and extracts matched ASCII byte sequences in stream payloads.
113. **Stream Content Case-Insensitive Matching:** Matches case-insensitive strings across varying capitalization.
114. **Stream Content Hex and Binary Matching:** Matches binary byte sequences decoded from hex patterns.
115. **Stream Content Offset and Depth Bounds:** Enforces byte search start offset and maximum search depth bounds.
116. **Stream Content Chained Relative Patterns:** Evaluates chained multi-pattern sequences with relative distance and within bounds.
117. **Stream Content Negated Pattern:** Enforces absence of required patterns, succeeding when absent and failing when present.
118. **Stream Content Cross-Segment Stream Matching:** Reassembles fragmented payloads across TCP segments before pattern evaluation.
119. **HTTP Metadata Matching:** Evaluates HTTP request/response methods, wildcard hosts, URIs, and status codes.
120. **TLS Metadata Matching:** Matches TLS ClientHello SNI with domain wildcards and ALPN protocol strings.
121. **DNS Metadata and Entropy Matching:** Evaluates DNS query domains, query types, and Shannon entropy calculations.
122. **Multi-Criteria Rule Evaluation:** Validates complex rules requiring simultaneous satisfaction of network, flow, stream, and protocol criteria.
123. **Maximum Matches Enforcement:** Caps emitted signature matches at configured `max_matches` threshold.
124. **Incident Correlation Integration:** Ingests signature events into security incidents, enriching timelines and scoring.
125. **End-to-End PCAP Signature Detection:** End-to-end PCAP execution verifying signature detection, ASCII report, and JSON/CSV artifact exports.

#### Part 7: Threat Intelligence Enrichment, IOC Matching & Threat Context Engine (Tests 126-155)
126. **Threat Intel Dataset JSON Parsing Valid:** Validates loading single and multi-IOC datasets, parsing dataset metadata and indicator fields.
127. **Threat Intel Dataset JSON Parsing Malformed:** Rejects syntax errors, unbalanced braces, and malformed JSON feeds safely.
128. **Threat Intel Dataset Missing Required Fields:** Rejects datasets missing mandatory ID, version, or IOC fields.
129. **Threat Intel Dataset Duplicate Dataset ID:** Prevents loading duplicate dataset IDs, preserving existing feeds.
130. **Threat Intel Dataset Duplicate IOC ID:** Rejects conflicting identical IOC IDs within the same dataset.
131. **Threat Intel Validation Invalid IPv4:** Validates strict octet range (0-255), leading zero rejection, and format correctness.
132. **Threat Intel Validation Invalid CIDR:** Rejects CIDR prefixes $> 32$ and malformed network masks.
133. **Threat Intel Validation Invalid Domain:** Validates RFC domain syntax, label lengths $\le 63$, character set, and wildcard semantics.
134. **Threat Intel Validation Invalid URL:** Rejects malformed URL strings and extracts host/path components safely.
135. **Threat Intel Dataset Expiration & Stale:** Filters expired feeds based on timestamp checks unless explicitly permitted.
136. **Threat Intel Dataset Disabled State:** Respects dataset enabled/disabled toggles during matching operations.
137. **Threat Intel Dataset Directory Loading:** Discovers and loads multiple `.json` threat dataset files across a directory.
138. **Threat Intel IPv4 Exact Matching:** Matches observed source and destination IPs against indexed threat indicators.
139. **Threat Intel IPv4 CIDR Matching:** Matches observed IPs against CIDR ranges, respecting subnet boundaries.
140. **Threat Intel IPv4 CIDR Boundary:** Validates matching at first IP (network address) and last IP (broadcast address) of CIDR blocks.
141. **Threat Intel IPv4 Overlapping CIDR:** Evaluates overlapping CIDR blocks with longest-prefix-match preference.
142. **Threat Intel Domain Exact Matching:** Matches observed domains identically against domain indicators.
143. **Threat Intel Domain Subdomain Matching:** Evaluates parent domain indicators against child subdomains (`evil.com` matches `sub.evil.com`).
144. **Threat Intel Domain Boundary Collision Rejection:** Rejects accidental prefix/suffix substring collisions (`notexample.com` does not match `example.com`).
145. **Threat Intel Domain Case and Trailing Dot:** Normalizes case-insensitivity and strips trailing FQDN dots during matching.
146. **Threat Intel Domain Wildcard Semantics:** Evaluates wildcard domain indicators (`*.malware.org`) across subdomain hierarchies.
147. **Threat Intel Protocol DNS Query Matching:** Matches DNS query names against domain indicators.
148. **Threat Intel Protocol DNS Resolved IP Matching:** Matches DNS answer IPs and CNAME chains against threat indicators.
149. **Threat Intel Protocol TLS SNI Matching:** Matches TLS ClientHello SNI values against domain indicators.
150. **Threat Intel Protocol HTTP Host and URL Matching:** Matches HTTP Host headers and request URIs against domain and URL indicators.
151. **Threat Intel Event JSON and CSV Serialization:** Validates export formatting for threat match events according to schema v1.0.
152. **Threat Intel Flow Enrichment:** Injects matched IOC IDs, categories, and severity summaries directly into `FlowRecord`.
153. **Threat Intel Incident Correlation Enrichment:** Appends threat match events to incident timelines and context.
154. **Threat Intel Incident Deduplicated Score:** Prevents artificial score inflation by deduplicating score boosts per unique IOC value.
155. **End-to-End PCAP Threat Intelligence Analysis:** Full pipeline execution on PCAP capture, verifying threat matching, report generation, and artifact export.

#### Part 8: Advanced Analytics, Forensics & Reporting Platform (Tests 156-180)
156. **Risk Profiler Endpoint Aggregation:** Groups bidirectional flows into unique endpoints, computing byte totals and flow counts.
157. **Risk Profiler RFC 1918 Classification:** Accurately classifies private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1) vs. public WAN IPs.
158. **Risk Profiler Explainable Scoring:** Aggregates contributing factors with explicit weights and human-readable explanations.
159. **Risk Profiler Diminishing Returns & Bounds:** Enforces mathematical bounds strictly between 0.0 and 100.0 with sublinear saturation.
160. **Risk Profiler Flow Scoring:** Evaluates flow-level risk based on matched IOCs and behavioral flags.
161. **Risk Profiler Behavioral Tagging:** Applies tags (SCANNER, BEACONING, DATA_EXFIL_SUSPECT, DNS_ANOMALOUS) based on observed patterns.
162. **Risk Profiler Top Endpoints Ranking:** Ranks active endpoints by composite risk score in descending order.
163. **Risk Profiler Serialization:** Validates JSON export of endpoint profiles and risk summary.
164. **Temporal Analytics Bucketing:** Slices capture duration into dynamic time buckets tracking packets, bytes, flows, and alerts.
165. **Temporal Analytics Peak Rates:** Correctly calculates peak packets-per-second (PPS) and bytes-per-second (BPS).
166. **Network Behavioral Stats Protocol Breakdown:** Aggregates flow counts and byte volume per application protocol.
167. **Network Behavioral Stats Port Services:** Maps target destination ports to recognized service names (HTTPS, DNS, HTTP, SSH).
168. **Network Behavioral Stats Percentiles:** Computes numerically stable duration and packet size percentiles (Min, Max, P25, P50, P75, P90, P95, P99).
169. **Network Graph Node & Edge Construction:** Constructs relationship topology connecting endpoints, domains, incidents, and threat IOCs.
170. **Network Graph Bounding Limits:** Strictly caps topology graph size to max 250 nodes and 500 edges.
171. **Investigation Creation & Fields:** Validates investigation record initialization with unique ID, status, priority, and analyst tags.
172. **Investigation Note Addition:** Verifies adding analyst investigation notes with unique timestamps and note IDs.
173. **Investigation Evidence Addition & Hash Integrity:** Calculates and verifies 16-character hexadecimal FNV-1a integrity digests.
174. **Investigation Evidence Safe Removal:** Allows removing non-critical evidence while preventing invalid deletions.
175. **Investigation Entity Linking:** Binds related flows, detections, incidents, and threat IOCs to an investigation workspace.
176. **Investigation Persistence Atomic Save & Load:** Saves investigations to JSON with atomic temp-file rename and reloads without loss.
177. **Report Generator JSON Types:** Validates generation of Executive, Technical, Security, Incident, and Threat Intel JSON reports.
178. **Report Generator Standalone HTML Report:** Verifies self-contained offline HTML generation with embedded CSS and zero external CDNs.
179. **DPI Engine Unified Analyze-All Bundle:** Validates automated export of all 19 JSON/CSV/HTML artifacts via `--analyze-all <dir>`.
180. **End-to-End PCAP Full Analytics & Reporting:** Full pipeline execution validating end-to-end integration across all subsystems.

---

## 18. Advanced Analytics, Forensics & Web Platform (Phases 3.6 - 4.4)

The platform provides a complete enterprise security intelligence workflow:
- **Unified Artifact Bundle:** Single CLI command `./bin/dpi_engine capture.pcap out.pcap --analyze-all <dir>` exports all flow, detection, incident, threat, graph, temporal, and HTML reports.
- **REST API Service:** Built on Python 3 standard library (`python3 server/api_server.py`) serving endpoints on `http://localhost:8080/`.
- **Operational Web Dashboard:** Responsive single-page console featuring 12 views (Dashboard, PCAP Workspace, Flow Explorer, Detection Center, Incident Center, Threat Intel, Network Graph, Traffic Analytics, Investigations, Reports, ML Model Lab, and AI Security Analyst).
- **Synthetic Demonstration Suite:** 5 labeled test PCAP fixtures generated via `python3 generate_all_fixtures.py` and automated with `./run_demo.sh`.

---

## 20. Versioning, Git Tracking & Release Workflow

### Recommended Git Initialization
This distribution is delivered as a clean, standalone project directory free of orphaned version-control objects. To establish local git version tracking and create release tags:

```bash
# 1. Initialize local repository
git init

# 2. Stage verified source code and documentation
git add .

# 3. Commit the release state
git commit -m "release: v5.5.0-FINAL - Production release with complete DPI engine, AI subsystem, security hardening, and documentation"

# 4. Create annotated release tag
git tag -a v5.5.0-FINAL -m "DPI & Packet Analyzer v5.5.0-FINAL: Complete verified release (234/234 tests, ASan/UBSan/TSan clean, zero CVEs, external benchmark adapters, AI analyst, and offline dashboard)"
```

### Release Versioning Scheme
- **Unified Platform Release:** `v5.5.0-FINAL`
- **C++ Core DPI Engine:** `v4.0.0-RELEASE` (180 automated tests passing; ASan/UBSan/TSan verified)
- **AI & ML Subsystem:** `v5.5.0` (Supervised Random Forest, Isolation Forest, Experiment Framework, AI Analyst, Active-Channel Risk Normalization)
- **Total Test Baseline:** 234 / 234 automated tests passing (180 C++ tests + 54 Python tests)
- **Feature Schema Version:** `2.0.0` (Strictly excludes raw ports, IPs, and timestamps)




