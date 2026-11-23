# System Architecture Specification — DPI & Packet Analyzer

**Platform Version:** `v5.5.0-FINAL`  
**Classification:** Technical System Architecture & Component Design  

---

## 1. Architectural Overview

The **DPI & Packet Analyzer** platform is architected as a layered, modular cybersecurity system uniting real-time C++17 stream processing with a Python AI intelligence pipeline and an offline web dashboard.

```
+-------------------------------------------------------------------------+
|                        PCAP Input Layer                                 |
|               (PcapReader: Microsecond precision)                       |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                     FastPath Packet Processing Pipeline                 |
|  - Packet Parser & Protocol Decoders (Ethernet, IPv4, IPv6, TCP, UDP)   |
|  - Bidirectional Flow Table (Welford Statistical Accumulator)           |
|  - Out-of-Order TCP Stream Reassembler & Boundary Trimmer               |
|  - Protocol Intelligence Parsers (HTTP, TLS SNI, DNS Decompressor)      |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                      Detection & Intelligence Layer                     |
|  - Behavioral Detection Engine (Port scan, SYN flood, DNS tunnel, ICMP) |
|  - Rule Signature Engine (Snort/Suricata rules, Aho-Corasick, PCRE)     |
|  - Threat Intelligence Engine (IP/CIDR, Domain Bloom filter, Hashes)    |
|  - Multi-Stage Incident Correlator (MITRE ATT&CK kill-chain mapping)    |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                 Analytics, Risk & Reporting Subsystems                  |
|  - Endpoint Risk Profiler (0-100 composite risk scoring)                |
|  - Network Analytics Engine (Top Talkers, Percentiles, BPS/PPS)        |
|  - Network Graph Generator (Cytoscape bounded topology)                |
|  - Investigation Case Manager (FNV-1a cryptographic evidence hashes)    |
|  - Unified Artifact Exporter (19 JSON/CSV/HTML artifacts)               |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                      AI & Machine Learning Subsystem                    |
|  - Supervised Random Forest Classifier (14-feature flow vectors)       |
|  - Unsupervised Isolation Forest Anomaly Detector                       |
|  - Leakage-Aware Vector-Hash Grouping Framework                         |
|  - Dynamic Active-Channel Explainability Normalizer                     |
|  - AI Security Analyst (Isolated XML prompts, regex sanitization)       |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                     Presentation & Integration Layer                    |
|  - REST API Daemon (server/api_server.py: zero third-party dependencies)|
|  - Offline Web Forensic Dashboard (12 DOM-XSS-sanitized views)          |
+-------------------------------------------------------------------------+
```

---

## 2. Core Engine Components (C++17)

1. **PcapReader ([src/core/pcap_reader.cpp](file:///Users/akshitamehra/Documents/Packet_analyzer-main/src/core/pcap_reader.cpp)):**
   - Independent PCAP binary parser handling microsecond and nanosecond timestamps.
   - Strictly bounds-checks magic headers (`0xa1b2c3d4`, `0xd4c3b2a1`) and per-packet header lengths (`caplen <= snaplen`).

2. **PacketParser ([src/core/packet_parser.cpp](file:///Users/akshitamehra/Documents/Packet_analyzer-main/src/core/packet_parser.cpp)):**
   - Decodes Layer 2 through Layer 4. Validates IP header length (`ihl * 4 >= 20`), checksums, and payload offsets.

3. **FlowTable & FlowRecord ([src/core/flow_table.cpp](file:///Users/akshitamehra/Documents/Packet_analyzer-main/src/core/flow_table.cpp)):**
   - Canonical 5-tuple key: `(min_ip, max_ip, min_port, max_port, proto)`.
   - Directional counters: packets, bytes, TCP state machine transitions (SYN, SYN-ACK, ESTABLISHED, FIN, RST).
   - Welford algorithm calculates streaming packet size mean and variance without storing raw packets in memory.

4. **TCPStreamReassembler ([src/core/tcp_stream_reassembler.cpp](file:///Users/akshitamehra/Documents/Packet_analyzer-main/src/core/tcp_stream_reassembler.cpp)):**
   - Implements sequence space arithmetic modulo $2^{32}$.
   - Reassembles out-of-order TCP segments into ordered streams.
   - Enforces strict memory caps (`MAX_BUFFER_PER_STREAM = 4 MB`) to prevent reassembly exhaustion attacks.

5. **SignatureEngine ([src/detection/signature_engine.cpp](file:///Users/akshitamehra/Documents/Packet_analyzer-main/src/detection/signature_engine.cpp)):**
   - Compiles Snort/Suricata rules into fast-path headers and Aho-Corasick multi-pattern search trees.

6. **ThreatIntel ([src/threat_intel/threat_intel.cpp](file:///Users/akshitamehra/Documents/Packet_analyzer-main/src/threat_intel/threat_intel.cpp)):**
   - Subnet trie for CIDR matching, Bloom filter for $O(1)$ domain checks, and unordered sets for SHA-256 file hashes.

---

## 3. AI & Machine Learning Subsystem (Python)

1. **Feature Vector Representation:**
   14 flow attributes extracted directly from C++ flow tables:
   ```
   [duration_ms, total_packets, total_bytes, forward_packets, backward_packets,
    forward_bytes, backward_bytes, bytes_per_second, packets_per_second,
    syn_ratio, rst_ratio, ack_ratio, fin_ratio, payload_entropy]
   ```
   *Note:* Raw IP addresses, ports, and timestamps are strictly excluded from feature vectors to prevent shortcut learning.

2. **Supervised Random Forest Classifier:**
   - 100 decision trees, Gini impurity criterion.
   - Model artifact stored in `ml/models/supervised_random_forest.joblib` with an accompanying HMAC-SHA256 signature in `.sig`.

3. **Unsupervised Isolation Forest:**
   - Detects zero-day anomalies based on isolation tree path depth.
   - Calibrated strictly against clean baseline traffic (minimum 10 benign flows). If fewer than 10 flows exist, the detector reports `INSUFFICIENT_BASELINE_DATA` without fabricating synthetic data.

4. **Leakage-Aware Experiment Framework:**
   - Groups identical feature vectors via SHA-256 hashing to ensure identical vectors never appear across training and validation folds.

5. **AI Security Analyst:**
   - Natural language investigation assistant enforcing XML isolation (`<untrusted_traffic_evidence>`) and regex query sanitization.

---

## 4. Web Presentation & API Layer

- **REST API Server ([server/api_server.py](file:///Users/akshitamehra/Documents/Packet_analyzer-main/server/api_server.py)):**
  - Built exclusively with Python 3 `http.server`.
  - Enforces path traversal confinement, payload bounding (`max_flows = 5000`), and CORS headers.
- **Frontend Dashboard ([web/js/app.js](file:///Users/akshitamehra/Documents/Packet_analyzer-main/web/js/app.js)):**
  - Zero external CDN dependencies; runs in completely air-gapped environments.
  - Complete DOM XSS sanitization across all 12 views via `escapeHtml()`.
