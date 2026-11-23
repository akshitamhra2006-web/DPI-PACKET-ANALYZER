# FINAL ARCHITECTURE SPECIFICATION
## Modular C++17 Deep Packet Inspection & Security Intelligence Engine

---

## 1. High-Level System Architecture

The DPI & Packet Analyzer is structured into five cohesive layers:
1. **Packet Capture & Decoding Layer:** Standalone PCAP parser extracting Ethernet, IPv4, TCP, UDP, DNS, TLS, and HTTP protocol headers without external library dependencies (`libpcap` is not required).
2. **Multithreaded FastPath Pipeline:** Symmetric load balancers distributing canonical 5-tuples to dedicated worker threads (`FastPath0-3`) using lock-free ring buffers.
3. **Stateful Flow & Stream Reconstruction Layer:** Bidirectional flow tables maintaining lifecycle state, directional Welford statistical accumulators, and an out-of-order TCP stream reassembler.
4. **Security Intelligence & Detection Layer:** Deterministic behavioral anomaly detectors, multi-criteria signature matching engine, threat intelligence IOC enrichment, and multi-stage security incident correlation.
5. **Analytics, Investigation & Presentation Layer:** Explainable endpoint risk profiler, temporal bucketing, bounded network relationship topology, investigation management with FNV-1a hash integrity, REST API service, and responsive frontend dashboard.

```
+-------------------------------------------------------------------------+
|                        PCAP Input Layer                                 |
|               (PcapReader: Microsecond precision)                       |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                     Load Balancing Subsystem                            |
|             hash(5-Tuple) % num_lbs -> LoadBalancer[0..1]               |
+-------------------+---------------------------------+-------------------+
                    |                                 |
                    v                                 v
+----------------------------------+ +----------------------------------+
|           FastPath 0 - 1         | |           FastPath 2 - 3         |
|  - Packet Parser & Classifier    | |  - Packet Parser & Classifier    |
|  - Connection Tracker & LRU      | |  - Connection Tracker & LRU      |
|  - Bidirectional Flow Table      | |  - Bidirectional Flow Table      |
|  - TCP Stream Reassembler        | |  - TCP Stream Reassembler        |
+-------------------+--------------+ +-------------------+--------------+
                    |                                    |
                    +------------------+-----------------+
                                       |
                                       v
+-------------------------------------------------------------------------+
|                      Detection & Intelligence Layer                     |
|  - Behavioral Detectors (Port scan, beaconing, burst, DNS, TCP anomalies)|
|  - Signature Engine (Snort/Suricata-style multi-criteria rules)          |
|  - Threat Intel Matcher (IP, CIDR, Domain, SNI, URL lookups)            |
|  - Incident Correlator (Evidence fusion, scoring, timeline generation)  |
+--------------------------------------+----------------------------------+
                                       |
                                       v
+-------------------------------------------------------------------------+
|                 Analytics, Risk & Reporting Subsystems                  |
|  - Risk Profiler: Explainable endpoint & flow scoring (0-100)           |
|  - Network Analytics Engine: Temporal bucketing, Top Talkers, Percentiles|
|  - Network Graph: Bounded topology (max 250 nodes, 500 edges)           |
|  - Investigation Manager: Case tracking, notes, FNV-1a evidence hash    |
|  - Report Generator: 5 JSON schemas + self-contained dark HTML report   |
+--------------------------------------+----------------------------------+
                                       |
                                       v
+-------------------------------------------------------------------------+
|                     Integration & Presentation Layer                    |
|  - REST API Service (Python 3 http.server, zero-dependency)             |
|  - Responsive Web UI (10-view operational security dashboard)           |
+-------------------------------------------------------------------------+
```

---

## 2. Component Design & Responsibilities

### 2.1 Packet Parser (`PacketParser`)
- Zero-copy protocol decoding where possible.
- Handles Ethernet frames with single and double 802.1Q VLAN tagging (`0x8100`, `0x88A8`).
- Endian-independent IPv4 decoding with header checksum validation.
- Protocol extraction:
  - **DNS:** Decodes questions, answers, RCODEs, with loop-safe label decompression.
  - **TLS:** Decodes handshake records, ClientHello SNI extension, ALPN, and supported versions.
  - **HTTP:** Decodes methods, URIs, Host headers, User-Agents, and chunked transfer encoding.

### 2.2 Bidirectional Flow Intelligence (`FlowTable`, `FlowRecord`)
- Canonical symmetric 5-tuple indexing:
  $$\text{Key} = (\min(\text{IP}_1, \text{IP}_2), \max(\text{IP}_1, \text{IP}_2), \min(\text{Port}_1, \text{Port}_2), \max(\text{Port}_1, \text{Port}_2), \text{Proto})$$
- Independent tracking for forward (initiator) and reverse (responder) directions.
- Numerically stable Welford statistical accumulators for packet sizes and inter-arrival times (IAT), calculating mean, sample variance, and standard deviation in $O(1)$ memory without storing individual packet lengths.

### 2.3 TCP Stream Reassembler (`TCPStreamReassembler`)
- Per-flow, per-direction sequence tracking with 32-bit integer wrap-around handling:
  $$\Delta = (S_{\text{incoming}} - S_{\text{expected}}) \pmod{2^{32}}$$
- Segments received in-order are immediately delivered to protocol parsers.
- Out-of-order segments are queued in an interval tree / ordered map.
- Handles identical overlaps, conflicting overlaps, and gaps.
- Memory consumption bounded at 64 MB globally with proactive LRU segment eviction.

### 2.4 Incident Correlator (`IncidentCorrelator`)
- Unifies disparate indicators into high-level `SecurityIncident` records.
- Correlates multi-stage kill-chain events within configurable time windows (default: 60s).
- Computes explainable correlation scores bounded to $[0, 100]$ based on evidence diversity, target criticality, and severity weighting.
- Chronologically orders timeline events with sub-microsecond tiebreak stability.

### 2.5 Explainable Risk Profiler (`RiskProfiler`)
- Identifies network roles (Client, Server, Mixed).
- Categorizes RFC 1918 internal addresses vs. public external addresses.
- Assigns behavioral tags: `SCANNER`, `BEACONING`, `DATA_EXFIL_SUSPECT`, `DNS_ANOMALOUS`, `THREAT_INTEL_FLAGGED`.
- Sublinear score aggregation ensures single repeated minor alerts cannot artificially saturate scores.

### 2.6 Relationship Graph (`NetworkGraph`)
- Constructs node objects for Endpoints, Domains, Incidents, and IOCs.
- Aggregates communication flows into weighted edges.
- Bounded strictly to 250 nodes and 500 edges to guarantee lightweight serialization and responsive browser rendering.

---

## 3. Data Flow & Concurrency Model

1. **Lock-Free Queuing:** Reader thread deposits raw packets into LoadBalancer ring buffers.
2. **Deterministic Hashing:** LoadBalancers hash the symmetric 5-tuple, dispatching packets to the same FastPath worker to guarantee single-thread flow ownership without lock contention.
3. **Thread Safety:** Flow tables and stream reassemblers operate without cross-thread locking during packet processing. FastPath workers only lock when finalizing and merging global analytics at capture completion.
