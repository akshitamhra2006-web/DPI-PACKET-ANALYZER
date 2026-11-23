# Changelog

All notable changes to the **DPI & Packet Analyzer** project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [5.5.0-FINAL] - 2026-11-23

### Completed
- **Milestone 5.5 Final Project Closure & Release Engineering:**
  - Certified comprehensive release baseline: 234 / 234 automated tests passing (180 C++ tests + 54 Python tests).
  - Executed and validated all sanitizers: AddressSanitizer (0 leaks, 0 corruption), UndefinedBehaviorSanitizer (0 UB), ThreadSanitizer (0 races).
  - Produced `FINAL_EXTERNAL_VALIDATION_REPORT.md` documenting transparent benchmark readiness on CIC-IDS2017 and UNSW-NB15 schemas without synthetic metric fabrication.
  - Produced `FINAL_SECURITY_AUDIT_REPORT.md` detailing defense-in-depth across C++ memory safety, REST API, web dashboard, and AI subsystem.
  - Produced `FINAL_TEST_AND_VERIFICATION_REPORT.md` documenting all test fixtures, logs, and end-to-end execution.
  - Created pinned `requirements.txt` with minimal dependency attack surface (`numpy`, `scikit-learn`, `joblib`).
  - Implemented unified `.gitignore` filtering build artifacts, temp dumps, and python caches.
  - Aligned API server metadata with `platform_version: 5.5.0-FINAL`.

---

## [5.4.0] - 2026-11-22

### Added
- **Leakage-Aware Experiment Framework:** Implemented `evaluate_leakage_aware()` in `ml/experiment_framework.py` with vector-hash grouping via SHA-256 to eliminate duplicate flow leakage across cross-validation folds.
- **External Dataset Ingestion Adapters:** Added `DatasetManager.ingest_external_csv()` supporting canonical schema translation for CIC-IDS2017 (`CICIDS_FEATURE_MAP`, `CICIDS_LABEL_MAP`) and UNSW-NB15 (`UNSW_FEATURE_MAP`, `UNSW_LABEL_MAP`).
- **Benchmark Test Fixtures:** Added `tests/fixtures/sample_cicids2017.csv` and `tests/fixtures/sample_unsw_nb15.csv`.
- **Model Cryptographic Signatures:** Added HMAC-SHA256 signature generation and verification (`model.joblib.sig`) in `ml/models.py` to prevent model tampering.
- **Dynamic Active-Channel Explainability:** Implemented active weight renormalization in `ml/explainability.py` ensuring feature contributions scale to $1.0$ when anomaly detection is uncalibrated.

### Fixed
- **Web Frontend DOM XSS Vulnerabilities:** Enforced `escapeHtml()` across all table cells, tooltips, and dynamic DOM nodes in `web/js/app.js` and `web/dist/js/app.js`.
- **Unsupported Class Handling:** Added explicit warning and tagging for unsupported classes (`PORT_SCAN`, `DNS_TUNNEL`) during binary classification evaluation.

---

## [5.2.0] - 2026-11-20

### Fixed
- **AI Remediation & Baseline Integrity:**
  - Removed all synthetic benign traffic generation from `ModelRegistry`.
  - Added strict minimum threshold of 10 genuine benign flows required for Isolation Forest anomaly calibration.
  - Implemented `INSUFFICIENT_BASELINE_DATA` status reporting in `/api/ai/status`.
  - Separated training accuracy from test evaluation metrics in `AI_EVALUATION_REPORT.md`.

---

## [5.0.0] - 2026-11-18

### Added
- **Supervised ML Intrusion Detection:** Random Forest classifier operating on 14 flow features extracted from live C++ stream records.
- **Unsupervised Anomaly Detection:** Isolation Forest detector calibrated against clean network baselines.
- **AI Security Analyst:** Natural language investigation assistant (`ai/assistant.py`) with query classification and context synthesis.
- **Risk Explainability Engine:** Tree-based feature importance attribution explaining why flows are classified as malicious.
- **SOC Recommendations Engine:** Actionable remediation guidance mapped to detected MITRE tactics and threats.
- **AI REST Endpoints:** Added `/api/ai/classify`, `/api/ai/batch-classify`, `/api/ai/detect-anomalies`, `/api/ai/explain`, `/api/ai/recommend`, `/api/ai/status`, and `/api/ai/investigate`.

---

## [4.0.0] - 2026-11-15

### Added
- **Interactive Offline Dashboard:** 10-view web interface built with vanilla HTML5, CSS3, and JavaScript (Overview, Flows, Detections, Signatures, Incidents, Threat Intel, Risk, Streams, Graph, Timeline).
- **Core REST API Server:** Lightweight HTTP daemon in `server/api_server.py` serving flow data, graph topology, temporal events, and investigations.
- **Investigation Case Management:** Forensic analyst workflow supporting case creation, evidence attachment, notes, and status tracking.
- **Advanced Forensic Analytics:** Host risk profiler, Cytoscape network interaction graphs, and temporal event tracking.
- **Full C++ Sanitizer Certification:** Validated 180 C++ tests with zero leaks under ASan, UBSan, and TSan.

---

## [3.5.0] - 2026-11-12

### Added
- **Threat Intelligence Enrichment:** IOC matching engine supporting IP/CIDR subnets, high-performance domain Bloom filters, and file hash lookups.
- **Feed Ingestion:** Structured JSON threat feed loaders with confidence scoring and threat classification.

---

## [3.4.0] - 2026-11-10

### Added
- **Rule-Based Signature Engine:** Snort/Suricata-style rule parser and runtime matcher supporting protocol, IP/port constraints, content matching (Aho-Corasick), and PCRE regular expressions.
- **Rule Management:** Hot-reloading signature rulesets from `config/signatures/`.

---

## [3.3.0] - 2026-11-08

### Added
- **Security Incident Correlation:** Multi-stage kill-chain correlation associating behavioral detections into consolidated incident cases.
- **MITRE ATT&CK Mapping:** Automatic tagging of Initial Access, Execution, Persistence, Defense Evasion, Discovery, Lateral Movement, and Exfiltration.

---

## [3.2.0] - 2026-11-05

### Added
- **Behavioral Detection Engine:** Statistical and heuristic detection algorithms for Horizontal/Vertical Port Scanning, SYN Flood DoS, DNS Tunneling, and ICMP C2 Beacons.

---

## [3.1.0] - 2026-11-02

### Added
- **Deep Protocol Intelligence:** Layer 7 parsers for HTTP (methods, URIs, headers, user-agents), TLS (ClientHello SNI extraction, cipher suites), and DNS (queries, answers, RR types, label decompression).

---

## [3.0.0] - 2026-10-28

### Added
- **TCP Stream Reassembly:** Out-of-order sequence reconstruction, duplicate segment deduplication, overlapping segment boundary trimming, and per-stream memory bounding.

---

## [2.1.0] - 2026-10-20

### Added
- **Flow State Intelligence:** Bidirectional 5-tuple flow tracking (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`), TCP flag accumulation, and connection state machine.

---

## [1.0.0] - 2026-10-10

### Added
- **Core C++17 DPI Engine:** Raw libpcap reader, Ethernet frame decoders, IPv4 and IPv6 packet parsing, and TCP/UDP transport header parsing.
