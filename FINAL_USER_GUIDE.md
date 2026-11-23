# FINAL USER & OPERATOR GUIDE
## Deep Packet Inspection & Network Security Intelligence Platform

---

## 1. Quick Start

### Build the Platform
```bash
# Build the production DPI Engine binary
make all

# Run the complete test suite (180 tests)
make test

# Run with AddressSanitizer / UndefinedBehaviorSanitizer
make test_asan
make test_ubsan
make test_tsan
```

### One-Click Demonstration
Run the automated end-to-end demonstration script:
```bash
./run_demo.sh
```
This builds binaries, generates synthetic PCAPs, executes the full DPI pipeline, exports the analysis bundle, and outputs direct links to the generated offline HTML report.

---

## 2. Running Analysis on PCAP Files

### Command-Line Execution
To execute the complete intelligence pipeline on a PCAP capture and export the unified artifact bundle:
```bash
./bin/dpi_engine <input.pcap> <filtered_output.pcap> \
    --analyze-all data/current_session \
    --detect \
    --incidents \
    --signatures \
    --threat-intelligence \
    --rules-dir config/signatures \
    --threat-intel-dir config/threat_intel \
    --risk-stats \
    --analytics-stats
```

### Output Artifacts Generated in `<output_dir>`:
- `analysis_report.html` — Comprehensive offline responsive dark-theme HTML report.
- `flows.json` & `flows.csv` — Stateful bidirectional flow records with Welford metrics.
- `detections.json` & `detections.csv` — Behavioral detection events with explainability.
- `incidents.json` & `incidents.csv` — Correlated security incidents with stage timelines.
- `signatures.json` & `signatures.csv` — Multi-criteria signature matches.
- `threat_matches.json` & `threat_matches.csv` — IOC indicator matches with dataset provenance.
- `endpoints.json` — Endpoint risk profiles with RFC 1918 classification and scores.
- `risk_summary.json` — Capture-wide risk assessment overview.
- `analytics.json` — Protocol breakdowns, port service rankings, percentiles.
- `network_graph.json` — Bounded relationship topology nodes and weighted edges.
- `temporal_analytics.json` — Time-bucketed throughput metrics (PPS/BPS).
- `investigations.json` — Forensic cases with notes and FNV-1a evidence digests.

---

## 3. Web Dashboard & REST API Service

Launch the backend REST API service:
```bash
python3 server/api_server.py
```
Open your browser and navigate to:
```
http://localhost:8080/
```

### Available Dashboard Views:
1. **Dashboard:** High-level metrics, throughput chart, protocol distribution, top talkers.
2. **PCAP Workspace:** Upload/select capture files, toggle engines, run live analysis.
3. **Flow Explorer:** Paginated stateful flow records, Welford statistics, L7 inspector.
4. **Detections:** Behavioral scan, burst, DNS, and TCP anomaly alerts.
5. **Incidents:** Correlated multi-stage security incidents with chronological timelines.
6. **Threat Intel:** Matched IOCs against active datasets.
7. **Network Graph:** Interactive SVG relationship topology.
8. **Traffic Analytics:** Bucket-based packet rate charts and TCP flag distribution.
9. **Investigations:** Case tracking, analyst notes, and cryptographic evidence hashes.
10. **Reports:** Direct download links for all 5 JSON report formats and the standalone HTML report.
