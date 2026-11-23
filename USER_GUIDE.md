# User & Operator Guide — DPI & Packet Analyzer

**Platform Version:** `v5.5.0-FINAL`  
**Classification:** Operational Guide & Command Reference  

---

## 1. Introduction

The **DPI & Packet Analyzer** is an enterprise-grade network security analysis platform. It combines line-rate C++17 deep packet inspection, signature matching, threat intelligence correlation, behavioral anomaly detection, machine learning classification, and an offline interactive dashboard.

---

## 2. Command-Line Interface Reference (`bin/dpi_engine`)

### Syntax
```bash
./bin/dpi_engine <input.pcap> <filtered_output.pcap> [OPTIONS]
```

### Options
| Flag | Parameter | Description |
| :--- | :--- | :--- |
| `--analyze-all` | `<dir>` | Run the complete analysis pipeline and export all 19 JSON/CSV/HTML artifacts to `<dir>`. |
| `--detect` | - | Enable behavioral anomaly detectors (Port Scans, SYN Floods, DNS Tunnels, ICMP Beacons). |
| `--incidents` | - | Enable incident correlation engine (multi-stage kill chains, MITRE ATT&CK mapping). |
| `--signatures` | - | Enable rule-based signature detection engine. |
| `--rules-dir` | `<dir>` | Path to Snort/Suricata-style signature rules (default: `config/signatures`). |
| `--threat-intelligence` | - | Enable threat intelligence and IOC matching. |
| `--threat-intel-dir` | `<dir>` | Path to threat intelligence feed files (default: `config/threat_intel`). |
| `--risk-stats` | - | Compute risk profiler metrics for all observed IP endpoints. |
| `--analytics-stats` | - | Compute temporal, protocol, and network topology statistics. |

### Example Command
```bash
./bin/dpi_engine test_dpi.pcap data/current_session/forwarded_traffic.pcap \
    --analyze-all data/current_session \
    --detect \
    --incidents \
    --signatures \
    --threat-intelligence \
    --rules-dir config/signatures \
    --threat-intel-dir config/threat_intel
```

---

## 3. Web Dashboard Views & Navigation

The offline dashboard serves 12 analytical views accessible at `http://localhost:8080`:

1. **Dashboard Overview:** Executive summary with traffic volume gauges, threat score distributions, top talkers, and protocol breakdowns.
2. **PCAP Workspace:** Upload new PCAP files or re-run analysis dynamically on selected sessions.
3. **Flow Explorer:** Searchable, paginated table of bidirectional network flows with TCP flags, durations, and byte ratios.
4. **Behavioral Detections:** Detailed list of algorithmic detections with confidence scores and MITRE ATT&CK mappings.
5. **Rule Signatures:** Matched intrusion detection signatures with triggering packet payloads.
6. **Incident Center:** Correlated multi-stage security incidents with severity ratings, kill-chain timelines, and affected hosts.
7. **Threat Intelligence:** Active IOC matches against IP feeds, domain Bloom filters, and malware hashes.
8. **Endpoint Risk Profiles:** Asset risk ranking based on inbound/outbound threat indicators.
9. **Forensic Stream Reassembly:** Reconstructed ASCII and hex representations of bidirectional TCP payloads.
10. **Network Graph:** Cytoscape/Canvas interactive relationship graph between internal and external IP addresses.
11. **Temporal Analytics:** PPS and BPS time-series visualizations.
12. **AI Security Assistant:** Interactive natural language assistant for querying forensic evidence, threat summarization, and SOC playbooks.

---

## 4. AI & Machine Learning Operations

### 4.1 Running Model Inference via CLI
```bash
# Classify a flow vector using the trained Random Forest model
python3 -c "
from ml.models import SupervisedFlowClassifier
import numpy as np

clf = SupervisedFlowClassifier.load('ml/models/supervised_random_forest.joblib')
# 14-feature vector: [dur, pkts, bytes, fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes, bps, pps, syn, rst, ack, fin, entropy]
sample = np.array([[1200, 45, 12800, 25, 20, 8000, 4800, 10666, 37.5, 0.05, 0.0, 0.95, 0.05, 5.4]])
pred = clf.predict(sample)
print('Prediction:', clf.classes_[pred[0]])
"
```

### 4.2 Training Models & Evaluating Leakage-Aware Cross Validation
```bash
python3 -c "
from ml.dataset_manager import DatasetManager
from ml.models import SupervisedFlowClassifier
from ml.experiment_framework import ExperimentFramework

dm = DatasetManager(dataset_dir='data/ml_datasets')
flows = dm.load_dataset('pcap_derived')
X, y, labels = dm.extract_feature_matrix(flows)

framework = ExperimentFramework()
results = framework.evaluate_leakage_aware(SupervisedFlowClassifier, X, y, n_splits=5)
print('Macro-F1:', results['macro_f1'])
"
```

---

## 5. REST API Endpoints Quick Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Healthcheck and platform version. |
| `GET` | `/api/summary` | Overall session summary metrics. |
| `GET` | `/api/flows` | Paginated flow records (query params: `page`, `limit`, `search`). |
| `GET` | `/api/incidents` | Security incidents. |
| `GET` | `/api/detections` | Behavioral detections. |
| `GET` | `/api/signatures` | Matched signatures. |
| `GET` | `/api/threat-matches` | Threat intelligence IOC matches. |
| `GET` | `/api/endpoints` | Endpoint risk profiles. |
| `GET` | `/api/graph` | Network topology nodes and edges. |
| `GET` | `/api/temporal` | Temporal timeline series. |
| `POST` | `/api/ai/classify` | Classify a single flow with Supervised ML. |
| `POST` | `/api/ai/batch-classify`| Classify up to 5,000 flows. |
| `POST` | `/api/ai/investigate` | Submit natural language query to AI Security Analyst. |
| `GET` | `/api/ai/status` | Assistant status and anomaly detector calibration state. |
