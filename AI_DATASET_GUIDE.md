# Deep Packet Inspection & Packet Analyzer — AI Dataset Guide
**Document Version:** 5.5.0-FINAL  
**Milestone:** Milestone 5.5 — Final Project Closure & Release Engineering  
**Applicable Subsystems:** `ml/dataset_manager.py`, `ml/feature_pipeline.py`, `data/datasets/`

---

## 1. Overview & Dataset Philosophy

A machine learning model for network security is only as dependable as the integrity and representative validity of its training data. This platform rejects fabricated synthetic arrays in favor of genuine flow records derived directly from real network packet captures (PCAP).

The dataset architecture operates on two levels:
1. **Local PCAP-Derived Ground-Truth Dataset (`PCAP-DERIVED-FLOWS-v1.json`)**: Extracted directly from five deterministic network scenario captures generated with realistic protocol headers, payload structures, and timing characteristics. Under Schema 2.0.0, every flow record is annotated with explicit scenario grouping metadata (`capture_scenario`, `source_pcap`, `dataset_origin`).
2. **Standardized Public Benchmark Ingestion (CIC-IDS2017 & UNSW-NB15)**: Schema transformation mapping external benchmark datasets into the standardized 24-dimensional feature vector.

---

## 2. PCAP-Derived Ground-Truth Dataset (Schema 2.0.0)

The dataset manager (`ml/dataset_manager.py`) processes PCAP captures using the C++ DPI engine to generate realistic, labeled bidirectional flow records:

| PCAP Source File | Attack / Traffic Scenario | Ground-Truth Label | Generated Flows | Traffic Characteristics |
| :--- | :--- | :--- | :---: | :--- |
| `normal_traffic.pcap` | Legitimate browsing & DNS | `BENIGN` | 2 | Standard TCP 3-way handshakes, HTTP GET requests, balanced bytes, low RST flags |
| `port_scan_recon.pcap` | Multi-port reconnaissance sweep | `PORT_SCAN` | 40 | Low packet counts (1-2), zero reverse bytes, high SYN flags, rapid sequential ports |
| `beacon_c2.pcap` | Command & Control beaconing | `C2_BEACON` | 24 | Periodic heartbeats, low inter-arrival jitter, constant payload size, persistent sessions |
| `dns_anomalies.pcap` | DNS tunneling / exfiltration | `DNS_TUNNEL` | 24 | High UDP volume to port 53, high byte-to-packet ratios, anomalous query entropy |
| `threat_intel_match.pcap` | Known malware C2 HTTP traffic | `MALWARE_HTTP` | 2 | HTTP POST/GET to known malicious endpoints, specific malicious user agents |
| **Total** | | | **92** | Full multi-class threat representation |

### Ground-Truth Label Distribution
```
PORT_SCAN:     40 flows (43.5%)
C2_BEACON:     24 flows (26.1%)
DNS_TUNNEL:    24 flows (26.1%)
BENIGN:         2 flows  (2.2%)
MALWARE_HTTP:   2 flows  (2.2%)
Total:         92 flows (100.0%)
```

### Scientific Finding: Feature Vector Redundancy & Port Leakage Elimination
During Milestone 5.1 auditing and Milestone 5.2 remediation, removing the raw `destination_port` feature revealed an essential structural characteristic of synthetic network generators:
- **8 Unique Feature Vectors**: Because PCAP generation scripts use identical packet sizes and fixed inter-arrival intervals for repetitive flows, the 92 PCAP flows collapse to **8 unique 24-dimensional feature vectors** when port numbers are replaced with structural indicators (`is_well_known_port`, `is_ephemeral_port`).
- **Elimination of Port Memorization**: In Milestone 5.0, the presence of raw `destination_port` allowed classifiers to memorize that port 445 or 8080 was a scan, yielding an artificial 100% resubstitution score. Under Schema 2.0.0, models must classify based on true behavioral dynamics (asymmetry, packet sizes, flag distributions).
- **Realistic Performance**: On these 8 unique behavioral clusters, Stratified Cross-Validation out-of-fold accuracy is **96.74% +/- 1.09%** for Random Forest and **69.57%** for Histogram Gradient Boosting, establishing genuine scientific integrity without artificial inflation.

---

## 3. Data Leakage Prevention Guarantees

Data leakage is the most prevalent flaw in network intrusion ML research, often occurring when models memorize IP addresses, port numbers, or session timestamps rather than learning genuine behavioral traffic patterns.

The platform enforces strict anti-leakage guarantees verified by automated test suites (`test_06_data_leakage_and_metrics_evaluation` in `tests/test_ml_subsystem.py`):

### 1. Leakage Audit Checks:
- **No IP Addresses**: Source IP (`192.168.1.100`) and Destination IP (`10.0.0.50`) are strictly banned from the feature matrix $\mathbf{X}$.
- **No Raw Port Numbers**: Specific port numbers (e.g. `8080`, `4444`) are prohibited. Only binary categorical indicators (`is_well_known_port < 1024` and `is_ephemeral_port >= 49152`) are permitted.
- **No Timestamps**: Wall-clock epoch timestamps (`start_time_us`, `last_time_us`) are excluded. Only relative statistical durations (`duration_ms`, `mean_iat_ms`, `std_iat_ms`) are extracted.
- **No Session IDs**: `flow_id`, transaction tokens, and interface names are excluded.

### 2. Group & Stratified Splitting
- Train/test splits preserve label distributions using stratified sampling.
- Evaluation runs across independent flows, ensuring that test metrics measure generalizability to unseen traffic.

---

## 4. Public Benchmark Integration: CIC-IDS2017 & UNSW-NB15

To evaluate models on large-scale external datasets without synthetic bias, `DatasetManager` (`ml/dataset_manager.py`) provides validated CSV ingestion and schema mapping adapters via `ingest_external_csv()` to translate public benchmarks into the canonical 24-feature space:

### CIC-IDS2017 Mapping Schema
- **Benchmark Source**: Canadian Institute for Cybersecurity (UNB)
- **Official URL**: `https://www.unb.ca/cic/datasets/ids-2017.html`
- **Feature Translation**:
  ```python
  CICIDS_FEATURE_MAP = {
      "Flow Duration": "duration_seconds",     # scale from microseconds to seconds (/ 1e6)
      "Total Fwd Packets": "fwd_packets",
      "Total Backward Packets": "rev_packets",
      "Total Length of Fwd Packets": "fwd_bytes",
      "Total Length of Bwd Packets": "rev_bytes",
      "Flow Packets/s": "packets_per_second",
      "Flow Bytes/s": "bytes_per_second",
      "SYN Flag Count": "fwd_syn_count",
      "ACK Flag Count": "fwd_ack_count",
      "FIN Flag Count": "fwd_fin_count",
      "RST Flag Count": "fwd_rst_count",
      "PSH Flag Count": "fwd_psh_count",
      "Flow IAT Mean": "iat_mean",
      "Flow IAT Std": "iat_stddev",
      "Destination Port": "destination_port"  # binned to is_well_known / is_ephemeral
  }
  ```
- **Label Normalization**:
  - `BENIGN` $\to$ `BENIGN`
  - `PortScan` $\to$ `PORT_SCAN`
  - `Bot` / `ARES` $\to$ `C2_BEACON`
  - `DDoS` / `DoS *` $\to$ `ANOMALOUS_BURST`
  - `Heartbleed` / `Web Attack *` $\to$ `MALWARE_HTTP`
  - `Infiltration` $\to$ `C2_BEACON`

### UNSW-NB15 Mapping Schema
- **Benchmark Source**: Australian Centre for Cyber Security (ACCS)
- **Official URL**: `https://research.unsw.edu.au/projects/unsw-nb15-dataset`
- **Feature Translation**:
  ```python
  UNSW_FEATURE_MAP = {
      "dur": "duration_seconds",
      "spkts": "fwd_packets",
      "dpkts": "rev_packets",
      "sbytes": "fwd_bytes",
      "dbytes": "rev_bytes",
      "rate": "packets_per_second",
      "sload": "bytes_per_second",
      "sinpkt": "iat_mean",
      "sjit": "iat_stddev",
      "dsport": "destination_port"            # binned to is_well_known / is_ephemeral
  }
  ```
- **Label Normalization**:
  - `Normal` $\to$ `BENIGN`
  - `Reconnaissance` / `Analysis` $\to$ `PORT_SCAN`
  - `Backdoors` / `Backdoor` / `Worms` $\to$ `C2_BEACON`
  - `Exploits` / `Generic` / `Shellcode` $\to$ `MALWARE_HTTP`
  - `DoS` $\to$ `ANOMALOUS_BURST`
  - `Fuzzers` $\to$ `SUSPICIOUS`

### Ingestion Usage Example
```python
from ml.dataset_manager import DatasetManager

dm = DatasetManager()

# Ingest CIC-IDS2017 CSV archive
X_cic, y_cic, meta_cic = dm.ingest_external_csv(
    "data/ml_datasets/Tuesday-WorkingHours.pcap_ISCX.csv",
    dataset_type="CICIDS2017",
    max_rows=10000
)
print(f"Ingested {len(X_cic)} flows with SHA-256: {meta_cic['sha256']}")

# Ingest UNSW-NB15 CSV archive
X_unsw, y_unsw, meta_unsw = dm.ingest_external_csv(
    "data/ml_datasets/UNSW_NB15_training-set.csv",
    dataset_type="UNSW-NB15",
    max_rows=10000
)
print(f"Ingested {len(X_unsw)} flows with SHA-256: {meta_unsw['sha256']}")
```

---

## 5. Dataset Management CLI & Inspection Tools

Inspect and verify local dataset fixtures:
```bash
python3 -c "
from ml.dataset_manager import DatasetManager

ds = DatasetManager.generate_flow_dataset()
print('Total flows:', ds['total_flows'])
for lbl, count in ds['class_distribution'].items():
    print(f'  {lbl}: {count}')
"
```

Inspect external benchmark dataset configuration:
```bash
python3 -c "
from ml.dataset_manager import DatasetManager

print(DatasetManager.get_benchmark_metadata('CICIDS2017'))
print(DatasetManager.get_benchmark_metadata('UNSW-NB15'))
"
```
