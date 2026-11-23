"""
DPI & Packet Analyzer — Network Intrusion Dataset Manager & PCAP Feature Ingestion
==================================================================================
Manages genuine training datasets from:
1. PCAP-derived FlowRecord extraction from labeled captures with grouping metadata.
2. Industry benchmark dataset adapters (CICIDS2017, UNSW-NB15) with schema mapping,
   integrity validation, and reproducible splitting.
"""

import os
import csv
import json
import subprocess
import hashlib
import time
import numpy as np
from typing import List, Dict, Any, Tuple, Optional

from ml.feature_pipeline import FeaturePipeline, FEATURE_NAMES, FEATURE_SCHEMA_VERSION, safe_float, safe_int

CICIDS_REQUIRED_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Label"
]

CICIDS_FEATURE_MAP = {
    "Flow Duration": "duration_seconds",
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
    "Destination Port": "destination_port"
}

CICIDS_LABEL_MAP = {
    "BENIGN": "BENIGN",
    "PortScan": "PORT_SCAN",
    "Bot": "C2_BEACON",
    "ARES": "C2_BEACON",
    "DDoS": "ANOMALOUS_BURST",
    "DoS Hulk": "ANOMALOUS_BURST",
    "DoS GoldenEye": "ANOMALOUS_BURST",
    "DoS slowloris": "ANOMALOUS_BURST",
    "DoS Slowhttptest": "ANOMALOUS_BURST",
    "Heartbleed": "MALWARE_HTTP",
    "Web Attack – Brute Force": "MALWARE_HTTP",
    "Web Attack – XSS": "MALWARE_HTTP",
    "Web Attack – Sql Injection": "MALWARE_HTTP",
    "Infiltration": "C2_BEACON"
}

UNSW_REQUIRED_COLUMNS = [
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes"
]

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
    "dsport": "destination_port"
}

UNSW_LABEL_MAP = {
    "Normal": "BENIGN",
    "Reconnaissance": "PORT_SCAN",
    "Backdoor": "C2_BEACON",
    "Backdoors": "C2_BEACON",
    "Exploits": "MALWARE_HTTP",
    "Generic": "MALWARE_HTTP",
    "DoS": "ANOMALOUS_BURST",
    "Fuzzers": "SUSPICIOUS",
    "Analysis": "PORT_SCAN",
    "Shellcode": "MALWARE_HTTP",
    "Worms": "C2_BEACON"
}

PROJECT_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DATASET_DIR = os.path.join(PROJECT_ROOT, "data", "ml_datasets")

PCAP_GROUND_TRUTH_LABELS = {
    "normal_traffic.pcap": "BENIGN",
    "port_scan_recon.pcap": "PORT_SCAN",
    "dns_anomalies.pcap": "DNS_TUNNEL",
    "beacon_c2.pcap": "C2_BEACON",
    "threat_intel_match.pcap": "MALWARE_HTTP"
}

class DatasetManager:
    """
    Manages genuine training and evaluation datasets with provenance tracking,
    integrity verification, scenario grouping metadata, and schema mapping.
    """
    def __init__(self, dataset_dir: str = DEFAULT_DATASET_DIR):
        self.dataset_dir = dataset_dir
        os.makedirs(self.dataset_dir, exist_ok=True)
        self.feature_pipeline = FeaturePipeline()

    def build_pcap_derived_dataset(self, pcap_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Extract genuine FlowRecords from labeled PCAP fixtures using the compiled
        C++17 DPI Engine, generating a verified ground-truth training dataset with grouping metadata.
        """
        if pcap_dir is None:
            pcap_dir = os.path.join(PROJECT_ROOT, "pcaps")

        engine_bin = os.path.join(PROJECT_ROOT, "bin", "dpi_engine")
        if not os.path.exists(engine_bin):
            raise FileNotFoundError("Engine binary bin/dpi_engine not found. Build with 'make all'.")

        all_flows = []
        labels = []
        source_counts = {}

        for pcap_name, label in PCAP_GROUND_TRUTH_LABELS.items():
            pcap_path = os.path.join(pcap_dir, pcap_name)
            if not os.path.exists(pcap_path):
                continue

            temp_out_dir = f"/tmp/pcap_ds_{os.path.splitext(pcap_name)[0]}"
            os.makedirs(temp_out_dir, exist_ok=True)
            out_pcap = os.path.join(temp_out_dir, "out.pcap")

            # Execute DPI engine to extract flows
            cmd = [
                engine_bin, pcap_path, out_pcap,
                "--analyze-all", temp_out_dir
            ]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode != 0:
                print(f"[DatasetManager] Warning: failed to extract flows from {pcap_name}: {res.stderr}")
                continue

            flows_file = os.path.join(temp_out_dir, "flows.json")
            if os.path.exists(flows_file):
                with open(flows_file, "r", encoding="utf-8") as f:
                    flows = json.load(f)
                for fl in flows:
                    fl["ground_truth_label"] = label
                    fl["source_pcap"] = pcap_name
                    fl["capture_scenario"] = pcap_name.replace(".pcap", "")
                    fl["dataset_origin"] = "DPI_PCAP_EXTRACTOR"
                    fl["feature_schema_version"] = FEATURE_SCHEMA_VERSION
                    all_flows.append(fl)
                    labels.append(label)
                source_counts[pcap_name] = len(flows)

        if not all_flows:
            raise RuntimeError("No flow records could be extracted from PCAP fixtures.")

        # Save dataset to data/ml_datasets/PCAP-DERIVED-FLOWS-v1.json
        dataset_id = "PCAP-DERIVED-FLOWS-v1"
        dataset_path = os.path.join(self.dataset_dir, f"{dataset_id}.json")

        # Feature matrix to check duplicates
        X_temp = self.feature_pipeline.transform_flows(all_flows)
        unique_vectors = len(np.unique(X_temp, axis=0))

        dataset_obj = {
            "dataset_id": dataset_id,
            "schema_version": FEATURE_SCHEMA_VERSION,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_samples": len(all_flows),
            "unique_feature_vectors": unique_vectors,
            "duplicate_feature_vectors": len(all_flows) - unique_vectors,
            "class_distribution": {cls: labels.count(cls) for cls in set(labels)},
            "source_pcaps": source_counts,
            "features": self.feature_pipeline.feature_names,
            "grouping_metadata": {
                "group_keys": ["source_pcap", "capture_scenario"],
                "total_scenarios": len(source_counts),
                "scenario_labels": PCAP_GROUND_TRUTH_LABELS
            },
            "flows": all_flows
        }

        # Calculate SHA256 of dataset
        content_bytes = json.dumps(dataset_obj, indent=2).encode("utf-8")
        sha = hashlib.sha256(content_bytes).hexdigest()
        dataset_obj["sha256"] = sha

        with open(dataset_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(dataset_obj, indent=2))

        return {
            "dataset_id": dataset_id,
            "dataset_path": dataset_path,
            "sha256": sha,
            "total_samples": len(all_flows),
            "unique_feature_vectors": unique_vectors,
            "class_distribution": dataset_obj["class_distribution"],
            "features": self.feature_pipeline.feature_names
        }

    def load_pcap_dataset(self, dataset_id: str = "PCAP-DERIVED-FLOWS-v1") -> Tuple[np.ndarray, np.ndarray, List[Dict[str, Any]]]:
        """
        Load PCAP-derived flow dataset and return (X, y, flows).
        Rebuilds dataset if schema version is outdated or file is missing.
        """
        path = os.path.join(self.dataset_dir, f"{dataset_id}.json")
        rebuild_needed = not os.path.exists(path)

        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("schema_version") != FEATURE_SCHEMA_VERSION:
                    rebuild_needed = True
            except Exception:
                rebuild_needed = True

        if rebuild_needed:
            self.build_pcap_derived_dataset()
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

        flows = data.get("flows", [])
        X = self.feature_pipeline.transform_flows(flows)
        y = np.array([f.get("ground_truth_label", "BENIGN") for f in flows])
        return X, y, flows

    def check_external_dataset_status(self, name: str) -> Dict[str, Any]:
        """
        Inspect availability and metadata of external network intrusion datasets
        (e.g., CICIDS2017, UNSW-NB15) without downloading enormous multi-gigabyte archives.
        """
        known_sources = {
            "CICIDS2017": {
                "full_name": "Canadian Institute for Cybersecurity Intrusion Detection Dataset 2017",
                "description": "Comprehensive labeled flow dataset covering DoS, DDoS, PortScan, Infiltration, Web Attacks",
                "license": "Academic / Non-Commercial Research License",
                "expected_files": ["Tuesday-WorkingHours.pcap_ISCX.csv", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"],
                "url": "https://www.unb.ca/cic/datasets/ids-2017.html"
            },
            "UNSW-NB15": {
                "full_name": "University of New South Wales Cyber Security Dataset 2015",
                "description": "Hybrid realistic benign activities and synthetic modern attack behaviors",
                "license": "Research and Education Use",
                "expected_files": ["UNSW-NB15_1.csv", "UNSW_NB15_training-set.csv"],
                "url": "https://research.unsw.edu.au/projects/unsw-nb15-dataset"
            }
        }

        info = known_sources.get(name.upper(), {
            "full_name": name,
            "description": "External dataset",
            "license": "Custom",
            "expected_files": [],
            "url": "N/A"
        })

        # Check local files in dataset directory
        found_files = []
        for exp in info.get("expected_files", []):
            loc = os.path.join(self.dataset_dir, exp)
            if os.path.exists(loc):
                found_files.append(exp)

        is_available = len(found_files) > 0
        return {
            "dataset_name": name,
            "full_name": info["full_name"],
            "description": info["description"],
            "license": info["license"],
            "is_locally_available": is_available,
            "download_instructions": f"To train on {name}, download the CSV archives from {info['url']} and place them in {self.dataset_dir}.",
            "found_files": found_files
        }

    def ingest_external_csv(
        self,
        filepath: str,
        dataset_type: str,
        max_rows: Optional[int] = None
    ) -> Tuple[np.ndarray, np.ndarray, Dict[str, Any]]:
        """
        Ingest and normalize external benchmark CSV datasets (CIC-IDS2017, UNSW-NB15):
        - Enforces schema validation and missing column rejection.
        - Translates heterogeneous benchmark features to canonical 24-feature space.
        - Normalizes labels to standard NIDS classes (BENIGN, PORT_SCAN, C2_BEACON, etc.).
        - Tracks provenance with SHA-256 digest, row counts, and rejection statistics.
        """
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"External dataset file not found: {filepath}")

        ds_type = dataset_type.upper().replace("-", "_")
        if ds_type not in ("CICIDS2017", "UNSW_NB15"):
            raise ValueError(f"Unsupported dataset type '{dataset_type}'. Supported types: 'CICIDS2017', 'UNSW-NB15'")

        # Compute SHA-256 digest of input file
        sha = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        file_sha = sha.hexdigest()

        # Read CSV header
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            raw_header = next(reader, None)
            if not raw_header:
                raise ValueError(f"CSV file '{filepath}' is empty.")

            clean_header = [col.strip() for col in raw_header]
            col_map = {col: idx for idx, col in enumerate(clean_header)}

            # Validate schema
            if ds_type == "CICIDS2017":
                missing = [col for col in CICIDS_REQUIRED_COLUMNS if col not in col_map]
                if missing:
                    raise ValueError(f"Invalid CICIDS2017 schema in '{filepath}': missing required columns {missing}")
            elif ds_type == "UNSW_NB15":
                missing = [col for col in UNSW_REQUIRED_COLUMNS if col not in col_map]
                has_label = ("attack_cat" in col_map) or ("label" in col_map)
                if missing or not has_label:
                    missing_all = list(missing) + ([] if has_label else ["attack_cat / label"])
                    raise ValueError(f"Invalid UNSW-NB15 schema in '{filepath}': missing required columns {missing_all}")

            X_rows = []
            y_rows = []
            valid_rows = 0
            rejected_rows = 0
            class_counts = {}

            for row_idx, row in enumerate(reader):
                if max_rows is not None and valid_rows >= max_rows:
                    break
                if not row or len(row) < len(clean_header):
                    rejected_rows += 1
                    continue

                def get_val(col_name: str, default: float = 0.0) -> float:
                    if col_name in col_map and col_map[col_name] < len(row):
                        return safe_float(row[col_map[col_name]], default)
                    return default

                try:
                    if ds_type == "CICIDS2017":
                        # Timing & Volume
                        dur_us = get_val("Flow Duration", 0.0)
                        dur_sec = max(0.0, dur_us / 1000000.0)
                        fwd_pkts = get_val("Total Fwd Packets", 0.0)
                        rev_pkts = get_val("Total Backward Packets", 0.0)
                        tot_pkts = fwd_pkts + rev_pkts
                        fwd_bytes = get_val("Total Length of Fwd Packets", 0.0)
                        rev_bytes = get_val("Total Length of Bwd Packets", 0.0)
                        tot_bytes = fwd_bytes + rev_bytes
                        pps = get_val("Flow Packets/s", (tot_pkts / dur_sec) if dur_sec > 0 else 0.0)
                        bps = get_val("Flow Bytes/s", (tot_bytes / dur_sec) if dur_sec > 0 else 0.0)
                        byte_asym = fwd_bytes / (rev_bytes + 1.0)
                        pkt_asym = fwd_pkts / (rev_pkts + 1.0)

                        # Packet size
                        pkt_min = get_val("Fwd Packet Length Min", 0.0)
                        pkt_max = max(get_val("Fwd Packet Length Max", 0.0), get_val("Bwd Packet Length Max", 0.0))
                        pkt_mean = get_val("Average Packet Size", (tot_bytes / tot_pkts) if tot_pkts > 0 else 0.0)
                        pkt_std = get_val("Packet Length Std", 0.0)

                        # IAT
                        iat_m = get_val("Flow IAT Mean", 0.0)
                        iat_s = get_val("Flow IAT Std", 0.0)

                        # TCP Flags
                        fwd_syn = get_val("SYN Flag Count", get_val("Fwd PSH Flags", 0.0))
                        fwd_ack = get_val("ACK Flag Count", 0.0)
                        fwd_fin = get_val("FIN Flag Count", 0.0)
                        fwd_rst = get_val("RST Flag Count", 0.0)
                        fwd_psh = get_val("PSH Flag Count", 0.0)

                        # Port ranges (NO RAW PORTS)
                        dst_port = int(get_val("Destination Port", 0.0))
                        is_well_known = 1.0 if (0 < dst_port < 1024) else 0.0
                        is_ephemeral = 1.0 if (dst_port >= 49152) else 0.0

                        raw_lbl = row[col_map["Label"]].strip()
                        norm_lbl = CICIDS_LABEL_MAP.get(raw_lbl, "SUSPICIOUS" if raw_lbl != "BENIGN" else "BENIGN")

                    else: # UNSW_NB15
                        dur_sec = max(0.0, get_val("dur", 0.0))
                        fwd_pkts = get_val("spkts", 0.0)
                        rev_pkts = get_val("dpkts", 0.0)
                        tot_pkts = fwd_pkts + rev_pkts
                        fwd_bytes = get_val("sbytes", 0.0)
                        rev_bytes = get_val("dbytes", 0.0)
                        tot_bytes = fwd_bytes + rev_bytes
                        pps = get_val("rate", (tot_pkts / dur_sec) if dur_sec > 0 else 0.0)
                        bps = get_val("sload", (tot_bytes / dur_sec) if dur_sec > 0 else 0.0)
                        byte_asym = fwd_bytes / (rev_bytes + 1.0)
                        pkt_asym = fwd_pkts / (rev_pkts + 1.0)

                        pkt_min = get_val("smean", 0.0)
                        pkt_max = max(get_val("smean", 0.0), get_val("dmean", 0.0))
                        pkt_mean = (tot_bytes / tot_pkts) if tot_pkts > 0 else 0.0
                        pkt_std = 0.0

                        iat_m = get_val("sinpkt", get_val("synack", 0.0))
                        iat_s = get_val("sjit", get_val("tcprtt", 0.0))

                        fwd_syn = 1.0 if get_val("synack", 0.0) > 0 else 0.0
                        fwd_ack = 1.0 if get_val("ackdat", 0.0) > 0 else 0.0
                        fwd_fin = 0.0
                        fwd_rst = 0.0
                        fwd_psh = 0.0

                        dst_port = int(get_val("dsport", 0.0))
                        is_well_known = 1.0 if (0 < dst_port < 1024) else 0.0
                        is_ephemeral = 1.0 if (dst_port >= 49152) else 0.0

                        if "attack_cat" in col_map:
                            raw_lbl = row[col_map["attack_cat"]].strip()
                        else:
                            lbl_num = get_val("label", 0.0)
                            raw_lbl = "Normal" if lbl_num == 0 else "Generic"
                        norm_lbl = UNSW_LABEL_MAP.get(raw_lbl, "SUSPICIOUS" if raw_lbl not in ("Normal", "0", "") else "BENIGN")

                    vector = [
                        dur_sec,
                        tot_pkts,
                        tot_bytes,
                        pps,
                        bps,
                        byte_asym,
                        pkt_asym,
                        fwd_pkts,
                        fwd_bytes,
                        rev_pkts,
                        rev_bytes,
                        pkt_min,
                        pkt_max,
                        pkt_mean,
                        pkt_std,
                        iat_m,
                        iat_s,
                        fwd_syn,
                        fwd_ack,
                        fwd_fin,
                        fwd_rst,
                        fwd_psh,
                        is_well_known,
                        is_ephemeral
                    ]
                    assert len(vector) == len(FEATURE_NAMES)
                    X_rows.append(vector)
                    y_rows.append(norm_lbl)
                    class_counts[norm_lbl] = class_counts.get(norm_lbl, 0) + 1
                    valid_rows += 1
                except Exception:
                    rejected_rows += 1

        X_arr = np.array(X_rows, dtype=np.float64)
        y_arr = np.array(y_rows)

        metadata = {
            "source_file": filepath,
            "sha256": file_sha,
            "dataset_type": ds_type,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "feature_count": len(FEATURE_NAMES),
            "features": FEATURE_NAMES,
            "total_rows_read": valid_rows + rejected_rows,
            "valid_rows": valid_rows,
            "rejected_rows": rejected_rows,
            "class_distribution": class_counts,
            "ingested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        return X_arr, y_arr, metadata
