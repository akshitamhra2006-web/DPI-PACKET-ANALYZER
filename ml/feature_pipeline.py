"""
DPI & Packet Analyzer — Flow Feature Extraction & Preprocessing Pipeline
========================================================================
Extracts, validates, normalizes, and encodes statistical network flow features
derived from C++17 FlowRecord structures for machine learning model training
and real-time inference.

Schema Version 2.0.0 (Remediated):
- Strictly excludes raw source/destination ports, IP addresses, and timestamps.
- Feature 22: is_well_known_port (binary indicator: 1.0 if 0 < dst_port < 1024 else 0.0)
- Feature 23: is_ephemeral_port (binary indicator: 1.0 if dst_port >= 49152 else 0.0)
"""

import json
import math
import numpy as np
from typing import List, Dict, Any, Tuple, Optional

FEATURE_SCHEMA_VERSION = "2.0.0"

# Banned identity and raw locator attributes
BANNED_FEATURE_FIELDS = {
    "source_ip", "src_ip",
    "destination_ip", "dst_ip",
    "source_port", "src_port",
    "destination_port", "dst_port",
    "flow_id", "timestamp", "start_time_us", "last_time_us"
}

# Canonical feature column names in deterministic order (24 Features)
FEATURE_NAMES = [
    "duration_seconds",
    "total_packets",
    "total_bytes",
    "packets_per_second",
    "bytes_per_second",
    "byte_asymmetry_ratio",
    "packet_asymmetry_ratio",
    "fwd_packets",
    "fwd_bytes",
    "rev_packets",
    "rev_bytes",
    "pkt_size_min",
    "pkt_size_max",
    "pkt_size_mean",
    "pkt_size_stddev",
    "iat_mean",
    "iat_stddev",
    "fwd_syn_count",
    "fwd_ack_count",
    "fwd_fin_count",
    "fwd_rst_count",
    "fwd_psh_count",
    "is_well_known_port",
    "is_ephemeral_port"
]

def safe_float(val: Any, default: float = 0.0) -> float:
    """Convert value to float, replacing NaN, inf, and None with default."""
    if val is None:
        return default
    try:
        f = float(val)
        if math.isnan(f) or math.isinf(f):
            return default
        return f
    except (ValueError, TypeError):
        return default

def safe_int(val: Any, default: int = 0) -> int:
    """Convert value to int, replacing invalid types with default."""
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default

class FeaturePipeline:
    """
    Robust feature extraction and normalization pipeline for network flow records.
    Enforces strict feature schema versioning and prevents identity leakage.
    """
    def __init__(self, feature_names: Optional[List[str]] = None):
        self.schema_version = FEATURE_SCHEMA_VERSION
        self.feature_names = feature_names or list(FEATURE_NAMES)
        self.validate_feature_names(self.feature_names)
        self.mean_ = None
        self.scale_ = None
        self.is_fitted = False

    @staticmethod
    def validate_feature_names(feature_names: List[str]):
        """Ensure no banned locator or identity fields exist in the schema."""
        for f in feature_names:
            if f.lower() in BANNED_FEATURE_FIELDS:
                raise ValueError(f"CRITICAL LEAKAGE DETECTED: Banned identity feature '{f}' present in feature schema!")
        if feature_names != FEATURE_NAMES:
            raise ValueError(f"Feature schema mismatch: expected {FEATURE_NAMES}, got {feature_names}")

    def extract_from_flow(self, flow: Dict[str, Any]) -> List[float]:
        """
        Extract numerical feature vector from a single serialized FlowRecord dictionary.
        Handles nested JSON keys from C++ flow export.
        Ensures NO raw IP or port numbers enter the vector.
        """
        # Timing & Volume
        duration = safe_float(flow.get("duration_seconds", 0.0))
        total_packets = safe_int(flow.get("total_packets", 0))
        total_bytes = safe_int(flow.get("total_bytes", 0))

        pps = safe_float(flow.get("packets_per_second", 0.0))
        bps = safe_float(flow.get("bytes_per_second", 0.0))
        byte_asym = safe_float(flow.get("byte_asymmetry_ratio", 1.0))
        pkt_asym = safe_float(flow.get("packet_asymmetry_ratio", 1.0))

        # Directional statistics
        fwd = flow.get("forward", {})
        rev = flow.get("reverse", {})

        fwd_packets = safe_int(fwd.get("packets", flow.get("fwd_packets", 0)))
        fwd_bytes = safe_int(fwd.get("bytes", flow.get("fwd_bytes", 0)))
        rev_packets = safe_int(rev.get("packets", flow.get("rev_packets", 0)))
        rev_bytes = safe_int(rev.get("bytes", flow.get("rev_bytes", 0)))

        # Packet size statistics
        pkt_size = flow.get("packet_size", {})
        pkt_size_min = safe_float(pkt_size.get("min", 0.0))
        pkt_size_max = safe_float(pkt_size.get("max", 0.0))
        pkt_size_mean = safe_float(pkt_size.get("mean", 0.0))
        pkt_size_std = safe_float(pkt_size.get("stddev", 0.0))

        # IAT statistics
        iat = flow.get("iat_microseconds", {})
        iat_mean = safe_float(iat.get("mean", 0.0))
        iat_std = safe_float(iat.get("stddev", 0.0))

        # TCP flags (forward direction)
        fwd_syn = safe_int(fwd.get("syn", 0))
        fwd_ack = safe_int(fwd.get("ack", 0))
        fwd_fin = safe_int(fwd.get("fin", 0))
        fwd_rst = safe_int(fwd.get("rst", 0))
        fwd_psh = safe_int(fwd.get("psh", 0))

        # Generalized Port Range Indicators (NO RAW PORT NUMBERS)
        dst_port = safe_int(flow.get("destination_port", flow.get("dst_port", 0)))
        is_well_known = 1.0 if (0 < dst_port < 1024) else 0.0
        is_ephemeral = 1.0 if (dst_port >= 49152) else 0.0

        return [
            duration,
            float(total_packets),
            float(total_bytes),
            pps,
            bps,
            byte_asym,
            pkt_asym,
            float(fwd_packets),
            float(fwd_bytes),
            float(rev_packets),
            float(rev_bytes),
            pkt_size_min,
            pkt_size_max,
            pkt_size_mean,
            pkt_size_std,
            iat_mean,
            iat_std,
            float(fwd_syn),
            float(fwd_ack),
            float(fwd_fin),
            float(fwd_rst),
            float(fwd_psh),
            is_well_known,
            is_ephemeral
        ]

    def transform_flows(self, flows: List[Dict[str, Any]]) -> np.ndarray:
        """Transform a list of flow records into a 2D numpy array [n_samples, n_features]."""
        if not flows:
            return np.empty((0, len(self.feature_names)), dtype=np.float32)

        data = [self.extract_from_flow(f) for f in flows]
        arr = np.array(data, dtype=np.float32)
        # Final safety check against NaNs or infinities
        arr = np.nan_to_num(arr, nan=0.0, posinf=1e6, neginf=-1e6)
        return arr

    def fit(self, X: np.ndarray) -> "FeaturePipeline":
        """Compute mean and standard deviation for standardization."""
        if X.shape[0] == 0:
            raise ValueError("Cannot fit FeaturePipeline with 0 samples")

        self.mean_ = np.mean(X, axis=0)
        std = np.std(X, axis=0)
        # Avoid division by zero for invariant features
        std[std == 0.0] = 1.0
        self.scale_ = std
        self.is_fitted = True
        return self

    def normalize(self, X: np.ndarray) -> np.ndarray:
        """Apply z-score normalization using fitted parameters."""
        if not self.is_fitted:
            return X
        return (X - self.mean_) / self.scale_

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        """Fit scaler and transform in one step."""
        return self.fit(X).normalize(X)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize pipeline configuration and parameters."""
        return {
            "schema_version": self.schema_version,
            "feature_names": self.feature_names,
            "is_fitted": self.is_fitted,
            "mean": self.mean_.tolist() if self.mean_ is not None else None,
            "scale": self.scale_.tolist() if self.scale_ is not None else None
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FeaturePipeline":
        """Deserialize pipeline from dictionary with schema verification."""
        version = d.get("schema_version", "1.0.0")
        if version != FEATURE_SCHEMA_VERSION:
            raise ValueError(f"Incompatible FeaturePipeline schema version: {version}. Expected {FEATURE_SCHEMA_VERSION}")

        feature_names = d.get("feature_names", FEATURE_NAMES)
        cls.validate_feature_names(feature_names)

        p = cls(feature_names=feature_names)
        p.is_fitted = d.get("is_fitted", False)
        if d.get("mean") is not None:
            p.mean_ = np.array(d["mean"], dtype=np.float32)
        if d.get("scale") is not None:
            p.scale_ = np.array(d["scale"], dtype=np.float32)
        return p
