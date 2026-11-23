"""
DPI & Packet Analyzer — Unsupervised Network Anomaly Detection
=============================================================
Provides unsupervised network flow anomaly detection using Isolation Forest
and statistical baseline profiling. Detects deviations from normal traffic
without requiring labeled attack datasets.
"""

import os
import json
import time
import hashlib
import numpy as np
import joblib
from typing import List, Dict, Any, Tuple, Optional

from sklearn.ensemble import IsolationForest
from ml.feature_pipeline import FeaturePipeline, FEATURE_NAMES, FEATURE_SCHEMA_VERSION

MIN_BASELINE_SAMPLES = 10

class UnsupervisedAnomalyDetector:
    """
    Unsupervised network flow anomaly detector.
    Utilizes an ensemble Isolation Forest combined with statistical baseline z-score
    attribution to identify unusual volume, rate, asymmetry, and flag behaviors.

    Enforces minimum sample sizes to prevent fragile baseline fitting.
    Explicitly documents that anomaly scores are heuristic distance indices, NOT probabilities.
    """
    def __init__(
        self,
        model_name: str = "FlowAnomaly-IsolationForest",
        version: str = "1.0.0",
        contamination: float = 0.05,
        threshold: float = 0.65,
        min_baseline_samples: int = MIN_BASELINE_SAMPLES,
        random_state: int = 42
    ):
        self.model_name = model_name
        self.version = version
        self.contamination = contamination
        self.threshold = threshold
        self.min_baseline_samples = min_baseline_samples
        self.random_state = random_state
        self.feature_pipeline = FeaturePipeline()
        self.baseline_stats: Dict[str, Dict[str, float]] = {}
        self.training_metadata: Dict[str, Any] = {}
        self.is_trained = False
        self.status = "BASELINE_NOT_TRAINED"

        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100,
            n_jobs=-1
        )

    def fit_baseline(self, flows: List[Dict[str, Any]], dataset_name: str = "Normal Baseline") -> Dict[str, Any]:
        """
        Learn baseline statistical distributions and train Isolation Forest on normal traffic flows.
        Requires at least min_baseline_samples (>= 10) to prevent brittle baseline variance.
        """
        if len(flows) < self.min_baseline_samples:
            self.is_trained = False
            self.status = "INSUFFICIENT_BASELINE_DATA"
            raise ValueError(
                f"Baseline training requires at least {self.min_baseline_samples} normal flow records; "
                f"received only {len(flows)}. Training rejected to prevent fragile baseline profiling."
            )

        start_time = time.time()
        X = self.feature_pipeline.transform_flows(flows)
        self.feature_pipeline.fit(X)
        X_norm = self.feature_pipeline.normalize(X)

        # Train Isolation Forest
        self.model.fit(X_norm)
        train_duration = time.time() - start_time
        self.is_trained = True
        self.status = "BASELINE_PROFILED"

        # Compute empirical baseline statistics per feature for explainability
        self.baseline_stats = {}
        for idx, feat_name in enumerate(self.feature_pipeline.feature_names):
            vals = X[:, idx]
            self.baseline_stats[feat_name] = {
                "mean": round(float(np.mean(vals)), 4),
                "std": round(float(np.std(vals)) if np.std(vals) > 0 else 1.0, 4),
                "min": round(float(np.min(vals)), 4),
                "max": round(float(np.max(vals)), 4)
            }

        self.training_metadata = {
            "model_name": self.model_name,
            "version": self.version,
            "algorithm": "isolation_forest",
            "contamination": self.contamination,
            "threshold": self.threshold,
            "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "train_duration_seconds": round(train_duration, 4),
            "baseline_samples": len(flows),
            "dataset_name": dataset_name,
            "baseline_feature_profiles": self.baseline_stats
        }
        return self.training_metadata

    def score_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compute anomaly score for a single flow, normalize to [0.0, 1.0],
        and extract top contributing deviation factors.
        """
        if not self.is_trained:
            return {
                "model_name": self.model_name,
                "version": self.version,
                "flow_id": flow.get("flow_id", 0),
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "status": "INSUFFICIENT_BASELINE_DATA",
                "verdict": "MODEL_OFFLINE_INSUFFICIENT_BASELINE",
                "threshold": self.threshold,
                "is_calibrated": False,
                "score_type": "HEURISTIC_ANOMALY_INDEX",
                "contributing_deviations": [],
                "explanation": f"Anomaly detector offline: requires legitimate baseline capture of >= {self.min_baseline_samples} benign flows."
            }

        vec = np.array([self.feature_pipeline.extract_from_flow(flow)], dtype=np.float32)
        vec_norm = self.feature_pipeline.normalize(vec)

        # Feature contribution attribution via z-scores against learned baseline
        contributions = self._attribute_deviations(vec[0])

        # Isolation forest raw decision function (lower = more abnormal)
        raw_score = float(self.model.decision_function(vec_norm)[0])
        if_score = max(0.0, min(1.0, 0.5 - raw_score))

        # Statistical z-score anomaly component
        max_z = max([c["z_score"] for c in contributions]) if contributions else 0.0
        mean_z = np.mean([c["z_score"] for c in contributions]) if contributions else 0.0
        z_score_component = min(1.0, (max_z / 4.0) * 0.7 + (float(mean_z) / 3.0) * 0.3)

        # Integrated normalized anomaly score [0.0, 1.0]
        norm_score = round(max(if_score, z_score_component), 4)
        is_anomaly = norm_score >= self.threshold

        return {
            "model_name": self.model_name,
            "version": self.version,
            "flow_id": flow.get("flow_id", 0),
            "source_ip": flow.get("source_ip", ""),
            "destination_ip": flow.get("destination_ip", ""),
            "destination_port": flow.get("destination_port", 0),
            "protocol": flow.get("protocol", ""),
            "raw_decision_score": round(raw_score, 4),
            "anomaly_score": norm_score,
            "is_anomaly": is_anomaly,
            "verdict": "ANOMALOUS_BEHAVIOR_OBSERVED (ANOMALY != CONFIRMED MALICIOUS)" if is_anomaly else "NORMAL_TRAFFIC_PROFILE",
            "threshold": self.threshold,
            "threshold_status": "DEFAULT_UNCHECKED_HEURISTIC (0.65)",
            "is_calibrated": False,
            "score_type": "HEURISTIC_ANOMALY_INDEX",
            "contributing_deviations": contributions,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

    def score_batch(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score a collection of flow records."""
        return [self.score_flow(f) for f in flows]

    def _attribute_deviations(self, raw_features: np.ndarray) -> List[Dict[str, Any]]:
        """Calculate per-feature deviation z-scores against baseline distribution."""
        deviations = []
        for idx, feat_name in enumerate(self.feature_pipeline.feature_names):
            val = float(raw_features[idx])
            b_stat = self.baseline_stats.get(feat_name, {"mean": 0.0, "std": 1.0})
            mean = b_stat["mean"]
            std = b_stat["std"] if b_stat["std"] > 0 else 1.0
            z_score = abs(val - mean) / std

            if z_score >= 1.5: # Meaningful statistical deviation
                deviations.append({
                    "feature": feat_name,
                    "observed_value": round(val, 2),
                    "baseline_mean": mean,
                    "z_score": round(float(z_score), 2),
                    "explanation": f"Feature '{feat_name}'={round(val, 2)} deviates {round(z_score, 1)} standard deviations from baseline mean ({mean})"
                })

        # Return top 4 most extreme deviations
        deviations.sort(key=lambda x: x["z_score"], reverse=True)
        return deviations[:4]

    def save(self, directory: str) -> Tuple[str, str]:
        """Save detector artifact and JSON manifest with SHA256 integrity check and schema versioning."""
        os.makedirs(directory, exist_ok=True)
        model_filename = f"{self.model_name}_{self.version}.joblib"
        manifest_filename = f"{self.model_name}_{self.version}_manifest.json"

        model_path = os.path.join(directory, model_filename)
        manifest_path = os.path.join(directory, manifest_filename)

        payload = {
            "schema_version": FEATURE_SCHEMA_VERSION,
            "model": self.model,
            "pipeline": self.feature_pipeline.to_dict(),
            "baseline_stats": self.baseline_stats,
            "contamination": self.contamination,
            "threshold": self.threshold,
            "random_state": self.random_state
        }
        joblib.dump(payload, model_path, compress=3)

        sha = hashlib.sha256()
        with open(model_path, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        artifact_hash = sha.hexdigest()

        manifest = {
            "schema_version": FEATURE_SCHEMA_VERSION,
            "model_name": self.model_name,
            "version": self.version,
            "algorithm": "isolation_forest",
            "artifact_file": model_filename,
            "sha256": artifact_hash,
            "is_trained": self.is_trained,
            "metadata": self.training_metadata
        }
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return model_path, manifest_path

    @classmethod
    def load(cls, directory: str, model_name: str, version: str) -> "UnsupervisedAnomalyDetector":
        """Load detector artifact with cryptographic integrity check and schema verification."""
        model_filename = f"{model_name}_{version}.joblib"
        manifest_filename = f"{model_name}_{version}_manifest.json"

        model_path = os.path.join(directory, model_filename)
        manifest_path = os.path.join(directory, manifest_filename)

        if not os.path.exists(model_path) or not os.path.exists(manifest_path):
            raise FileNotFoundError(f"Anomaly detector files not found for {model_name} v{version}")

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        manifest_schema = manifest.get("schema_version")
        if manifest_schema != FEATURE_SCHEMA_VERSION:
            raise ValueError(
                f"Incompatible anomaly detector schema version: {manifest_schema} (expected {FEATURE_SCHEMA_VERSION}). "
                f"Artifact must be retrained."
            )

        sha = hashlib.sha256()
        with open(model_path, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        if sha.hexdigest() != manifest.get("sha256"):
            raise ValueError(f"Integrity check failed for {model_filename}!")

        payload = joblib.load(model_path)
        if payload.get("schema_version") != FEATURE_SCHEMA_VERSION:
            raise ValueError(
                f"Incompatible payload schema version: {payload.get('schema_version')} (expected {FEATURE_SCHEMA_VERSION})."
            )

        inst = cls(
            model_name=manifest["model_name"],
            version=manifest["version"],
            contamination=payload.get("contamination", 0.05),
            threshold=payload.get("threshold", 0.65),
            random_state=payload.get("random_state", 42)
        )
        inst.model = payload["model"]
        inst.feature_pipeline = FeaturePipeline.from_dict(payload["pipeline"])
        inst.baseline_stats = payload.get("baseline_stats", {})
        inst.is_trained = manifest.get("is_trained", True)
        inst.training_metadata = manifest.get("metadata", {})
        return inst
