"""
DPI & Packet Analyzer — Supervised Machine Learning Intrusion Detection Models
==============================================================================
Provides trainable, explainable supervised classifiers (Random Forest,
HistGradientBoosting) for binary and multiclass network intrusion classification.
"""

import os
import json
import time
import hashlib
import hmac
import numpy as np
import joblib
from typing import List, Dict, Any, Tuple, Optional

from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from ml.feature_pipeline import FeaturePipeline, FEATURE_NAMES, FEATURE_SCHEMA_VERSION

DEFAULT_CLASSES = [
    "BENIGN",
    "PORT_SCAN",
    "C2_BEACON",
    "DNS_TUNNEL",
    "MALWARE_HTTP",
    "SUSPICIOUS"
]

class SupervisedIDSModel:
    """
    Supervised Machine Learning Intrusion Detection Model wrapper.
    Supports Random Forest and HistGradientBoosting with probability calibration,
    feature importance, and provenance tracking.
    """
    def __init__(
        self,
        model_name: str = "NIDS-RandomForest",
        version: str = "1.0.0",
        algorithm: str = "random_forest",
        classes: Optional[List[str]] = None,
        random_state: int = 42
    ):
        self.model_name = model_name
        self.version = version
        self.algorithm = algorithm.lower()
        self.classes = classes or list(DEFAULT_CLASSES)
        self.random_state = random_state
        self.feature_pipeline = FeaturePipeline()
        self.training_metadata: Dict[str, Any] = {}
        self.is_trained = False

        if self.algorithm == "hist_gradient_boosting":
            self.clf = HistGradientBoostingClassifier(
                random_state=self.random_state,
                max_iter=100,
                max_depth=8,
                early_stopping=False
            )
        else: # default: random_forest
            self.clf = RandomForestClassifier(
                n_estimators=100,
                max_depth=12,
                class_weight="balanced",
                random_state=self.random_state,
                n_jobs=-1
            )

    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        dataset_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Train the classifier on extracted flow features and target class labels.
        """
        start_time = time.time()
        # Fit feature pipeline
        self.feature_pipeline.fit(X)
        X_norm = self.feature_pipeline.normalize(X)

        # Train classifier
        self.clf.fit(X_norm, y)
        train_duration = time.time() - start_time
        self.is_trained = True

        # Compute feature importances if supported
        feature_importances = {}
        if hasattr(self.clf, "feature_importances_"):
            for name, imp in zip(self.feature_pipeline.feature_names, self.clf.feature_importances_):
                feature_importances[name] = round(float(imp), 4)

        # Record training metadata
        self.training_metadata = {
            "model_name": self.model_name,
            "version": self.version,
            "algorithm": self.algorithm,
            "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "train_duration_seconds": round(train_duration, 4),
            "samples_trained": int(X.shape[0]),
            "feature_count": int(X.shape[1]),
            "classes": [str(c) for c in getattr(self.clf, "classes_", self.classes)],
            "feature_importances": feature_importances,
            "dataset_info": dataset_info or {}
        }
        return self.training_metadata

    def predict_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run inference on a single flow record and return explainable prediction.
        """
        if not self.is_trained:
            return {
                "model_name": self.model_name,
                "version": self.version,
                "status": "MODEL_NOT_TRAINED",
                "predicted_class": "UNKNOWN",
                "confidence": 0.0,
                "flow_id": flow.get("flow_id", 0)
            }

        vec = np.array([self.feature_pipeline.extract_from_flow(flow)], dtype=np.float32)
        vec_norm = self.feature_pipeline.normalize(vec)

        # Prediction and probabilities
        pred_label = self.clf.predict(vec_norm)[0]
        probs = {}
        confidence = 0.0
        if hasattr(self.clf, "predict_proba"):
            p = self.clf.predict_proba(vec_norm)[0]
            for cls_name, prob in zip(self.clf.classes_, p):
                probs[str(cls_name)] = round(float(prob), 4)
            confidence = probs.get(str(pred_label), 0.0)

        # Feature explanation: identify top features driving this prediction
        top_features = self._explain_prediction(vec[0], str(pred_label))

        return {
            "model_name": self.model_name,
            "model_version": self.version,
            "flow_id": flow.get("flow_id", 0),
            "source_ip": flow.get("source_ip", ""),
            "destination_ip": flow.get("destination_ip", ""),
            "destination_port": flow.get("destination_port", 0),
            "protocol": flow.get("protocol", ""),
            "predicted_class": str(pred_label),
            "is_intrusion": str(pred_label).upper() != "BENIGN",
            "confidence": confidence,
            "class_probabilities": probs,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "feature_explanation": top_features,
            "provenance": {
                "algorithm": self.algorithm,
                "random_state": self.random_state,
                "trained_at": self.training_metadata.get("trained_at", "N/A")
            }
        }

    def predict_batch(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run inference across a batch of flow records."""
        return [self.predict_flow(f) for f in flows]

    def _explain_prediction(self, raw_features: np.ndarray, pred_class: str) -> List[Dict[str, Any]]:
        """Generate human-interpretable feature contribution summary."""
        explanations = []
        importances = self.training_metadata.get("feature_importances", {})
        # Sort features by global importance and magnitude
        sorted_feats = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:4]

        for feat_name, imp in sorted_feats:
            if feat_name in self.feature_pipeline.feature_names:
                idx = self.feature_pipeline.feature_names.index(feat_name)
                val = float(raw_features[idx])
                explanations.append({
                    "feature": feat_name,
                    "value": round(val, 2),
                    "importance_weight": imp,
                    "reason": f"{feat_name}={round(val, 2)} (weight {imp})"
                })
        return explanations

    def save(self, directory: str, hmac_key: Optional[bytes] = None) -> Tuple[str, str]:
        """
        Save model artifact and verified JSON manifest with SHA256 integrity hash.
        Optionally signs the manifest with an HMAC secret key for tamper-proofing.
        """
        os.makedirs(directory, exist_ok=True)
        model_filename = f"{self.model_name}_{self.version}.joblib"
        manifest_filename = f"{self.model_name}_{self.version}_manifest.json"

        model_path = os.path.join(directory, model_filename)
        manifest_path = os.path.join(directory, manifest_filename)

        # Save model and pipeline
        payload = {
            "schema_version": FEATURE_SCHEMA_VERSION,
            "clf": self.clf,
            "pipeline": self.feature_pipeline.to_dict(),
            "classes": self.classes,
            "algorithm": self.algorithm,
            "random_state": self.random_state
        }
        joblib.dump(payload, model_path, compress=3)

        # Compute SHA256 of saved binary artifact
        sha = hashlib.sha256()
        with open(model_path, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        artifact_hash = sha.hexdigest()

        # Save manifest
        manifest = {
            "schema_version": FEATURE_SCHEMA_VERSION,
            "model_name": self.model_name,
            "version": self.version,
            "algorithm": self.algorithm,
            "artifact_file": model_filename,
            "sha256": artifact_hash,
            "is_trained": self.is_trained,
            "metadata": self.training_metadata
        }

        # Optional HMAC signature
        if hmac_key is not None:
            if isinstance(hmac_key, str):
                hmac_key = hmac_key.encode("utf-8")
            manifest["hmac_sha256"] = hmac.new(hmac_key, artifact_hash.encode("utf-8"), hashlib.sha256).hexdigest()

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return model_path, manifest_path

    @classmethod
    def load(cls, directory: str, model_name: str, version: str, hmac_key: Optional[bytes] = None) -> "SupervisedIDSModel":
        """
        Load model artifact with cryptographic integrity check, schema compatibility validation,
        and optional HMAC authenticity verification.
        """
        model_filename = f"{model_name}_{version}.joblib"
        manifest_filename = f"{model_name}_{version}_manifest.json"

        model_path = os.path.join(directory, model_filename)
        manifest_path = os.path.join(directory, manifest_filename)

        if not os.path.exists(model_path) or not os.path.exists(manifest_path):
            raise FileNotFoundError(f"Model files not found for {model_name} v{version}")

        # Verify checksum against manifest
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        manifest_schema = manifest.get("schema_version")
        if manifest_schema != FEATURE_SCHEMA_VERSION:
            raise ValueError(
                f"Incompatible model schema version: {manifest_schema} (expected {FEATURE_SCHEMA_VERSION}). "
                f"Model was trained with incompatible feature definitions and must be retrained."
            )

        sha = hashlib.sha256()
        with open(model_path, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        calc_hash = sha.hexdigest()

        if calc_hash != manifest.get("sha256"):
            raise ValueError(f"Integrity check failed for {model_filename}: hash mismatch!")

        # Optional HMAC verification
        if hmac_key is not None:
            if isinstance(hmac_key, str):
                hmac_key = hmac_key.encode("utf-8")
            expected_hmac = manifest.get("hmac_sha256")
            if not expected_hmac:
                raise ValueError(f"HMAC authentication requested, but manifest for {model_filename} contains no HMAC signature!")
            calc_hmac = hmac.new(hmac_key, calc_hash.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(calc_hmac, expected_hmac):
                raise ValueError(f"Cryptographic authentication failed for {model_filename}: HMAC signature mismatch!")

        # Load verified artifact
        payload = joblib.load(model_path)
        if payload.get("schema_version") != FEATURE_SCHEMA_VERSION:
            raise ValueError(
                f"Incompatible payload schema version: {payload.get('schema_version')} (expected {FEATURE_SCHEMA_VERSION})."
            )

        inst = cls(
            model_name=manifest["model_name"],
            version=manifest["version"],
            algorithm=payload.get("algorithm", "random_forest"),
            classes=payload.get("classes", DEFAULT_CLASSES),
            random_state=payload.get("random_state", 42)
        )
        inst.clf = payload["clf"]
        inst.feature_pipeline = FeaturePipeline.from_dict(payload["pipeline"])
        inst.is_trained = manifest.get("is_trained", True)
        inst.training_metadata = manifest.get("metadata", {})
        return inst
