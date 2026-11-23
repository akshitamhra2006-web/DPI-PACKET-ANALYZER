"""
DPI & Packet Analyzer — Machine Learning Model Registry & Execution Manager
===========================================================================
Central lifecycle manager for loading, training, serving, and inspecting
versioned supervised IDS and unsupervised anomaly models.

Schema Version 2.0.0:
- Uses Stratified Cross-Validation instead of resubstitution.
- Enforces minimum sample size for unsupervised anomaly baseline (>= 10 flows).
- Cryptographic SHA-256 and feature schema verification on all models.
"""

import os
import json
import time
import numpy as np
from typing import List, Dict, Any, Tuple, Optional

from ml.models import SupervisedIDSModel
from ml.anomaly_detector import UnsupervisedAnomalyDetector, MIN_BASELINE_SAMPLES
from ml.dataset_manager import DatasetManager
from ml.experiment_framework import ExperimentRunner
from ml.explainability import ThreatExplainabilityEngine
from ml.feature_pipeline import FEATURE_SCHEMA_VERSION

PROJECT_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
SUPERVISED_DIR = os.path.join(MODELS_DIR, "supervised")
ANOMALY_DIR = os.path.join(MODELS_DIR, "anomaly")
EXPERIMENTS_FILE = os.path.join(MODELS_DIR, "experiment_history.json")

CURRENT_MODEL_VERSION = "2.0.0"

class ModelRegistry:
    """
    Manages active ML model instances, model manifests, versioned artifact storage,
    and automatic initialization on platform startup with strict validation.
    """
    def __init__(self, models_dir: str = MODELS_DIR):
        self.models_dir = models_dir
        self.supervised_dir = os.path.join(models_dir, "supervised")
        self.anomaly_dir = os.path.join(models_dir, "anomaly")
        os.makedirs(self.supervised_dir, exist_ok=True)
        os.makedirs(self.anomaly_dir, exist_ok=True)

        self.supervised_model: Optional[SupervisedIDSModel] = None
        self.anomaly_detector: Optional[UnsupervisedAnomalyDetector] = None
        self.dataset_manager = DatasetManager()
        self.experiment_history: List[Dict[str, Any]] = []

        self.load_or_initialize_models()

    def load_or_initialize_models(self):
        """
        Attempt to load existing trained models matching current schema version (2.0.0),
        or initialize and train baseline models using cross-validation.
        """
        sup_name = "NIDS-RandomForest"
        sup_ver = CURRENT_MODEL_VERSION
        try:
            self.supervised_model = SupervisedIDSModel.load(self.supervised_dir, sup_name, sup_ver)
            print(f"[ModelRegistry] Loaded supervised model: {sup_name} v{sup_ver}")
        except Exception as e:
            print(f"[ModelRegistry] No compatible supervised model v{sup_ver} found ({e}); training baseline...")
            self._train_default_supervised()

        anom_name = "FlowAnomaly-IsolationForest"
        anom_ver = CURRENT_MODEL_VERSION
        try:
            self.anomaly_detector = UnsupervisedAnomalyDetector.load(self.anomaly_dir, anom_name, anom_ver)
            print(f"[ModelRegistry] Loaded anomaly detector: {anom_name} v{anom_ver}")
        except Exception as e:
            print(f"[ModelRegistry] Evaluating anomaly detector baseline status ({e})...")
            self._train_default_anomaly()

        # Load experiment history
        if os.path.exists(EXPERIMENTS_FILE):
            try:
                with open(EXPERIMENTS_FILE, "r", encoding="utf-8") as f:
                    self.experiment_history = json.load(f)
            except Exception:
                self.experiment_history = []

    def _train_default_supervised(self):
        """
        Train and persist default Random Forest and HistGradientBoosting IDS models
        using scientifically rigorous Stratified Cross-Validation.
        """
        try:
            X, y, flows = self.dataset_manager.load_pcap_dataset()
            classes = list(np.unique(y))

            # 1. Random Forest Classifier
            rf_runner = ExperimentRunner(experiment_id="EXP-RF-CV-01", random_state=42)
            rf_eval = rf_runner.evaluate_cross_validation(
                model_class=SupervisedIDSModel,
                model_init_kwargs={
                    "model_name": "NIDS-RandomForest",
                    "version": CURRENT_MODEL_VERSION,
                    "algorithm": "random_forest",
                    "classes": classes,
                    "random_state": 42
                },
                X=X,
                y=y,
                classes=classes,
                n_splits=5,
                dataset_metadata={"dataset_id": "PCAP-DERIVED-FLOWS-v1", "samples": len(flows), "schema": FEATURE_SCHEMA_VERSION}
            )

            # Fit deployment model on full dataset
            rf_model = SupervisedIDSModel(
                model_name="NIDS-RandomForest",
                version=CURRENT_MODEL_VERSION,
                algorithm="random_forest",
                classes=classes,
                random_state=42
            )
            rf_model.train(X, y, dataset_info={"dataset_id": "PCAP-DERIVED-FLOWS-v1", "samples": len(flows), "schema": FEATURE_SCHEMA_VERSION})
            rf_model.save(self.supervised_dir)
            self.supervised_model = rf_model

            # 2. HistGradientBoosting Classifier
            hgb_runner = ExperimentRunner(experiment_id="EXP-HGB-CV-01", random_state=42)
            hgb_eval = hgb_runner.evaluate_cross_validation(
                model_class=SupervisedIDSModel,
                model_init_kwargs={
                    "model_name": "NIDS-HistGradientBoosting",
                    "version": CURRENT_MODEL_VERSION,
                    "algorithm": "hist_gradient_boosting",
                    "classes": classes,
                    "random_state": 42
                },
                X=X,
                y=y,
                classes=classes,
                n_splits=5,
                dataset_metadata={"dataset_id": "PCAP-DERIVED-FLOWS-v1", "samples": len(flows), "schema": FEATURE_SCHEMA_VERSION}
            )

            hgb_model = SupervisedIDSModel(
                model_name="NIDS-HistGradientBoosting",
                version=CURRENT_MODEL_VERSION,
                algorithm="hist_gradient_boosting",
                classes=classes,
                random_state=42
            )
            hgb_model.train(X, y, dataset_info={"dataset_id": "PCAP-DERIVED-FLOWS-v1", "samples": len(flows), "schema": FEATURE_SCHEMA_VERSION})
            hgb_model.save(self.supervised_dir)

            # Record verified cross-validation experiments
            self.experiment_history = [rf_eval, hgb_eval]
            with open(EXPERIMENTS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.experiment_history, f, indent=2)

            print(f"[ModelRegistry] Cross-validation evaluation completed.")
            print(f"  -> {rf_model.model_name} CV Accuracy: {rf_eval['metrics']['accuracy']} +/- {rf_eval['metrics']['accuracy_std']}")
            print(f"  -> {hgb_model.model_name} CV Accuracy: {hgb_eval['metrics']['accuracy']} +/- {hgb_eval['metrics']['accuracy_std']}")
        except Exception as err:
            print(f"[ModelRegistry] Could not auto-train supervised models: {err}")

    def _train_default_anomaly(self):
        """
        Inspect available baseline data. If insufficient (< MIN_BASELINE_SAMPLES),
        explicitly set detector status to INSUFFICIENT_BASELINE_DATA without fabricating data.
        """
        try:
            X, y, flows = self.dataset_manager.load_pcap_dataset()
            benign_flows = [f for f, lbl in zip(flows, y) if lbl == "BENIGN"]

            detector = UnsupervisedAnomalyDetector(
                model_name="FlowAnomaly-IsolationForest",
                version=CURRENT_MODEL_VERSION,
                contamination=0.05,
                threshold=0.65,
                min_baseline_samples=MIN_BASELINE_SAMPLES,
                random_state=42
            )

            if len(benign_flows) < MIN_BASELINE_SAMPLES:
                print(f"[ModelRegistry] Insufficient benign baseline traffic ({len(benign_flows)} flows < {MIN_BASELINE_SAMPLES} required).")
                print(f"[ModelRegistry] Anomaly detector marked INSUFFICIENT_BASELINE_DATA (no synthetic fabrication).")
                detector.is_trained = False
                detector.status = "INSUFFICIENT_BASELINE_DATA"
                self.anomaly_detector = detector
            else:
                detector.fit_baseline(benign_flows, dataset_name="PCAP Benign Baseline")
                detector.save(self.anomaly_dir)
                self.anomaly_detector = detector
                print(f"[ModelRegistry] Successfully trained anomaly detector on {len(benign_flows)} flows.")
        except Exception as err:
            print(f"[ModelRegistry] Anomaly detector initialization: {err}")

    def record_experiment(self, experiment: Dict[str, Any]):
        """Append and persist experiment results."""
        self.experiment_history.append(experiment)
        try:
            with open(EXPERIMENTS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.experiment_history, f, indent=2)
        except Exception as e:
            print(f"[ModelRegistry] Failed to save experiment history: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Return system-wide status of ML models and registries."""
        return {
            "status": "OPERATIONAL",
            "schema_version": FEATURE_SCHEMA_VERSION,
            "supervised_model": {
                "available": self.supervised_model is not None and self.supervised_model.is_trained,
                "model_name": self.supervised_model.model_name if self.supervised_model else None,
                "version": self.supervised_model.version if self.supervised_model else None,
                "algorithm": self.supervised_model.algorithm if self.supervised_model else None,
                "features_count": len(self.supervised_model.feature_pipeline.feature_names) if self.supervised_model else 0,
                "classes": self.supervised_model.classes if self.supervised_model else []
            },
            "anomaly_detector": {
                "available": self.anomaly_detector is not None and self.anomaly_detector.is_trained,
                "model_name": self.anomaly_detector.model_name if self.anomaly_detector else None,
                "version": self.anomaly_detector.version if self.anomaly_detector else None,
                "algorithm": "isolation_forest",
                "status": self.anomaly_detector.status if self.anomaly_detector else "INSUFFICIENT_BASELINE_DATA",
                "threshold": self.anomaly_detector.threshold if self.anomaly_detector else 0.65,
                "is_calibrated": False,
                "min_baseline_required": MIN_BASELINE_SAMPLES
            },
            "total_experiments_recorded": len(self.experiment_history)
        }

    def predict_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        if not self.supervised_model:
            return {"error": "NO_ACTIVE_SUPERVISED_MODEL"}
        return self.supervised_model.predict_flow(flow)

    def score_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        if not self.anomaly_detector:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "status": "INSUFFICIENT_BASELINE_DATA",
                "verdict": "MODEL_OFFLINE_INSUFFICIENT_BASELINE"
            }
        return self.anomaly_detector.score_flow(flow)

    def list_models(self) -> List[Dict[str, Any]]:
        models = []
        for d in [self.supervised_dir, self.anomaly_dir]:
            if not os.path.exists(d):
                continue
            for f in os.listdir(d):
                if f.endswith("_manifest.json"):
                    try:
                        with open(os.path.join(d, f), "r", encoding="utf-8") as mf:
                            models.append(json.load(mf))
                    except Exception:
                        pass
        return models

GLOBAL_REGISTRY = ModelRegistry()
