#!/usr/bin/env python3
"""
Automated Test Suite for Machine Learning Subsystem
===================================================
Tests feature extraction, preprocessing, supervised classification,
unsupervised anomaly detection, model persistence, SHA256 integrity verification,
data leakage auditing, and evaluation metrics.
"""

import unittest
import os
import sys
import shutil
import json
import numpy as np

PROJECT_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.feature_pipeline import FeaturePipeline, FEATURE_NAMES
from ml.models import SupervisedIDSModel
from ml.anomaly_detector import UnsupervisedAnomalyDetector
from ml.experiment_framework import ExperimentRunner
from ml.dataset_manager import DatasetManager
from ml.explainability import ThreatExplainabilityEngine

TEST_DIR = "/tmp/test_ml_artifacts"

class TestMLSubsystem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.makedirs(TEST_DIR, exist_ok=True)

        # Synthetic normal flow
        cls.normal_flow = {
            "flow_id": 1,
            "source_ip": "192.168.1.100",
            "destination_ip": "93.184.216.34",
            "source_port": 50123,
            "destination_port": 443,
            "protocol": "TCP",
            "duration_seconds": 1.25,
            "total_packets": 10,
            "total_bytes": 1500,
            "packets_per_second": 8.0,
            "bytes_per_second": 1200.0,
            "byte_asymmetry_ratio": 1.1,
            "packet_asymmetry_ratio": 1.0,
            "forward": {"packets": 5, "bytes": 750, "syn": 1, "ack": 4, "fin": 1, "rst": 0, "psh": 1},
            "reverse": {"packets": 5, "bytes": 750, "syn": 1, "ack": 4, "fin": 1, "rst": 0, "psh": 1},
            "packet_size": {"min": 54.0, "max": 500.0, "mean": 150.0, "stddev": 120.0},
            "iat_microseconds": {"mean": 125000.0, "stddev": 30000.0}
        }

        # Synthetic scan flow (SYN-heavy, high asymmetry)
        cls.scan_flow = {
            "flow_id": 2,
            "source_ip": "192.168.1.200",
            "destination_ip": "10.0.0.50",
            "source_port": 40001,
            "destination_port": 445,
            "protocol": "TCP",
            "duration_seconds": 0.001,
            "total_packets": 1,
            "total_bytes": 54,
            "packets_per_second": 1000.0,
            "bytes_per_second": 54000.0,
            "byte_asymmetry_ratio": 54.0,
            "packet_asymmetry_ratio": 1.0,
            "forward": {"packets": 1, "bytes": 54, "syn": 1, "ack": 0, "fin": 0, "rst": 0, "psh": 0},
            "reverse": {"packets": 0, "bytes": 0, "syn": 0, "ack": 0, "fin": 0, "rst": 0, "psh": 0},
            "packet_size": {"min": 54.0, "max": 54.0, "mean": 54.0, "stddev": 0.0},
            "iat_microseconds": {"mean": 0.0, "stddev": 0.0}
        }

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(TEST_DIR, ignore_errors=True)

    # 1. Feature Pipeline Tests
    def test_01_feature_extraction_completeness(self):
        pipeline = FeaturePipeline()
        vec = pipeline.extract_from_flow(self.normal_flow)
        self.assertEqual(len(vec), len(FEATURE_NAMES))
        self.assertEqual(len(vec), 24)
        # Check specific mapped fields
        self.assertEqual(vec[0], 1.25) # duration
        self.assertEqual(vec[1], 10.0) # total_packets
        # Schema 2.0.0: port 443 is well-known (<1024) and non-ephemeral (<49152)
        self.assertEqual(vec[22], 1.0) # is_well_known_port
        self.assertEqual(vec[23], 0.0) # is_ephemeral_port

    def test_01b_banned_fields_and_schema_version_validation(self):
        pipeline = FeaturePipeline()
        self.assertEqual(pipeline.schema_version, "2.0.0")
        with self.assertRaises(ValueError):
            pipeline.validate_feature_names(["duration_seconds", "destination_port"])
        with self.assertRaises(ValueError):
            pipeline.validate_feature_names(["duration_seconds", "protocol_num"])

    def test_02_feature_pipeline_scaling_and_safety(self):
        pipeline = FeaturePipeline()
        flows = [self.normal_flow, self.scan_flow]
        X = pipeline.transform_flows(flows)
        self.assertEqual(X.shape, (2, 24))
        # Ensure no NaNs or infinities
        self.assertFalse(np.isnan(X).any())
        self.assertFalse(np.isinf(X).any())

        # Test fitting and normalization
        X_norm = pipeline.fit_transform(X)
        self.assertEqual(X_norm.shape, (2, 24))
        self.assertTrue(pipeline.is_fitted)

    # 2. Supervised IDS Training & Inference Tests
    def test_03_supervised_model_training_and_inference(self):
        X = np.array([
            [1.0, 10, 1000, 10, 1000, 1.0, 1.0, 5, 500, 5, 500, 54, 500, 100, 20, 10000, 2000, 1, 4, 1, 0, 1, 1.0, 0.0],
            [0.01, 1, 54, 100, 5400, 54.0, 1.0, 1, 54, 0, 0, 54, 54, 54, 0, 0, 0, 1, 0, 0, 0, 0, 1.0, 0.0],
            [1.0, 12, 1200, 12, 1200, 1.0, 1.0, 6, 600, 6, 600, 54, 500, 100, 20, 10000, 2000, 1, 5, 1, 0, 1, 1.0, 0.0],
            [0.01, 1, 54, 100, 5400, 54.0, 1.0, 1, 54, 0, 0, 54, 54, 54, 0, 0, 0, 1, 0, 0, 0, 0, 0.0, 0.0]
        ], dtype=np.float32)
        y = np.array(["BENIGN", "PORT_SCAN", "BENIGN", "PORT_SCAN"])

        model = SupervisedIDSModel(model_name="Test-RF", version="0.1.0", random_state=42)
        meta = model.train(X, y)
        self.assertTrue(model.is_trained)
        self.assertIn("feature_importances", meta)

        # Predict normal flow
        pred_norm = model.predict_flow(self.normal_flow)
        self.assertEqual(pred_norm["predicted_class"], "BENIGN")
        self.assertFalse(pred_norm["is_intrusion"])
        self.assertGreaterEqual(pred_norm["confidence"], 0.5)

        # Predict scan flow
        pred_scan = model.predict_flow(self.scan_flow)
        self.assertEqual(pred_scan["predicted_class"], "PORT_SCAN")
        self.assertTrue(pred_scan["is_intrusion"])

    def test_04_supervised_model_persistence_and_integrity(self):
        X = np.random.RandomState(42).randn(10, 24).astype(np.float32)
        y = np.array(["BENIGN", "PORT_SCAN"] * 5)

        model = SupervisedIDSModel(model_name="NIDS-Persist", version="1.0.0", random_state=42)
        model.train(X, y)
        model_path, manifest_path = model.save(TEST_DIR)
        self.assertTrue(os.path.exists(model_path))
        self.assertTrue(os.path.exists(manifest_path))

        # Reload with verified integrity
        loaded = SupervisedIDSModel.load(TEST_DIR, "NIDS-Persist", "1.0.0")
        self.assertTrue(loaded.is_trained)
        self.assertEqual(loaded.model_name, "NIDS-Persist")

    # 3. Unsupervised Anomaly Detection Tests
    def test_05_unsupervised_anomaly_detection(self):
        # Create baseline of benign flows
        benign_baseline = [self.normal_flow for _ in range(20)]
        detector = UnsupervisedAnomalyDetector(
            model_name="Test-Anomaly-IF",
            version="1.0.0",
            contamination=0.05,
            threshold=0.60,
            random_state=42
        )
        detector.fit_baseline(benign_baseline)
        self.assertTrue(detector.is_trained)

        # Normal flow should have low anomaly score
        norm_res = detector.score_flow(self.normal_flow)
        self.assertFalse(norm_res["is_anomaly"])
        self.assertLess(norm_res["anomaly_score"], 0.60)

        # Scan flow should have high anomaly score and deviation factors
        scan_res = detector.score_flow(self.scan_flow)
        self.assertTrue(scan_res["is_anomaly"])
        self.assertGreaterEqual(scan_res["anomaly_score"], 0.60)
        self.assertGreater(len(scan_res["contributing_deviations"]), 0)

    def test_05b_unsupervised_insufficient_baseline_rejection(self):
        detector = UnsupervisedAnomalyDetector(min_baseline_samples=10)
        # Attempting to fit with only 3 flows should raise ValueError
        with self.assertRaises(ValueError) as ctx:
            detector.fit_baseline([self.normal_flow, self.normal_flow, self.normal_flow])
        self.assertIn("at least 10 normal flow records", str(ctx.exception))
        self.assertEqual(detector.status, "INSUFFICIENT_BASELINE_DATA")

    # 4. Data Leakage & Experiment Framework Tests
    def test_06_data_leakage_and_metrics_evaluation(self):
        train_flows = [self.normal_flow]
        test_flows = [self.scan_flow]

        # Audit for leakage
        leak_res = ExperimentRunner.check_data_leakage(train_flows, test_flows)
        self.assertFalse(leak_res["leakage_detected"])
        self.assertEqual(leak_res["audit_verdict"], "CLEAN_ISOLATED_SPLIT")

        # Test evaluation runner
        X = np.random.RandomState(42).randn(10, 24).astype(np.float32)
        y = np.array(["BENIGN"] * 5 + ["PORT_SCAN"] * 5)
        model = SupervisedIDSModel(model_name="Eval-Model", version="1.0.0")
        model.train(X, y)

        runner = ExperimentRunner(experiment_id="TEST-EXP-01")
        eval_metrics = runner.evaluate_model(model, X, y, classes=["BENIGN", "PORT_SCAN"])
        self.assertIn("accuracy", eval_metrics["metrics"])
        self.assertIn("f1_macro", eval_metrics["metrics"])
        self.assertIn("confusion_matrix", eval_metrics)
        self.assertIn("inference_latency_microseconds", eval_metrics["performance"])

    def test_06b_stratified_cross_validation_evaluation(self):
        # Test Stratified Cross-Validation with variance/standard deviation reporting
        X = np.random.RandomState(42).randn(12, 24).astype(np.float32)
        y = np.array(["BENIGN"] * 6 + ["PORT_SCAN"] * 6)

        runner = ExperimentRunner(experiment_id="TEST-EXP-CV")
        cv_res = runner.evaluate_cross_validation(
            SupervisedIDSModel,
            {"model_name": "Eval-CV-Model", "version": "2.0.0"},
            X,
            y,
            classes=["BENIGN", "PORT_SCAN"],
            n_splits=3
        )
        self.assertEqual(cv_res["evaluation_type"], "STRATIFIED_CROSS_VALIDATION")
        self.assertIn("accuracy", cv_res["metrics"])
        self.assertIn("accuracy_std", cv_res["metrics"])
        self.assertIn("f1_macro", cv_res["metrics"])
        self.assertIn("f1_macro_std", cv_res["metrics"])
        self.assertEqual(len(cv_res["fold_results"]), 3)

    # 5. Explainability Engine Tests
    def test_07_explainability_risk_decomposition(self):
        ml_pred = {"is_intrusion": True, "predicted_class": "PORT_SCAN", "confidence": 0.95, "model_name": "NIDS-RF"}
        anom_res = {"is_anomaly": True, "anomaly_score": 0.85, "model_name": "IsolationForest"}
        det = [{"detection_id": "DET-SCAN-01", "severity": "HIGH", "category": "SCANNER", "explanation": "Vertical port scan"}]
        threat = [{"event_id": "IOC-101", "severity": "HIGH", "ioc_type": "IP", "ioc_value": "192.168.1.200", "dataset_id": "FEED-01"}]

        expl = ThreatExplainabilityEngine.explain_flow_risk(
            self.scan_flow,
            ml_prediction=ml_pred,
            anomaly_result=anom_res,
            behavioral_detections=det,
            threat_matches=threat
        )

        self.assertGreaterEqual(expl["composite_risk_score"], 70.0)
        self.assertIn(expl["risk_level"], ["HIGH", "CRITICAL"])
        self.assertEqual(len(expl["factors"]), 4) # Behavioral + Threat + ML + Anomaly
        self.assertIn("narrative_summary", expl)
        self.assertIn("uncertainty_assessment", expl)

    # 6. Schema Compatibility & Integrity Tests
    def test_08_schema_incompatible_artifact_rejection(self):
        import joblib
        # Create a dummy model file and manifest with incompatible schema version 1.0.0
        bad_manifest = {
            "model_name": "Incompatible-Model",
            "version": "1.0.0",
            "schema_version": "1.0.0",
            "feature_names": ["duration_seconds", "destination_port"],
            "model_file": "Incompatible-Model_1.0.0.joblib",
            "sha256": "dummy"
        }
        manifest_path = os.path.join(TEST_DIR, "Incompatible-Model_1.0.0_manifest.json")
        model_path = os.path.join(TEST_DIR, "Incompatible-Model_1.0.0.joblib")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(bad_manifest, f)
        joblib.dump({"clf": None, "schema_version": "1.0.0"}, model_path)

        with self.assertRaises(ValueError) as ctx:
            SupervisedIDSModel.load(TEST_DIR, "Incompatible-Model", "1.0.0")
        self.assertIn("incompatible", str(ctx.exception).lower())

    # 7. Milestone 5.4 Remediation Tests
    def test_09_leakage_aware_evaluation(self):
        dm = DatasetManager()
        X, y, _ = dm.load_pcap_dataset()
        runner = ExperimentRunner("TEST-EXP-LEAKAGE")

        result = runner.evaluate_leakage_aware(
            SupervisedIDSModel,
            {"model_name": "NIDS-RandomForest", "algorithm": "random_forest"},
            X, y
        )

        self.assertEqual(result["status"], "INSUFFICIENT_UNIQUE_GROUPS_FOR_STRICT_EVALUATION")
        self.assertIn("PORT_SCAN", result["insufficient_group_classes"])
        self.assertIn("DNS_TUNNEL", result["insufficient_group_classes"])
        self.assertIn("C2_BEACON", result["evaluable_classes"])
        self.assertIn("BENIGN", result["evaluable_classes"])
        self.assertEqual(result["group_audit"]["unique_feature_vectors"], 8)
        self.assertGreaterEqual(result["group_audit"]["duplicate_sample_count"], 80)
        self.assertIn("duplicate_leakage_warning", result["conventional_stratified_cv_comparison"])
        self.assertIn("memorization", result["conventional_stratified_cv_comparison"]["duplicate_leakage_warning"].lower())

    def test_10_external_csv_ingestion(self):
        dm = DatasetManager()
        cic_path = os.path.join(PROJECT_ROOT, "tests", "fixtures", "sample_cicids2017.csv")
        unsw_path = os.path.join(PROJECT_ROOT, "tests", "fixtures", "sample_unsw_nb15.csv")

        # Ingest CIC-IDS2017
        X_cic, y_cic, meta_cic = dm.ingest_external_csv(cic_path, "CICIDS2017")
        self.assertEqual(X_cic.shape, (5, 24))
        self.assertEqual(len(y_cic), 5)
        self.assertIn("BENIGN", y_cic)
        self.assertIn("PORT_SCAN", y_cic)
        self.assertEqual(meta_cic["dataset_type"], "CICIDS2017")
        self.assertIn("sha256", meta_cic)

        # Ingest UNSW-NB15
        X_unsw, y_unsw, meta_unsw = dm.ingest_external_csv(unsw_path, "UNSW-NB15")
        self.assertEqual(X_unsw.shape, (5, 24))
        self.assertEqual(len(y_unsw), 5)
        self.assertIn("BENIGN", y_unsw)
        self.assertIn("C2_BEACON", y_unsw)
        self.assertEqual(meta_unsw["dataset_type"], "UNSW_NB15")

        # Test missing required column rejection
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv") as tmp:
            tmp.write("ColumnA,ColumnB\n1,2\n")
            tmp.flush()
            with self.assertRaises(ValueError) as ctx:
                dm.ingest_external_csv(tmp.name, "CICIDS2017")
            self.assertIn("missing required columns", str(ctx.exception).lower())

    def test_11_model_artifact_hmac_authentication(self):
        model = SupervisedIDSModel(algorithm="random_forest", random_state=42)
        X = np.ones((10, 24))
        y = np.array(["BENIGN"] * 5 + ["PORT_SCAN"] * 5)
        model.train(X, y)

        hmac_key = b"secret-audit-key-2026"
        model.save(TEST_DIR, hmac_key=hmac_key)

        # Success with correct key
        loaded = SupervisedIDSModel.load(TEST_DIR, model.model_name, model.version, hmac_key=hmac_key)
        self.assertTrue(loaded.is_trained)

        # Failure with incorrect key
        with self.assertRaises(ValueError) as ctx:
            SupervisedIDSModel.load(TEST_DIR, model.model_name, model.version, hmac_key=b"tampered-key")
        self.assertIn("hmac signature mismatch", str(ctx.exception).lower())

        # Success without HMAC key (backward-compatible check)
        loaded_plain = SupervisedIDSModel.load(TEST_DIR, model.model_name, model.version)
        self.assertTrue(loaded_plain.is_trained)

    def test_12_explainability_active_channel_normalization(self):
        ml_pred = {"is_intrusion": True, "predicted_class": "PORT_SCAN", "confidence": 1.0}
        det = [{"detection_id": "DET-01", "severity": "HIGH", "explanation": "Port scan"}]
        threat = [{"event_id": "IOC-01", "severity": "HIGH", "ioc_value": "1.2.3.4"}]

        # Scenario A: Anomaly detector uncalibrated (INSUFFICIENT_BASELINE_DATA)
        anom_uncal = {"status": "INSUFFICIENT_BASELINE_DATA", "is_anomaly": False, "is_calibrated": False}
        res_uncal = ThreatExplainabilityEngine.explain_flow_risk(
            self.scan_flow,
            ml_prediction=ml_pred,
            anomaly_result=anom_uncal,
            behavioral_detections=det,
            threat_matches=threat
        )
        self.assertTrue(res_uncal["is_re_normalized"])
        self.assertEqual(res_uncal["active_weight_sum"], 0.85)
        # Active score must be re-scaled higher than un-normalized score to avoid 15% dampening
        self.assertGreater(res_uncal["active_normalized_score"], res_uncal["composite_risk_score"])
        self.assertEqual(res_uncal["risk_level"], "CRITICAL")

        # Scenario B: Anomaly detector calibrated and active
        anom_cal = {"status": "ACTIVE", "is_anomaly": True, "anomaly_score": 0.8, "is_calibrated": True}
        res_cal = ThreatExplainabilityEngine.explain_flow_risk(
            self.scan_flow,
            ml_prediction=ml_pred,
            anomaly_result=anom_cal,
            behavioral_detections=det,
            threat_matches=threat
        )
        self.assertFalse(res_cal["is_re_normalized"])
        self.assertEqual(res_cal["active_weight_sum"], 1.00)
        self.assertEqual(res_cal["active_normalized_score"], res_cal["composite_risk_score"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
