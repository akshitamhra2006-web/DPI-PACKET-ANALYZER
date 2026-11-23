#!/usr/bin/env python3
"""
Automated REST API Test Suite for Machine Learning & AI Endpoints
================================================================
Verifies all new /api/ml/* and /api/ai/* REST endpoints in-process:
status, models, metrics, experiments, predictions, anomalies,
explanations, natural language investigation, and recommendations.
"""

import unittest
import io
import json
import os
import sys

PROJECT_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

SERVER_DIR = os.path.join(PROJECT_ROOT, "server")
if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)

from api_server import DPIRequestHandler, STATE

class DummyServer:
    pass

class MockSocket:
    def __init__(self, request_bytes):
        self.rfile = io.BytesIO(request_bytes)
        self.wfile = io.BytesIO()

    def makefile(self, mode, *args, **kwargs):
        if "r" in mode:
            return self.rfile
        return self.wfile

    def sendall(self, b):
        self.wfile.write(b)

class TestAIAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        STATE.reload()

    def request(self, method, path, data=None, headers=None):
        if headers is None:
            headers = {}
        body_bytes = b""
        if data is not None:
            if isinstance(data, (dict, list)):
                body_bytes = json.dumps(data).encode("utf-8")
                if "Content-Type" not in headers:
                    headers["Content-Type"] = "application/json"
            elif isinstance(data, str):
                body_bytes = data.encode("utf-8")
            else:
                body_bytes = data
            if "Content-Length" not in headers:
                headers["Content-Length"] = str(len(body_bytes))

        raw = f"{method} {path} HTTP/1.1\r\nHost: localhost\r\n"
        for k, v in headers.items():
            raw += f"{k}: {v}\r\n"
        raw += "\r\n"
        raw_bytes = raw.encode("utf-8") + body_bytes

        sock = MockSocket(raw_bytes)
        try:
            DPIRequestHandler(sock, ("127.0.0.1", 12345), DummyServer())
        except Exception:
            pass

        response_bytes = sock.wfile.getvalue()
        header_end = response_bytes.find(b"\r\n\r\n")
        if header_end == -1:
            return 0, {}, response_bytes

        header_lines = response_bytes[:header_end].decode("latin1").split("\r\n")
        body = response_bytes[header_end + 4:]
        status_line = header_lines[0]
        status_parts = status_line.split(" ")
        status_code = int(status_parts[1]) if len(status_parts) > 1 else 0

        resp_headers = {}
        for line in header_lines[1:]:
            if ":" in line:
                hk, hv = line.split(":", 1)
                resp_headers[hk.strip()] = hv.strip()

        return status_code, resp_headers, body

    # 1. GET /api/ml/status
    def test_01_ml_status(self):
        status, headers, body = self.request("GET", "/api/ml/status")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["status"], "OPERATIONAL")
        self.assertTrue(data["supervised_model"]["available"])
        self.assertIn("status", data["anomaly_detector"])
        self.assertIn(data["anomaly_detector"]["status"], ["INSUFFICIENT_BASELINE_DATA", "TRAINED"])

    # 2. GET /api/ml/models
    def test_02_ml_models(self):
        status, headers, body = self.request("GET", "/api/ml/models")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("models", data)
        self.assertGreaterEqual(len(data["models"]), 2)

    # 3. GET /api/ml/metrics
    def test_03_ml_metrics(self):
        status, headers, body = self.request("GET", "/api/ml/metrics")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("metrics", data)
        self.assertIn("confusion_matrix", data)
        self.assertIn("feature_importances", data)

    # 4. GET /api/ml/experiments
    def test_04_ml_experiments(self):
        status, headers, body = self.request("GET", "/api/ml/experiments")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("history", data)
        self.assertIn("comparison", data)
        self.assertGreaterEqual(data["total_experiments"], 1)

    # 5. POST /api/ml/predict (Batch)
    def test_05_ml_predict_batch(self):
        status, headers, body = self.request("POST", "/api/ml/predict", data={})
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("total_flows_evaluated", data)
        self.assertIn("predictions", data)

    def test_05b_ml_predict_batch_oversized_rejection(self):
        # Test batch protection: payloads > 5000 flows must return 413
        oversized_payload = {"flows": [{"flow_id": i} for i in range(5001)]}
        status, headers, body = self.request("POST", "/api/ml/predict", data=oversized_payload)
        self.assertEqual(status, 413)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["error"], "BATCH_SIZE_EXCEEDED")
        self.assertEqual(data["max_limit"], 5000)
        self.assertEqual(data["received"], 5001)

    def test_05c_ml_predict_batch_invalid_type_rejection(self):
        # Test bad input validation: flows must be a list
        status, headers, body = self.request("POST", "/api/ml/predict", data={"flows": "invalid_string"})
        self.assertEqual(status, 400)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["error"], "INVALID_FLOWS_PAYLOAD")

    # 6. POST /api/ml/predict (Single Flow)
    def test_06_ml_predict_single_flow(self):
        sample_flow = {
            "flow_id": 999,
            "duration_seconds": 0.001,
            "total_packets": 1,
            "total_bytes": 54,
            "forward": {"syn": 1, "ack": 0, "packets": 1, "bytes": 54},
            "reverse": {"packets": 0, "bytes": 0},
            "destination_port": 445,
            "protocol": "TCP"
        }
        status, headers, body = self.request("POST", "/api/ml/predict", data={"flow": sample_flow})
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("predicted_class", data)
        self.assertIn("confidence", data)

    # 7. GET /api/ml/anomalies
    def test_07_ml_anomalies(self):
        status, headers, body = self.request("GET", "/api/ml/anomalies")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("total_flows_evaluated", data)
        self.assertIn("anomalies", data)

    # 8. GET /api/ml/explanations
    def test_08_ml_explanations(self):
        status, headers, body = self.request("GET", "/api/ml/explanations?flow_id=8")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("composite_risk_score", data)
        self.assertIn("factors", data)
        self.assertIn("narrative_summary", data)

    # 9. GET /api/ai/status
    def test_09_ai_status(self):
        status, headers, body = self.request("GET", "/api/ai/status")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["assistant_version"], "5.0.0")
        self.assertIn("active_mode", data)

    # 10. POST /api/ai/investigate
    def test_10_ai_investigate(self):
        query_payload = {"query": "Which hosts have the highest risk?"}
        status, headers, body = self.request("POST", "/api/ai/investigate", data=query_payload)
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("mode", data)
        self.assertIn("response", data)
        resp = data["response"]
        self.assertIn("observed_facts", resp)
        self.assertIn("interpretation", resp)
        self.assertIn("recommended_investigation_steps", resp)

    # 11. GET /api/ai/recommendations
    def test_11_ai_recommendations(self):
        status, headers, body = self.request("GET", "/api/ai/recommendations")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("recommendations", data)
        self.assertGreater(len(data["recommendations"]), 0)

if __name__ == "__main__":
    unittest.main(verbosity=2)
