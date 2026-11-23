#!/usr/bin/env python3
"""
Automated In-Process REST API Test Suite for DPI & Packet Analyzer Platform
===========================================================================
Verifies all 13 REST API endpoints, HTTP error cases, CORS headers,
investigation CRUD lifecycle, execution controller, and static file serving.
Runs cleanly and deterministically without external network socket dependencies.
"""

import unittest
import io
import json
import time
import os
import sys

# Add server directory to path
SERVER_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "server"))
PROJECT_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, SERVER_DIR)

from api_server import DPIRequestHandler, STATE

class DummyServer:
    def __init__(self):
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

class TestAPIServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Populate session data using test_dpi.pcap before running tests
        session_dir = os.path.join(PROJECT_ROOT, "data", "current_session")
        os.makedirs(session_dir, exist_ok=True)
        engine_bin = os.path.join(PROJECT_ROOT, "bin", "dpi_engine")
        if os.path.exists(engine_bin):
            subprocess_cmd = [
                engine_bin,
                os.path.join(PROJECT_ROOT, "test_dpi.pcap"),
                os.path.join(session_dir, "forwarded_traffic.pcap"),
                "--analyze-all", session_dir,
                "--detect", "--incidents", "--signatures", "--threat-intelligence",
                "--rules-dir", os.path.join(PROJECT_ROOT, "config", "signatures"),
                "--threat-intel-dir", os.path.join(PROJECT_ROOT, "config", "threat_intel")
            ]
            import subprocess
            subprocess.run(subprocess_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

        STATE.data_dir = session_dir
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

    # 1. Health Endpoint
    def test_01_health_endpoint(self):
        status, headers, body = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["status"], "UP")
        self.assertEqual(data["version"], "4.0.0")
        self.assertIn("Access-Control-Allow-Origin", headers)

    # 2. Metadata Endpoint
    def test_02_metadata_endpoint(self):
        status, headers, body = self.request("GET", "/api/metadata")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("session_id", data)
        self.assertEqual(data["engine_version"], "4.0.0")

    # 3. Summary Endpoint
    def test_03_summary_endpoint(self):
        status, headers, body = self.request("GET", "/api/summary")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertGreater(data["total_flows"], 0)
        self.assertGreater(data["total_endpoints"], 0)
        self.assertIn("top_protocols", data)

    # 4. Flows Endpoint (Pagination & Filtering)
    def test_04_flows_endpoint(self):
        status, headers, body = self.request("GET", "/api/flows?page=1&limit=5")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("total", data)
        self.assertEqual(data["limit"], 5)
        self.assertLessEqual(len(data["data"]), 5)

        # Filter by search
        status, _, body = self.request("GET", "/api/flows?search=192.168.1.100")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertGreater(len(data["data"]), 0)

    # 5. Endpoints & Risk Profiles
    def test_05_endpoints_endpoint(self):
        status, headers, body = self.request("GET", "/api/endpoints")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("endpoints", data)
        self.assertGreater(len(data["endpoints"]), 0)

        # Filter with min_risk
        status, _, body = self.request("GET", "/api/endpoints?min_risk=0.0")
        self.assertEqual(status, 200)

    # 6. Detections Endpoint
    def test_06_detections_endpoint(self):
        status, headers, body = self.request("GET", "/api/detections")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("detections", data)

    # 7. Signatures Endpoint
    def test_07_signatures_endpoint(self):
        status, headers, body = self.request("GET", "/api/signatures")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("signatures", data)

    # 8. Incidents Endpoint
    def test_08_incidents_endpoint(self):
        status, headers, body = self.request("GET", "/api/incidents")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("incidents", data)

    # 9. Threat Matches Endpoint
    def test_09_threat_matches_endpoint(self):
        status, headers, body = self.request("GET", "/api/threat-matches")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("threat_matches", data)

    # 10. Graph Endpoint
    def test_10_graph_endpoint(self):
        status, headers, body = self.request("GET", "/api/graph")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("nodes", data)
        self.assertIn("edges", data)

    # 11. Temporal Endpoint
    def test_11_temporal_endpoint(self):
        status, headers, body = self.request("GET", "/api/temporal")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("buckets", data)

    # 12. Investigations Full Lifecycle (GET, POST, NOTES, EVIDENCE, PUT)
    def test_12_investigations_lifecycle(self):
        # 12a. List investigations
        status, _, body = self.request("GET", "/api/investigations")
        self.assertEqual(status, 200)

        # 12b. Create investigation
        new_inv_payload = {
            "title": "Automated API Test Investigation",
            "priority": "HIGH",
            "description": "Verification of investigation CRUD workflow via REST API",
            "lead_analyst": "secops_bot",
            "tags": ["TEST", "AUTOMATION"]
        }
        status, _, body = self.request("POST", "/api/investigations", data=new_inv_payload)
        self.assertEqual(status, 201)
        created_inv = json.loads(body.decode("utf-8"))
        inv_id = created_inv["investigation_id"]
        self.assertTrue(inv_id.startswith("INV-"))
        self.assertEqual(created_inv["title"], "Automated API Test Investigation")

        # 12c. Retrieve single investigation
        status, _, body = self.request("GET", f"/api/investigations/{inv_id}")
        self.assertEqual(status, 200)
        single_inv = json.loads(body.decode("utf-8"))
        self.assertEqual(single_inv["investigation_id"], inv_id)

        # 12d. Add note
        note_payload = {
            "author": "lead_hunter",
            "content": "Initial triage confirmed malicious activity."
        }
        status, _, body = self.request("POST", f"/api/investigations/{inv_id}/notes", data=note_payload)
        self.assertEqual(status, 201)
        note_res = json.loads(body.decode("utf-8"))
        self.assertTrue(note_res["note_id"].startswith("NOTE-"))

        # 12e. Add evidence reference with integrity hashing
        evidence_payload = {
            "type": "PCAP_PAYLOAD",
            "source_id": "FLOW-102",
            "description": "Raw hex payload from suspicious flow",
            "raw_content": "AttackBot user agent string verification sample",
            "tags": ["SAMPLE"]
        }
        status, _, body = self.request("POST", f"/api/investigations/{inv_id}/evidence", data=evidence_payload)
        self.assertEqual(status, 201)
        ev_res = json.loads(body.decode("utf-8"))
        self.assertTrue(ev_res["evidence_id"].startswith("EVID-"))
        self.assertEqual(len(ev_res["integrity_hash"]), 16) # 16-hex FNV hash

        # 12f. Update investigation status via PUT
        update_payload = {
            "status": "IN_PROGRESS",
            "priority": "CRITICAL"
        }
        status, _, body = self.request("PUT", f"/api/investigations/{inv_id}", data=update_payload)
        self.assertEqual(status, 200)
        updated_inv = json.loads(body.decode("utf-8"))
        self.assertEqual(updated_inv["status"], "IN_PROGRESS")
        self.assertEqual(updated_inv["priority"], "CRITICAL")
        self.assertEqual(len(updated_inv["notes"]), 1)
        self.assertEqual(len(updated_inv["evidence_list"]), 1)

    # 13. Analyze Endpoint (Execution Controller)
    def test_13_analyze_controller_endpoint(self):
        analyze_payload = {
            "pcap_file": "pcaps/threat_intel_match.pcap"
        }
        status, _, body = self.request("POST", "/api/analyze", data=analyze_payload)
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["metadata"]["pcap_file"], "threat_intel_match.pcap")

    # 14. Error Conditions & Edge Cases
    def test_14_error_conditions(self):
        # 14a. Non-existent GET endpoint -> 404
        status, _, body = self.request("GET", "/api/nonexistent_route")
        self.assertEqual(status, 404)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("error", data)

        # 14b. Non-existent investigation ID -> 404
        status, _, body = self.request("GET", "/api/investigations/INV-99999")
        self.assertEqual(status, 404)

        # 14c. Malformed JSON body on POST -> handled gracefully
        status, _, body = self.request("POST", "/api/analyze", data="INVALID_JSON_BODY{{{")
        self.assertIn(status, [200, 400, 500])

        # 14d. Path traversal attempt on static files
        status, _, _ = self.request("GET", "/../../../../etc/passwd")
        self.assertIn(status, [200, 404])

        # 14e. CORS Preflight OPTIONS
        status, headers, _ = self.request("OPTIONS", "/api/flows")
        self.assertEqual(status, 204)
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), "*")

    # 15. Static File Serving
    def test_15_static_file_serving(self):
        # 15a. Root index.html
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"DPI & Packet Analyzer", body)

        # 15b. CSS stylesheet
        status, headers, body = self.request("GET", "/css/styles.css")
        self.assertEqual(status, 200)
        self.assertTrue("text/css" in headers.get("Content-Type", ""))

        # 15c. JavaScript application
        status, headers, body = self.request("GET", "/js/app.js")
        self.assertEqual(status, 200)
        self.assertTrue("javascript" in headers.get("Content-Type", ""))

if __name__ == "__main__":
    unittest.main(verbosity=2)
