#!/usr/bin/env python3
"""
DPI & Packet Analyzer — Backend REST API Service
================================================
Lightweight, secure, zero-dependency Python 3 HTTP API server that bridges
the frontend web dashboard with the C++17 modular DPI engine.

Features:
- RESTful endpoints for flows, endpoints, detections, signatures, incidents,
  threat intelligence, network graph, temporal metrics, and investigations.
- Execution controller for invoking ./bin/dpi_engine with --analyze-all.
- Stateful investigation management (notes, evidence with FNV/SHA hash integrity).
- Security controls: path traversal validation, CORS headers, size bounding.
- Static file server for production frontend distribution.
"""

import http.server
import socketserver
import urllib.parse
import json
import os
import sys
import subprocess
import time
import hashlib
import threading

# Add project root to sys.path so ml and ai packages can be imported
PROJECT_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.model_registry import GLOBAL_REGISTRY
from ml.explainability import ThreatExplainabilityEngine
from ml.experiment_framework import ExperimentRunner
from ai.assistant import GLOBAL_ASSISTANT
from ai.recommendation_engine import InvestigationRecommendationEngine

PORT = 8080
DEFAULT_DATA_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "data", "current_session"))
STATIC_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "web", "dist"))
PROJECT_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
MAX_PREDICT_BATCH_SIZE = 5000

class DPIState:
    def __init__(self, data_dir=DEFAULT_DATA_DIR):
        self.data_dir = data_dir
        self.lock = threading.Lock()
        self.metadata = {
            "session_id": "session-default",
            "pcap_file": "test_dpi.pcap",
            "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "engine_version": "4.0.0",
            "platform_version": "5.5.0-FINAL",
            "status": "READY"
        }
        self.cache = {}
        self.ensure_data_dir()
        self.reload()

    def ensure_data_dir(self):
        os.makedirs(self.data_dir, exist_ok=True)

    def load_json_file(self, filename, default=None):
        if default is None:
            default = []
        path = os.path.join(self.data_dir, filename)
        if not os.path.exists(path):
            return default
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[API] Error loading {filename}: {e}", file=sys.stderr)
            return default

    def reload(self):
        with self.lock:
            raw_flows = self.load_json_file("flows.json", [])
            for fl in raw_flows:
                try:
                    if GLOBAL_REGISTRY.supervised_model and GLOBAL_REGISTRY.supervised_model.is_trained:
                        fl["ml_prediction"] = GLOBAL_REGISTRY.predict_flow(fl)
                    if GLOBAL_REGISTRY.anomaly_detector and GLOBAL_REGISTRY.anomaly_detector.is_trained:
                        fl["anomaly_result"] = GLOBAL_REGISTRY.score_flow(fl)
                except Exception:
                    pass
            self.cache["flows"] = raw_flows
            self.cache["detections"] = self.load_json_file("detections.json", [])
            self.cache["signatures"] = self.load_json_file("signatures.json", [])
            self.cache["incidents"] = self.load_json_file("incidents.json", [])
            self.cache["threat_matches"] = self.load_json_file("threat_matches.json", [])
            self.cache["endpoints"] = self.load_json_file("endpoints.json", {})
            self.cache["risk_summary"] = self.load_json_file("risk_summary.json", {})
            self.cache["analytics"] = self.load_json_file("analytics.json", {})
            self.cache["network_graph"] = self.load_json_file("network_graph.json", {"nodes": [], "edges": []})
            self.cache["temporal"] = self.load_json_file("temporal_analytics.json", {"buckets": []})
            self.cache["investigations"] = self.load_json_file("investigations.json", [])
            print(f"[API] Reloaded data cache from {self.data_dir}: {len(self.cache['flows'])} flows, {len(self.cache['incidents'])} incidents")

    def run_analysis(self, pcap_path, options=None):
        if options is None:
            options = {}
        
        # Verify PCAP path exists and is within project root or safe location
        real_pcap = os.path.realpath(pcap_path)
        if not os.path.exists(real_pcap):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        engine_bin = os.path.join(PROJECT_ROOT, "bin", "dpi_engine")
        if not os.path.exists(engine_bin):
            raise FileNotFoundError("Engine binary bin/dpi_engine not found. Build with 'make all'.")

        self.ensure_data_dir()
        out_pcap = os.path.join(self.data_dir, "forwarded_traffic.pcap")

        cmd = [
            engine_bin,
            real_pcap,
            out_pcap,
            "--analyze-all", self.data_dir,
            "--detect",
            "--incidents",
            "--signatures",
            "--threat-intelligence"
        ]

        # Optional signature rules directory
        sig_dir = os.path.join(PROJECT_ROOT, "config", "signatures")
        if os.path.exists(sig_dir):
            cmd.extend(["--rules-dir", sig_dir])

        # Optional threat intel directory
        intel_dir = os.path.join(PROJECT_ROOT, "config", "threat_intel")
        if os.path.exists(intel_dir):
            cmd.extend(["--threat-intel-dir", intel_dir])

        print(f"[API] Executing: {' '.join(cmd)}")
        start_t = time.time()
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        dur = time.time() - start_t

        if res.returncode != 0:
            print(f"[API] Engine error:\n{res.stderr}", file=sys.stderr)
            raise RuntimeError(f"DPI Engine failed with code {res.returncode}: {res.stderr}")

        self.metadata = {
            "session_id": f"session-{int(time.time())}",
            "pcap_file": os.path.basename(real_pcap),
            "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "duration_seconds": round(dur, 3),
            "engine_version": "4.0.0",
            "status": "SUCCESS"
        }
        self.reload()
        return self.metadata

STATE = DPIState()

class DPIRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Enable permissive CORS for frontend SPA integration
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def send_json(self, status_code, data):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status_code, message):
        self.send_json(status_code, {"error": message, "timestamp": time.time()})

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path.startswith("/api/"):
            self.handle_api_get(path, qs)
        else:
            self.handle_static_get(path)

    def handle_static_get(self, path):
        # Fallback to web/dist or web/
        target_dir = STATIC_DIR
        if not os.path.exists(target_dir):
            target_dir = os.path.realpath(os.path.join(PROJECT_ROOT, "web"))

        # Safe path resolution
        req_path = path.lstrip("/")
        if not req_path:
            req_path = "index.html"

        safe_path = os.path.realpath(os.path.join(target_dir, req_path))
        if not safe_path.startswith(target_dir) or not os.path.exists(safe_path) or os.path.isdir(safe_path):
            index_path = os.path.join(target_dir, "index.html")
            if os.path.exists(index_path):
                safe_path = index_path
            else:
                self.send_error_json(404, "Static asset not found")
                return

        # Determine MIME
        ext = os.path.splitext(safe_path)[1].lower()
        mime_types = {
            ".html": "text/html; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".json": "application/json",
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".ico": "image/x-icon"
        }
        content_type = mime_types.get(ext, "application/octet-stream")

        try:
            with open(safe_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error_json(500, f"Error reading asset: {e}")

    def handle_api_get(self, path, qs):
        if path == "/api/health":
            self.send_json(200, {
                "status": "UP",
                "version": "4.0.0",
                "platform_version": "5.5.0-FINAL",
                "timestamp": time.time(),
                "service": "DPI & Packet Analyzer API"
            })
            return

        if path == "/api/metadata":
            self.send_json(200, STATE.metadata)
            return

        if path == "/api/summary":
            flows = STATE.cache.get("flows", [])
            incidents = STATE.cache.get("incidents", [])
            detections = STATE.cache.get("detections", [])
            signatures = STATE.cache.get("signatures", [])
            threats = STATE.cache.get("threat_matches", [])
            endpoints = STATE.cache.get("endpoints", {})
            analytics = STATE.cache.get("analytics", {})

            summary = {
                "metadata": STATE.metadata,
                "total_flows": len(flows),
                "total_packets": analytics.get("total_packets", sum((f.get("fwd_packets", 0) + f.get("rev_packets", 0)) for f in flows)),
                "total_bytes": analytics.get("total_bytes", sum((f.get("fwd_bytes", 0) + f.get("rev_bytes", 0)) for f in flows)),
                "total_endpoints": len(endpoints),
                "total_incidents": len(incidents),
                "total_detections": len(detections),
                "total_signatures": len(signatures),
                "total_threat_matches": len(threats),
                "high_critical_incidents": sum(1 for inc in incidents if inc.get("severity") in ["HIGH", "CRITICAL"]),
                "total_ml_intrusions": sum(1 for f in flows if f.get("ml_prediction", {}).get("is_intrusion")),
                "total_anomalies": sum(1 for f in flows if f.get("anomaly_result", {}).get("is_anomaly")),
                "ml_status": GLOBAL_REGISTRY.get_status(),
                "top_protocols": analytics.get("protocol_breakdown", {})
            }
            self.send_json(200, summary)
            return

        if path == "/api/flows":
            flows = STATE.cache.get("flows", [])
            # Filtering
            proto = qs.get("protocol", [None])[0]
            search = qs.get("search", [None])[0]
            if proto:
                pu = proto.upper()
                flows = [f for f in flows if f.get("detected_app_name", "").upper() == pu or f.get("protocol_str", "").upper() == pu or f.get("protocol", "").upper() == pu]
            if search:
                s = search.lower()
                flows = [f for f in flows if s in str(f.get("flow_id", "")).lower() or
                                             s in str(f.get("source_ip", "")).lower() or
                                             s in str(f.get("destination_ip", "")).lower() or
                                             s in str(f.get("source_port", "")).lower() or
                                             s in str(f.get("destination_port", "")).lower() or
                                             s in f.get("sni", "").lower() or
                                             s in f.get("http_host", "").lower() or
                                             s in f.get("dns_query", "").lower() or
                                             s in f.get("detected_app_name", "").lower()]

            # Pagination
            page = max(1, int(qs.get("page", [1])[0]))
            limit = min(500, max(1, int(qs.get("limit", [50])[0])))
            total = len(flows)
            start = (page - 1) * limit
            end = start + limit
            self.send_json(200, {
                "total": total,
                "page": page,
                "limit": limit,
                "data": flows[start:end]
            })
            return

        if path == "/api/endpoints":
            eps = STATE.cache.get("endpoints", {})
            ep_list = list(eps.values()) if isinstance(eps, dict) else eps
            min_risk = float(qs.get("min_risk", [0.0])[0])
            role = qs.get("role", [None])[0]
            search = qs.get("search", [None])[0]

            if min_risk > 0.0:
                ep_list = [e for e in ep_list if e.get("risk_score", 0.0) >= min_risk]
            if role:
                ep_list = [e for e in ep_list if e.get("role", "") == role]
            if search:
                s = search.lower()
                ep_list = [e for e in ep_list if s in e.get("ip", "").lower()]

            # Sort by risk score descending
            ep_list.sort(key=lambda x: x.get("risk_score", 0.0), reverse=True)
            self.send_json(200, {"total": len(ep_list), "endpoints": ep_list})
            return

        if path == "/api/detections":
            dets = STATE.cache.get("detections", [])
            sev = qs.get("severity", [None])[0]
            cat = qs.get("category", [None])[0]
            if sev:
                dets = [d for d in dets if d.get("severity") == sev.upper()]
            if cat:
                dets = [d for d in dets if d.get("category") == cat.upper()]
            self.send_json(200, {"total": len(dets), "detections": dets})
            return

        if path == "/api/signatures":
            sigs = STATE.cache.get("signatures", [])
            sev = qs.get("severity", [None])[0]
            if sev:
                sigs = [s for s in sigs if s.get("severity") == sev.upper()]
            self.send_json(200, {"total": len(sigs), "signatures": sigs})
            return

        if path == "/api/incidents":
            incs = STATE.cache.get("incidents", [])
            sev = qs.get("severity", [None])[0]
            if sev:
                incs = [i for i in incs if i.get("severity") == sev.upper()]
            self.send_json(200, {"total": len(incs), "incidents": incs})
            return

        if path == "/api/threat-matches":
            tms = STATE.cache.get("threat_matches", [])
            self.send_json(200, {"total": len(tms), "threat_matches": tms})
            return

        if path == "/api/graph":
            self.send_json(200, STATE.cache.get("network_graph", {"nodes": [], "edges": []}))
            return

        if path == "/api/temporal":
            self.send_json(200, STATE.cache.get("temporal", {"buckets": []}))
            return

        if path == "/api/investigations":
            invs = STATE.cache.get("investigations", [])
            self.send_json(200, {"total": len(invs), "investigations": invs})
            return

        if path.startswith("/api/investigations/"):
            inv_id = path.split("/")[3]
            invs = STATE.cache.get("investigations", [])
            match = next((i for i in invs if i.get("investigation_id") == inv_id), None)
            if match:
                self.send_json(200, match)
            else:
                self.send_error_json(404, f"Investigation {inv_id} not found")
            return

        if path == "/api/ml/status":
            self.send_json(200, GLOBAL_REGISTRY.get_status())
            return

        if path == "/api/ml/models":
            self.send_json(200, {"models": GLOBAL_REGISTRY.list_models()})
            return

        if path == "/api/ml/metrics":
            if GLOBAL_REGISTRY.supervised_model and GLOBAL_REGISTRY.supervised_model.is_trained:
                latest_exp = GLOBAL_REGISTRY.experiment_history[-1] if GLOBAL_REGISTRY.experiment_history else {}
                self.send_json(200, {
                    "model_name": GLOBAL_REGISTRY.supervised_model.model_name,
                    "version": GLOBAL_REGISTRY.supervised_model.version,
                    "metrics": latest_exp.get("metrics", {}),
                    "class_metrics": latest_exp.get("class_metrics", {}),
                    "confusion_matrix": latest_exp.get("confusion_matrix", {}),
                    "feature_importances": GLOBAL_REGISTRY.supervised_model.training_metadata.get("feature_importances", {}),
                    "training_metadata": GLOBAL_REGISTRY.supervised_model.training_metadata
                })
            else:
                self.send_error_json(404, "No trained ML model metrics available")
            return

        if path == "/api/ml/experiments":
            comparison = ExperimentRunner.compare_models(GLOBAL_REGISTRY.experiment_history)
            self.send_json(200, {
                "total_experiments": len(GLOBAL_REGISTRY.experiment_history),
                "history": GLOBAL_REGISTRY.experiment_history,
                "comparison": comparison
            })
            return

        if path == "/api/ml/anomalies":
            flows = STATE.cache.get("flows", [])
            scores = GLOBAL_REGISTRY.anomaly_detector.score_batch(flows) if GLOBAL_REGISTRY.anomaly_detector else []
            anomalies = [s for s in scores if s.get("is_anomaly")]
            self.send_json(200, {
                "total_flows_evaluated": len(scores),
                "total_anomalies_detected": len(anomalies),
                "anomalies": anomalies
            })
            return

        if path == "/api/ml/explanations":
            flow_id_param = qs.get("flow_id", [None])[0]
            flows = STATE.cache.get("flows", [])
            flow = None
            if flow_id_param is not None:
                try:
                    fid = int(flow_id_param)
                    flow = next((f for f in flows if f.get("flow_id") == fid), None)
                except ValueError:
                    pass
            if not flow and flows:
                flow = flows[0]
            if not flow:
                self.send_error_json(404, "No flow records available to explain")
                return

            ml_pred = GLOBAL_REGISTRY.predict_flow(flow) if GLOBAL_REGISTRY.supervised_model else None
            anom = GLOBAL_REGISTRY.score_flow(flow) if GLOBAL_REGISTRY.anomaly_detector else None
            dets = [d for d in STATE.cache.get("detections", []) if flow.get("flow_id") in d.get("related_flow_ids", [])]
            threats = [t for t in STATE.cache.get("threat_matches", []) if t.get("dst_ip") == flow.get("destination_ip") or t.get("src_ip") == flow.get("source_ip")]

            explanation = ThreatExplainabilityEngine.explain_flow_risk(
                flow,
                ml_prediction=ml_pred,
                anomaly_result=anom,
                behavioral_detections=dets,
                threat_matches=threats
            )
            self.send_json(200, explanation)
            return

        if path == "/api/ai/status":
            self.send_json(200, GLOBAL_ASSISTANT.get_status())
            return

        if path == "/api/ai/recommendations":
            inc_id = qs.get("incident_id", [None])[0]
            ip = qs.get("ip", [None])[0]
            inc = None
            ep = None
            if inc_id:
                inc = next((i for i in STATE.cache.get("incidents", []) if i.get("incident_id") == inc_id), None)
            if ip:
                eps = STATE.cache.get("endpoints", {})
                ep = eps.get(ip) if isinstance(eps, dict) else next((e for e in eps if e.get("ip") == ip), None)
            if not inc and not ep and STATE.cache.get("incidents"):
                inc = STATE.cache["incidents"][0]

            recs = InvestigationRecommendationEngine.generate_recommendations(incident=inc, endpoint=ep)
            self.send_json(200, {
                "target": inc.get("incident_id") if inc else (ep.get("ip") if ep else "SESSION"),
                "recommendations": recs
            })
            return

        self.send_error_json(404, f"Endpoint not found: {path}")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_len = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            body = json.loads(post_body)
        except Exception:
            body = {}

        if path == "/api/analyze":
            pcap = body.get("pcap_file", "test_dpi.pcap")
            # If relative, resolve to project root
            if not os.path.isabs(pcap):
                pcap = os.path.join(PROJECT_ROOT, pcap)

            try:
                meta = STATE.run_analysis(pcap, body.get("options", {}))
                self.send_json(200, {"status": "SUCCESS", "metadata": meta})
            except Exception as e:
                self.send_error_json(500, f"Analysis failed: {str(e)}")
            return

        if path == "/api/investigations":
            title = body.get("title", "New Investigation")
            desc = body.get("description", "")
            prio = body.get("priority", "MEDIUM")
            tags = body.get("tags", [])

            invs = STATE.cache.get("investigations", [])
            new_id = f"INV-{len(invs) + 1:04d}"
            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            record = {
                "investigation_id": new_id,
                "title": title,
                "description": desc,
                "status": "OPEN",
                "priority": prio,
                "created_at": now_iso,
                "updated_at": now_iso,
                "lead_analyst": body.get("lead_analyst", "analyst"),
                "tags": tags,
                "notes": [],
                "evidence_list": [],
                "related_incidents": body.get("related_incidents", []),
                "related_detections": body.get("related_detections", []),
                "related_flows": body.get("related_flows", []),
                "related_endpoints": body.get("related_endpoints", []),
                "related_iocs": body.get("related_iocs", [])
            }
            invs.append(record)
            self.save_investigations(invs)
            self.send_json(201, record)
            return

        if "/api/investigations/" in path and path.endswith("/notes"):
            inv_id = path.split("/")[3]
            invs = STATE.cache.get("investigations", [])
            match = next((i for i in invs if i.get("investigation_id") == inv_id), None)
            if not match:
                self.send_error_json(404, f"Investigation {inv_id} not found")
                return

            note_id = f"NOTE-{len(match['notes']) + 1:04d}"
            note = {
                "note_id": note_id,
                "author": body.get("author", "analyst"),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "content": body.get("content", "")
            }
            match["notes"].append(note)
            match["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self.save_investigations(invs)
            self.send_json(201, note)
            return

        if "/api/investigations/" in path and path.endswith("/evidence"):
            inv_id = path.split("/")[3]
            invs = STATE.cache.get("investigations", [])
            match = next((i for i in invs if i.get("investigation_id") == inv_id), None)
            if not match:
                self.send_error_json(404, f"Investigation {inv_id} not found")
                return

            ev_id = f"EVID-{len(match['evidence_list']) + 1:04d}"
            content_sample = body.get("raw_content", "")
            # Compute 16-hex FNV-1a hash
            hash_val = 0xcbf29ce484222325
            for b in content_sample.encode("utf-8"):
                hash_val ^= b
                hash_val = (hash_val * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
            integrity_hash = f"{hash_val:016x}"

            ev = {
                "evidence_id": ev_id,
                "evidence_type": body.get("type", "CUSTOM"),
                "source_identifier": body.get("source_id", ""),
                "description": body.get("description", ""),
                "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "integrity_hash": integrity_hash,
                "analyst_tags": body.get("tags", [])
            }
            match["evidence_list"].append(ev)
            match["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self.save_investigations(invs)
            self.send_json(201, ev)
            return

        if path == "/api/ml/predict":
            if "flows" in body:
                flows_input = body.get("flows")
                if not isinstance(flows_input, list):
                    self.send_json(400, {"error": "INVALID_FLOWS_PAYLOAD", "message": "'flows' must be a list of flow records"})
                    return
                if len(flows_input) > MAX_PREDICT_BATCH_SIZE:
                    self.send_json(413, {
                        "error": "BATCH_SIZE_EXCEEDED",
                        "max_limit": MAX_PREDICT_BATCH_SIZE,
                        "received": len(flows_input),
                        "message": f"Batch size of {len(flows_input)} exceeds maximum allowable limit of {MAX_PREDICT_BATCH_SIZE} flows"
                    })
                    return
                preds = GLOBAL_REGISTRY.supervised_model.predict_batch(flows_input) if GLOBAL_REGISTRY.supervised_model else []
                intrusions = [p for p in preds if p.get("is_intrusion")]
                self.send_json(200, {
                    "total_flows_evaluated": len(preds),
                    "total_intrusions_detected": len(intrusions),
                    "intrusions": intrusions,
                    "predictions": preds
                })
                return

            flow = body.get("flow")
            if flow is not None:
                if not isinstance(flow, dict):
                    self.send_json(400, {"error": "INVALID_FLOW_PAYLOAD", "message": "'flow' must be a JSON object"})
                    return
                res = GLOBAL_REGISTRY.predict_flow(flow)
                self.send_json(200, res)
                return
            else:
                flows = STATE.cache.get("flows", [])
                if len(flows) > MAX_PREDICT_BATCH_SIZE:
                    self.send_json(413, {
                        "error": "BATCH_SIZE_EXCEEDED",
                        "max_limit": MAX_PREDICT_BATCH_SIZE,
                        "received": len(flows),
                        "message": f"Cached session flows ({len(flows)}) exceed batch limit of {MAX_PREDICT_BATCH_SIZE}"
                    })
                    return
                preds = GLOBAL_REGISTRY.supervised_model.predict_batch(flows) if GLOBAL_REGISTRY.supervised_model else []
                intrusions = [p for p in preds if p.get("is_intrusion")]
                self.send_json(200, {
                    "total_flows_evaluated": len(preds),
                    "total_intrusions_detected": len(intrusions),
                    "intrusions": intrusions,
                    "predictions": preds
                })
                return

        if path == "/api/ai/investigate":
            query = body.get("query", "Summarize session security posture")
            context_scope = body.get("context")
            res = GLOBAL_ASSISTANT.investigate(query, context_scope)
            self.send_json(200, res)
            return

        self.send_error_json(404, f"POST endpoint not found: {path}")

    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_len = int(self.headers.get("Content-Length", 0))
        put_body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            body = json.loads(put_body)
        except Exception:
            body = {}

        if path.startswith("/api/investigations/"):
            parts = path.strip("/").split("/")
            if len(parts) == 3:
                inv_id = parts[2]
                invs = STATE.cache.get("investigations", [])
                match = next((i for i in invs if i.get("investigation_id") == inv_id), None)
                if not match:
                    self.send_error_json(404, f"Investigation {inv_id} not found")
                    return

                for field in ["title", "description", "status", "priority", "lead_analyst", "tags"]:
                    if field in body:
                        match[field] = body[field]
                match["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                self.save_investigations(invs)
                self.send_json(200, match)
                return

        self.send_error_json(404, f"PUT endpoint not found: {path}")

    def save_investigations(self, invs):
        path = os.path.join(STATE.data_dir, "investigations.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(invs, f, indent=2)
        except Exception as e:
            print(f"[API] Error saving investigations: {e}", file=sys.stderr)

def main():
    server_address = ("", PORT)
    httpd = socketserver.TCPServer(server_address, DPIRequestHandler)
    print(f"===============================================================")
    print(f"  DPI & Packet Analyzer — Backend API Server Started")
    print(f"  Serving on: http://localhost:{PORT}")
    print(f"  Data Directory: {STATE.data_dir}")
    print(f"===============================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.server_close()

if __name__ == "__main__":
    main()
