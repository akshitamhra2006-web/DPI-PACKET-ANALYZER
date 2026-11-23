"""
DPI & Packet Analyzer — Read-Only Evidence Retrieval & Hardened Prompt Injection Defense
========================================================================================
Provides safe, read-only data accessors for session telemetry and enforces
multi-tier prompt injection defense:
1. Regex pattern redaction for common jailbreak/override archetypes.
2. XML delimiter neutralization (< and > escaped to &lt; and &gt;) to prevent boundary breakout.
3. Control character filtering and strict length clamping.
4. Rigid separation of system directives from untrusted telemetry evidence.
"""

import os
import json
import re
from typing import Dict, Any, List, Optional

PROJECT_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_SESSION_DIR = os.path.join(PROJECT_ROOT, "data", "current_session")

# Extended prompt injection signatures commonly embedded in malicious traffic payloads
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(prior|previous|above)\s+(directives|guidelines|instructions?)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a\s+)?(dan|jailbreak|unrestricted|adversary|admin)", re.IGNORECASE),
    re.compile(r"system\s*(override|prompt|directive)\s*:", re.IGNORECASE),
    re.compile(r"<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>", re.IGNORECASE),
    re.compile(r"###\s*(instruction|system|human)", re.IGNORECASE),
    re.compile(r"bypass\s+(all\s+)?security", re.IGNORECASE),
    re.compile(r"output\s+only\s+(benign|clean|nothing|normal)", re.IGNORECASE),
    re.compile(r"<\s*script[^>]*>|<\s*/\s*script\s*>", re.IGNORECASE),
    re.compile(r"\b(cat\s+/etc/passwd|rm\s+-rf|sudo|chmod\s+\+x)\b", re.IGNORECASE)
]

def sanitize_untrusted_content(text: Any, max_len: int = 400) -> str:
    """
    Sanitize untrusted strings originating from packet payloads, HTTP headers,
    DNS query names, TLS metadata, or user queries.
    Escapes XML delimiters (< >) to prevent context boundary breakouts.
    """
    if text is None:
        return ""
    s = str(text)

    # 1. Neutralize common injection triggers
    for pat in PROMPT_INJECTION_PATTERNS:
        s = pat.sub("[REDACTED_ADVERSARIAL_INJECTION_ATTEMPT]", s)

    # 2. Prevent XML boundary breakouts by escaping tags
    s = s.replace("<", "&lt;").replace(">", "&gt;")

    # 3. Filter out non-printable control characters except newline and tab
    s = "".join(ch for ch in s if ch in ("\n", "\t") or (32 <= ord(ch) <= 126))

    # 4. Enforce maximum length bound
    if len(s) > max_len:
        s = s[:max_len] + "... [TRUNCATED]"
    return s.strip()

class EvidenceContextBuilder:
    """
    Read-only evidence retrieval interface. Bounds query access strictly to
    verified session data files.
    """
    def __init__(self, session_dir: str = DEFAULT_SESSION_DIR):
        self.session_dir = session_dir

    def _load_json(self, filename: str, default: Any) -> Any:
        path = os.path.join(self.session_dir, filename)
        if not os.path.exists(path):
            return default
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default

    def get_summary(self) -> Dict[str, Any]:
        flows = self._load_json("flows.json", [])
        incidents = self._load_json("incidents.json", [])
        detections = self._load_json("detections.json", [])
        threats = self._load_json("threat_matches.json", [])
        risk = self._load_json("risk_summary.json", {})
        return {
            "total_flows": len(flows),
            "total_incidents": len(incidents),
            "total_detections": len(detections),
            "total_threat_matches": len(threats),
            "critical_endpoints": risk.get("critical_endpoints", 0),
            "top_risk_endpoints": [e.get("ip") for e in risk.get("top_risk_endpoints", [])[:3]],
            "highest_risk_score": risk.get("top_risk_endpoints", [{}])[0].get("risk_score", 0.0) if risk.get("top_risk_endpoints") else 0.0
        }

    def get_flow_by_id(self, flow_id: int) -> Optional[Dict[str, Any]]:
        flows = self._load_json("flows.json", [])
        return next((f for f in flows if f.get("flow_id") == flow_id), None)

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        incidents = self._load_json("incidents.json", [])
        inc_id = incident_id.upper().strip()
        return next((i for i in incidents if i.get("incident_id", "").upper() == inc_id), None)

    def get_endpoint_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        endpoints = self._load_json("endpoints.json", {})
        if isinstance(endpoints, dict):
            return endpoints.get(ip)
        elif isinstance(endpoints, list):
            return next((e for e in endpoints if e.get("ip") == ip), None)
        return None

    def get_top_endpoints(self, limit: int = 5) -> List[Dict[str, Any]]:
        risk = self._load_json("risk_summary.json", {})
        return risk.get("top_risk_endpoints", [])[:limit]

    def get_detections(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self._load_json("detections.json", [])[:limit]

    def get_threat_matches(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self._load_json("threat_matches.json", [])[:limit]

    def build_sanitized_context(self, scope: Optional[str] = None) -> str:
        """
        Build an isolated, prompt-safe context block for LLM inference.
        All telemetry values are escaped and quarantined.
        """
        summary = self.get_summary()
        top_eps = self.get_top_endpoints(3)
        dets = self.get_detections(5)

        lines = [
            "### VERIFIED SESSION TELEMETRY CONTEXT (READ-ONLY)",
            f"- Total Flows: {summary['total_flows']}",
            f"- Correlated Incidents: {summary['total_incidents']}",
            f"- Behavioral Detections: {summary['total_detections']}",
            f"- Threat IOC Matches: {summary['total_threat_matches']}",
            f"- Critical Endpoints: {summary['critical_endpoints']}",
            "",
            "### TOP RISK HOSTS:"
        ]
        for ep in top_eps:
            ip = sanitize_untrusted_content(ep.get("ip"))
            role = sanitize_untrusted_content(ep.get("role"))
            score = ep.get("risk_score", 0.0)
            level = sanitize_untrusted_content(ep.get("risk_level"))
            lines.append(f"- IP: {ip} | Role: {role} | Risk: {score} ({level})")

        lines.append("\n### RECENT DETECTION ALERTS (SANITIZED):")
        for d in dets:
            clean_expl = sanitize_untrusted_content(d.get('explanation', ''))
            det_id = sanitize_untrusted_content(d.get('detection_id', ''))
            cat = sanitize_untrusted_content(d.get('category', ''))
            sev = sanitize_untrusted_content(d.get('severity', ''))
            lines.append(f"- [{sev}] {det_id}: {cat} - {clean_expl}")

        return "\n".join(lines)
