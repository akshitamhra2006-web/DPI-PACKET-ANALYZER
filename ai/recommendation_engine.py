"""
DPI & Packet Analyzer — Deterministic Investigation Recommendation Engine
==========================================================================
Produces prioritized, evidence-based SOC investigative recommendations
independent of large language models. Directly maps observed facts, detections,
and incidents to actionable forensic playbooks.
"""

from typing import List, Dict, Any, Optional

class InvestigationRecommendationEngine:
    """
    Analyzes verified session telemetry, correlated incidents, and endpoint profiles
    to generate safe, actionable next-step recommendations for security analysts.
    """

    @staticmethod
    def generate_recommendations(
        incident: Optional[Dict[str, Any]] = None,
        endpoint: Optional[Dict[str, Any]] = None,
        session_summary: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Generate prioritized recommendations based on incident evidence and host posture.
        """
        recommendations = []
        rec_id = 1

        # 1. Incident-Driven Recommendations
        if incident:
            title = incident.get("title", "")
            category = incident.get("category", "")
            target = incident.get("primary_endpoint", "")
            related_flows = incident.get("related_flow_ids", [])
            evidence = incident.get("evidence_summary", [])

            # Reconnaissance / Port Scan
            if "RECONNAISSANCE" in category or "SCAN" in title.upper():
                recommendations.append({
                    "recommendation_id": f"REC-{rec_id:03d}",
                    "priority": "HIGH",
                    "action_title": "Examine Target Sweep Surface & Firewall Logs",
                    "category": "FIREWALL_TRIAGE",
                    "rationale": f"Host {target} initiated anomalous port scanning across multiple targets.",
                    "suggested_steps": [
                        f"Inspect flows: {related_flows[:5]} for TCP SYN/RST patterns.",
                        f"Check host {target} endpoint process tree for nmap, masscan, or port-sweep scripts.",
                        "Verify whether destination target ports (e.g. 445, 22, 3389) are exposed externally."
                    ],
                    "associated_flows": related_flows[:10],
                    "target_host": target
                })
                rec_id += 1

            # C2 Beaconing / Outbound Communication
            if "COMMAND_AND_CONTROL" in category or "BEACON" in title.upper():
                recommendations.append({
                    "recommendation_id": f"REC-{rec_id:03d}",
                    "priority": "CRITICAL",
                    "action_title": "Isolate Host & Validate C2 Listener Reputation",
                    "category": "C2_CONTAINMENT",
                    "rationale": f"Host {target} exhibited periodic, low-jitter beaconing to external infrastructure.",
                    "suggested_steps": [
                        f"Perform OSINT reputation check on destination IP in flows: {related_flows[:3]}.",
                        f"Capture memory dump of {target} to inspect active persistent outbound sockets.",
                        "Examine host startup items, scheduled tasks, and cron jobs for persistence."
                    ],
                    "associated_flows": related_flows[:10],
                    "target_host": target
                })
                rec_id += 1

            # Exfiltration / DNS Tunneling
            if "EXFILTRATION" in category or "DNS" in title.upper():
                recommendations.append({
                    "recommendation_id": f"REC-{rec_id:03d}",
                    "priority": "HIGH",
                    "action_title": "Inspect DNS Resolver Queries & Shannon Entropy",
                    "category": "DNS_FORENSICS",
                    "rationale": f"High query volume or entropy detected for domain queries originating from {target}.",
                    "suggested_steps": [
                        "Review DNS query TXT record payloads for base64/hex data encoding.",
                        f"Query local recursive DNS resolver logs for queries to the tunneling apex domain.",
                        "Check internal host proxy settings and inspect local browser/system DNS cache."
                    ],
                    "associated_flows": related_flows[:10],
                    "target_host": target
                })
                rec_id += 1

            # General incident evidence review
            recommendations.append({
                "recommendation_id": f"REC-{rec_id:03d}",
                "priority": "MEDIUM",
                "action_title": "Attach Correlated Evidence to Investigation Workspace",
                "category": "CASE_MANAGEMENT",
                "rationale": f"Formalize investigation case for incident {incident.get('incident_id')} with {len(evidence)} evidence points.",
                "suggested_steps": [
                    f"Create new investigation ticket linking incident {incident.get('incident_id')}.",
                    "Save relevant PCAP flow segment to evidence ledger with integrity hash.",
                    "Document triage findings and update incident status."
                ],
                "associated_flows": related_flows[:5],
                "target_host": target
            })
            rec_id += 1

        # 2. Endpoint-Driven Recommendations
        if endpoint and not incident:
            ip = endpoint.get("ip", "")
            risk_score = endpoint.get("risk_score", 0.0)
            tags = endpoint.get("behavioral_tags", [])

            if risk_score >= 80.0:
                recommendations.append({
                    "recommendation_id": f"REC-{rec_id:03d}",
                    "priority": "CRITICAL",
                    "action_title": f"Prioritize Deep Forensics on Critical Host {ip}",
                    "category": "ENDPOINT_TRIAGE",
                    "rationale": f"Endpoint has accumulated a critical risk score of {risk_score} based on multiple threat vectors.",
                    "suggested_steps": [
                        f"Filter Flow Explorer for all traffic involving {ip}.",
                        "Verify whether the host is a critical internal server, gateway, or standard workstation.",
                        "Review authentication logs for anomalous logins preceding the alert window."
                    ],
                    "associated_flows": [],
                    "target_host": ip
                })
                rec_id += 1

        # 3. Clean Session / Fallback Recommendations
        if not recommendations:
            recommendations.append({
                "recommendation_id": "REC-001",
                "priority": "LOW",
                "action_title": "Routine Baseline Traffic Monitoring",
                "category": "BASELINE_MONITORING",
                "rationale": "No critical security anomalies or severe incidents detected in the current capture.",
                "suggested_steps": [
                    "Verify flow distribution in Traffic Analytics view matches expected baseline.",
                    "Ensure signature rules and threat intelligence feeds remain up to date.",
                    "Schedule periodic PCAP ingestion for continuous network posture verification."
                ],
                "associated_flows": [],
                "target_host": "N/A"
            })

        return recommendations
