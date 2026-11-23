"""
DPI & Packet Analyzer — Threat Analysis & Machine Learning Explainability Engine
================================================================================
Provides transparent, mathematically rigorous explanations for:
1. Supervised ML prediction feature attribution.
2. Unsupervised anomaly score deviation factors.
3. Multi-factor flow & endpoint risk score breakdown via normalized convex weighting:
   R = 0.35 * R_behavioral + 0.30 * R_threat_intel + 0.20 * R_supervised_ml + 0.15 * R_anomaly
"""

from typing import List, Dict, Any, Optional

SEVERITY_SCORES = {
    "CRITICAL": 100.0,
    "HIGH": 75.0,
    "MEDIUM": 50.0,
    "LOW": 25.0,
    "INFORMATIONAL": 10.0,
    "CLEAN": 0.0
}

THREAT_INTEL_SCORES = {
    "CRITICAL": 100.0,
    "HIGH": 80.0,
    "MEDIUM": 50.0,
    "LOW": 25.0
}

class ThreatExplainabilityEngine:
    """
    Synthesizes ML feature attribution, anomaly indicators, behavioral detections,
    and threat intelligence matches into mathematically normalized, evidence-grounded risk scores.
    """

    @staticmethod
    def explain_flow_risk(
        flow: Dict[str, Any],
        ml_prediction: Optional[Dict[str, Any]] = None,
        anomaly_result: Optional[Dict[str, Any]] = None,
        behavioral_detections: Optional[List[Dict[str, Any]]] = None,
        threat_matches: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Produce a mathematically rigorous, factor-by-factor risk explanation for a specific flow.
        Formula:
          R = 0.35 * R_behavioral + 0.30 * R_threat_intel + 0.20 * R_supervised_ml + 0.15 * R_anomaly
        Each component R_i in [0.0, 100.0], guaranteeing composite R in [0.0, 100.0].
        """
        factors = []

        # 1. Behavioral Detections Component (Weight = 0.35)
        b_dets = behavioral_detections or []
        r_behav = 0.0
        if b_dets:
            max_sev = max([SEVERITY_SCORES.get(d.get("severity", "MEDIUM").upper(), 50.0) for d in b_dets])
            # Small compounding factor for multi-detection confirmation (+5 per additional detection, capped at 100)
            r_behav = min(100.0, max_sev + 5.0 * (len(b_dets) - 1))
            for det in b_dets:
                factors.append({
                    "factor_type": "BEHAVIORAL_ANOMALY",
                    "source": det.get("detection_id", "DET"),
                    "name": det.get("category", "ANOMALY"),
                    "severity": det.get("severity", "MEDIUM"),
                    "description": det.get("explanation", "Behavioral anomaly detected in flow traffic.")
                })

        # 2. Threat Intelligence IOC Component (Weight = 0.30)
        t_matches = threat_matches or []
        r_threat = 0.0
        if t_matches:
            max_ti = max([THREAT_INTEL_SCORES.get(tm.get("severity", "HIGH").upper(), 80.0) for tm in t_matches])
            r_threat = min(100.0, max_ti + 5.0 * (len(t_matches) - 1))
            for tm in t_matches:
                factors.append({
                    "factor_type": "THREAT_INTELLIGENCE_IOC",
                    "source": tm.get("event_id", "IOC-EVT"),
                    "name": f"IOC Match: {tm.get('ioc_value')}",
                    "severity": tm.get("severity", "HIGH"),
                    "description": f"Flow matched known threat indicator ({tm.get('ioc_type')}: {tm.get('ioc_value')}) from dataset {tm.get('dataset_id')}."
                })

        # 3. Supervised Machine Learning Component (Weight = 0.20)
        r_ml = 0.0
        if ml_prediction and ml_prediction.get("is_intrusion"):
            pred_cls = ml_prediction.get("predicted_class", "MALICIOUS")
            conf = float(ml_prediction.get("confidence", 0.5))
            r_ml = min(100.0, max(0.0, conf * 100.0))
            factors.append({
                "factor_type": "SUPERVISED_ML_PREDICTION",
                "source": ml_prediction.get("model_name", "ML-IDS"),
                "name": f"Predicted Intrusion: {pred_cls}",
                "confidence": conf,
                "description": f"Classified as '{pred_cls}' with {round(conf * 100, 1)}% model confidence."
            })

        # 4. Unsupervised Anomaly Detection Component (Weight = 0.15)
        r_anom = 0.0
        anom_status = "NOT_EVALUATED"
        is_anom_active = False

        if anomaly_result:
            anom_status = anomaly_result.get("status", "ACTIVE")
            is_calibrated = anomaly_result.get("is_calibrated", True)
            if anom_status != "INSUFFICIENT_BASELINE_DATA" and is_calibrated and anomaly_result.get("status") != "OFFLINE":
                is_anom_active = True
                if anomaly_result.get("is_anomaly"):
                    anom_score = float(anomaly_result.get("anomaly_score", 0.0))
                    r_anom = min(100.0, max(0.0, anom_score * 100.0))
                    factors.append({
                        "factor_type": "UNSUPERVISED_ANOMALY",
                        "source": anomaly_result.get("model_name", "IsolationForest"),
                        "name": "Statistical Traffic Anomaly",
                        "anomaly_score": anom_score,
                        "description": f"Flow exhibited significant behavioral deviation from baseline (Anomaly Score: {anom_score})."
                    })

        # Compute Fixed-Weight Convex Combination:
        # R = 0.35 * R_behav + 0.30 * R_threat + 0.20 * R_ml + 0.15 * R_anom
        w_behav = 0.35 * r_behav
        w_threat = 0.30 * r_threat
        w_ml = 0.20 * r_ml
        w_anom = 0.15 * r_anom if is_anom_active else 0.0

        final_score = round(min(100.0, max(0.0, w_behav + w_threat + w_ml + w_anom)), 1)

        # Dynamic Active-Channel Normalization:
        # When anomaly detector is offline/uncalibrated, redistribute remaining weight
        # across active channels (sum of active weights = 0.85 instead of 1.00)
        active_weight_sum = 0.35 + 0.30 + 0.20 + (0.15 if is_anom_active else 0.0)
        if is_anom_active and abs(active_weight_sum - 1.0) < 1e-6:
            active_weight_sum = 1.0
            active_normalized_score = final_score
        else:
            active_normalized_score = round(min(100.0, max(0.0, (w_behav + w_threat + w_ml + w_anom) / active_weight_sum)), 1)

        dynamic_weights = {
            "behavioral": round(0.35 / active_weight_sum, 4),
            "threat_intel": round(0.30 / active_weight_sum, 4),
            "supervised_ml": round(0.20 / active_weight_sum, 4),
            "anomaly_detection": round(0.15 / active_weight_sum, 4) if is_anom_active else 0.0
        }

        # Use active_normalized_score for risk level categorization to avoid artificial dampening
        eval_score = active_normalized_score if not is_anom_active else final_score
        risk_level = (
            "CRITICAL" if eval_score >= 80.0 else (
                "HIGH" if eval_score >= 60.0 else (
                    "MEDIUM" if eval_score >= 35.0 else (
                        "LOW" if eval_score > 0.0 else "CLEAN"
                    )
                )
            )
        )

        return {
            "flow_id": flow.get("flow_id", 0),
            "composite_risk_score": final_score,
            "active_normalized_score": active_normalized_score,
            "is_re_normalized": not is_anom_active,
            "active_weight_sum": round(active_weight_sum, 2),
            "risk_level": risk_level,
            "formula": "0.35*R_behavioral + 0.30*R_threat_intel + 0.20*R_supervised_ml + 0.15*R_anomaly",
            "active_formula": f"{dynamic_weights['behavioral']}*R_behavioral + {dynamic_weights['threat_intel']}*R_threat_intel + {dynamic_weights['supervised_ml']}*R_supervised_ml" + (f" + {dynamic_weights['anomaly_detection']}*R_anomaly" if is_anom_active else " (anomaly offline)"),
            "components": {
                "behavioral": {
                    "raw_score": round(r_behav, 1),
                    "fixed_weight": 0.35,
                    "dynamic_weight": dynamic_weights["behavioral"],
                    "weighted_contribution": round(w_behav, 2)
                },
                "threat_intel": {
                    "raw_score": round(r_threat, 1),
                    "fixed_weight": 0.30,
                    "dynamic_weight": dynamic_weights["threat_intel"],
                    "weighted_contribution": round(w_threat, 2)
                },
                "supervised_ml": {
                    "raw_score": round(r_ml, 1),
                    "fixed_weight": 0.20,
                    "dynamic_weight": dynamic_weights["supervised_ml"],
                    "weighted_contribution": round(w_ml, 2)
                },
                "anomaly_detection": {
                    "raw_score": round(r_anom, 1),
                    "fixed_weight": 0.15,
                    "dynamic_weight": dynamic_weights["anomaly_detection"],
                    "weighted_contribution": round(w_anom, 2),
                    "status": anom_status,
                    "is_active": is_anom_active
                }
            },
            "total_contributing_factors": len(factors),
            "factors": factors,
            "narrative_summary": ThreatExplainabilityEngine._generate_risk_narrative(flow, eval_score, risk_level, factors),
            "uncertainty_assessment": ThreatExplainabilityEngine._assess_uncertainty(flow, factors, anom_status)
        }

    @staticmethod
    def _generate_risk_narrative(
        flow: Dict[str, Any],
        score: float,
        level: str,
        factors: List[Dict[str, Any]]
    ) -> str:
        """Construct clear, professional analytical threat narrative."""
        src = flow.get("source_ip", "Unknown")
        dst = flow.get("destination_ip", "Unknown")
        port = flow.get("destination_port", 0)
        proto = flow.get("protocol", "TCP")

        if score == 0.0:
            return f"Traffic between {src} and {dst}:{port} ({proto}) aligns with standard baseline parameters. No anomalies, signature triggers, or threat intelligence hits observed."

        types = set(f["factor_type"] for f in factors)
        reasons = []
        if "BEHAVIORAL_ANOMALY" in types:
            reasons.append("deterministic behavioral scan/surge detection")
        if "THREAT_INTELLIGENCE_IOC" in types:
            reasons.append("verified threat intelligence indicator matches")
        if "SUPERVISED_ML_PREDICTION" in types:
            reasons.append("supervised intrusion classification")
        if "UNSUPERVISED_ANOMALY" in types:
            reasons.append("unsupervised statistical distribution deviations")

        return f"Flow from {src} to {dst}:{port} ({proto}) assigned {level} risk ({score}/100) driven by {', '.join(reasons)}. Correlated with {len(factors)} distinct security evidence factors."

    @staticmethod
    def _assess_uncertainty(flow: Dict[str, Any], factors: List[Dict[str, Any]], anom_status: str) -> Dict[str, Any]:
        """Assess limitations and observational uncertainty in the telemetry."""
        notes = []
        is_encrypted = flow.get("destination_port") == 443 or flow.get("sni") != ""
        if is_encrypted:
            notes.append("Payload contents encrypted via TLS; inspection limited to L4 telemetry and L7 handshake metadata.")
        if flow.get("total_packets", 0) < 3:
            notes.append("Low packet volume (under 3 packets); statistical rate metrics have wide confidence intervals.")
        if anom_status == "INSUFFICIENT_BASELINE_DATA":
            notes.append("Unsupervised anomaly detector offline: benign baseline dataset contains fewer than 10 flows.")

        return {
            "data_completeness": "HIGH" if flow.get("total_packets", 0) >= 3 else "PARTIAL",
            "payload_visibility": "METADATA_ONLY" if is_encrypted else "FULL_LAYER_4_AND_7",
            "anomaly_baseline_status": anom_status,
            "observational_notes": notes
        }
