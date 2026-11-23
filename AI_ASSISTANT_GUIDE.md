# Deep Packet Inspection & Packet Analyzer — AI Security Assistant Guide
**Document Version:** 5.2.0  
**Milestone:** AI Milestone 5.2 — Scientific Remediation & AI Integrity Fixes  
**Applicable Subsystems:** `ai/assistant.py`, `ai/deterministic_engine.py`, `ai/local_llm_client.py`, `ai/context_builder.py`, `web/index.html` (View 12)

---

## 1. Overview & Operating Philosophy

The AI Security Analyst Assistant provides an interactive, natural language investigation interface for security operations center (SOC) analysts and network forensic researchers.

### Operating Philosophy:
1. **Evidence-Grounded**: The assistant never invents or hallucinates network traffic. Every statement must be corroborated by actual packet telemetry, flow records, behavioral heuristics, or signature matches.
2. **Dual-Mode Reliability**: The assistant automatically utilizes a local Large Language Model (via Ollama on `localhost:11434`) when available. If no local LLM is running, it seamlessly operates using the built-in **Deterministic Evidence Engine**, guaranteeing 100% offline availability without third-party cloud services.
3. **Structured 5-Part Forensic Reasoning**: All investigative responses adhere to a standardized 5-part forensic format to eliminate conversational vagueness and provide clear, actionable intelligence.
4. **Normalized Schema Guarantee (Milestone 5.2)**: Both local LLM generation and deterministic fallback modes return a uniform JSON schema containing both `narrative` and the 5 structured sections, ensuring frontend views render consistently regardless of active backend mode.

---

## 2. Local LLM Setup & Configuration (Ollama)

The assistant natively connects to local LLM engines using standard HTTP REST APIs.

### Setup Steps for macOS & Linux:
1. **Install Ollama**:
   - macOS: `brew install ollama` or download from `https://ollama.com/download`
   - Linux: `curl -fsSL https://ollama.com/install.sh | sh`
2. **Start the Ollama Daemon**:
   ```bash
   ollama serve
   ```
   (Runs on `http://127.0.0.1:11434`)
3. **Download Recommended Security Reasoning Models**:
   - For fast, balanced analysis:
     ```bash
     ollama pull mistral:latest
     ```
   - For deep reasoning (if >= 16 GB RAM is available):
     ```bash
     ollama pull llama3:8b
     ```
4. **Verify Connectivity**:
   ```bash
   curl -s http://127.0.0.1:11434/api/tags | jq .
   ```

When the DPI API server starts, it probes `http://127.0.0.1:11434/api/tags` with a 1.5-second timeout. If active, it binds the local LLM and announces:
`[AIAssistant] Bound local LLM: mistral @ http://127.0.0.1:11434`

If Ollama is not running, the system transparently activates the `DeterministicEvidenceEngine`:
`[AIAssistant] No local LLM found. Deterministic evidence engine active (100% offline availability).`

---

## 3. The 5-Part Forensic Reasoning Format

Every investigation query returns a structured report structured into five distinct sections:

```
+--------------------------------------------------------------------------+
| 🔍 1. Observed Facts                                                     |
| Wire-level facts: IPs, ports, protocols, packet counts, duration.        |
+--------------------------------------------------------------------------+
| 📊 2. Correlated Evidence                                                |
| Triggered behavioral rules, signature alert IDs, IOC matches.            |
+--------------------------------------------------------------------------+
| 💡 3. Forensic Interpretation                                            |
| Kill-chain alignment, adversary intent, MITRE ATT&CK categorization.     |
+--------------------------------------------------------------------------+
| ⚠️ 4. Uncertainty & Limitations                                          |
| Visibility gaps, encryption limits, packet truncation, false alert risks.|
+--------------------------------------------------------------------------+
| 🛡️ 5. Recommended Next Steps (Non-Destructive)                           |
| Prioritized SOC response playbooks with zero accidental disruption.      |
+--------------------------------------------------------------------------+
```

### Canonical JSON Response Schema
```json
{
  "mode": "LOCAL_LLM_GENERATIVE" | "DETERMINISTIC_EVIDENCE_ENGINE",
  "llm_available": true | false,
  "query": "Analyst inquiry string",
  "response": {
    "narrative": "Comprehensive forensic synthesis...",
    "observed_facts": ["Fact 1", "Fact 2"],
    "correlated_evidence": ["Evidence 1", "Evidence 2"],
    "interpretation": "Forensic interpretation...",
    "uncertainty_and_limitations": "Visibility boundaries...",
    "recommended_investigation_steps": ["Step 1", "Step 2"]
  }
}
```
*Note: Key aliases (`facts`, `evidence`, `uncertainty_limitations`, `recommendations`) are maintained for backward compatibility.*

---

## 4. Supported Query Catalog & Interactive Inquiries

The assistant parses natural language inquiries across seven core forensic intent categories:

### 1. Host Risk Assessment
- **Example Queries**:
  - *"Which hosts have the highest risk?"*
  - *"Who are the top talkers and what is their risk score?"*
  - *"List high-risk IP endpoints."*
- **Response Focus**: Identifies IP addresses with elevated composite risk scores ($\ge 50.0$), displaying primary roles, traffic volume, and trigger counts.

### 2. Reconnaissance & Port Scans
- **Example Queries**:
  - *"Explain this port scan"*
  - *"Did someone scan our network?"*
  - *"Show reconnaissance activity"*
- **Response Focus**: Correlates rapid sequential SYN requests with zero response bytes, identifies scanner IP (`192.168.1.100`), target range, and probed destination ports.

### 3. Command & Control (C2) Beaconing
- **Example Queries**:
  - *"What patterns indicate possible beaconing?"*
  - *"Are there persistent periodic sessions?"*
  - *"Check for C2 callbacks"*
- **Response Focus**: Analyzes inter-arrival time distributions, low standard deviation jitter, and persistent connections to external infrastructure.

### 4. DNS Anomalies & Data Exfiltration
- **Example Queries**:
  - *"Explain DNS tunneling"*
  - *"Is there suspicious DNS activity?"*
  - *"Check for DNS data exfiltration"*
- **Response Focus**: Examines high-frequency query bursts, anomalous query length entropy, high UDP volume to port 53, and exfiltration characteristics.

### 5. Specific Flow Inquiries
- **Example Queries**:
  - *"Explain flow #8"*
  - *"What happened in flow 12?"*
  - *"Analyze flow #3 and evaluate its risk"*
- **Response Focus**: Fetches precise 5-tuple, packet/byte counts, L7 metadata (SNI/Host/DNS), ML classification label, and multi-factor risk attribution breakdown.

### 6. Incident Deep-Dives
- **Example Queries**:
  - *"Summarize incident INC-0001"*
  - *"What caused incident 2?"*
  - *"Give me a breakdown of active incidents"*
- **Response Focus**: Traces correlated behavioral detections, rule matches, victim endpoints, attack category, and incident timeline.

### 7. SOC Action Playbooks
- **Example Queries**:
  - *"What should I investigate next?"*
  - *"What are the recommended SOC playbooks?"*
  - *"Give me next steps for remediation"*
- **Response Focus**: Returns prioritized, non-destructive SOC playbooks (e.g. host isolation verification, packet PCAP slicing, DNS sinkholing).

---

## 5. Web Dashboard Usage (View 12)

1. Open the dashboard at `http://localhost:8080/`.
2. Click **AI Security Analyst** in the sidebar navigation or navigate to `#ai-analyst`.
3. Inspect the top header status pills:
   - **Assistant Mode**: `DETERMINISTIC_EVIDENCE_ENGINE` or `LOCAL_LLM`
   - **Local LLM**: Shows `ONLINE (mistral)` or `OFFLINE (Deterministic Fallback Active)`
4. Click any of the **Suggested Query Pills** for instant investigation or type a custom question into the chat input bar.
5. In **View 3 (Flow Explorer)**, click the **Explain** button on any flow row to instantly jump to the assistant and generate an in-depth forensic risk breakdown.
