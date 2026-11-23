# Security Policy & Hardening Guide — DPI & Packet Analyzer

**Platform Version:** `v5.5.0-FINAL`  
**Classification:** Security Architecture, Threat Model, and Vulnerability Disclosure  

---

## 1. Security Overview

The **DPI & Packet Analyzer** platform is designed for enterprise network security monitoring. Because it processes untrusted raw network packets and user-supplied forensic queries, security hardening is applied across all architectural tiers.

---

## 2. Threat Model & Defenses

### 2.1 Malformed & Malicious Packet Captures
- **Threat:** An adversary sends crafted packet headers, truncated frames, or compression bombs to cause heap overflows or CPU denial-of-service.
- **Defenses:**
  - Standard C++17 memory safety tested under AddressSanitizer and UndefinedBehaviorSanitizer (0 errors across 180 tests).
  - Explicit frame slice length checks before pointer offsets are calculated.
  - DNS decompression recursion capped at 10 hops to prevent compression loop denial of service.
  - TCP stream reassembly enforces a 4 MB per-stream limit and total capacity caps.

### 2.2 Dashboard Injection & Cross-Site Scripting (XSS)
- **Threat:** Packet payloads, HTTP user-agents, or DNS query names contain malicious HTML or `<script>` tags designed to execute in the analyst's browser.
- **Defenses:**
  - Strict DOM XSS sanitization across all 12 analytical views using `escapeHtml()`.
  - Zero external CDN dependencies; dashboard runs strictly air-gapped without remote script loading.
  - SVG diagram labels escape text before rendering.

### 2.3 API Attacks & Path Traversal
- **Threat:** Attackers request system files (e.g. `../../../../etc/passwd`) or overwhelm the API server with massive flow payloads.
- **Defenses:**
  - Static file handler enforces directory confinement (`os.path.abspath(filepath).startswith(os.path.abspath(WEB_DIR))`).
  - Batch endpoints enforce a strict maximum size of 5,000 flows with HTTP 413 (`Payload Too Large`).
  - Detailed error messages are suppressed; all errors return structured JSON envelopes.

### 2.4 AI Model Tampering & Prompt Injection
- **Threat:** Malicious model weights are swapped in to bypass detections, or adversarial packet text hijacks the AI Analyst's system prompt.
- **Defenses:**
  - HMAC-SHA256 signatures (`model.joblib.sig`) and SHA-256 manifests (`model_manifest.json`) verify model integrity before deserialization.
  - Untrusted packet data is encapsulated within `<untrusted_traffic_evidence>` XML tags.
  - User queries are sanitized with strict regex filters removing control characters.

---

## 3. Reporting a Vulnerability

If you discover a security vulnerability within the DPI & Packet Analyzer platform:
1. Please do not open a public issue on GitHub.
2. Email security details and reproduction steps to `security@example.com`.
3. Include relevant PCAP captures and operating system details.
4. The security response team will acknowledge receipt within 48 hours and provide a coordinated disclosure timeline.
