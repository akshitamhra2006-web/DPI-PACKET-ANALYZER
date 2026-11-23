# REST API DOCUMENTATION
## DPI & Packet Analyzer Platform Service

The API server (`server/api_server.py`) provides an HTTP REST interface connecting the modular C++17 DPI engine with web dashboards, automated security pipelines, and external SIEM/SOAR platforms.

- **Base URL:** `http://localhost:8080/`
- **Protocol:** HTTP/1.1
- **Content-Type:** `application/json`
- **Dependencies:** None (Python 3.8+ Standard Library)

---

## 1. System Endpoints

### 1.1 Health Check
```http
GET /api/health
```
**Response (200 OK):**
```json
{
  "status": "UP",
  "version": "4.0.0",
  "timestamp": 1700000000.0,
  "service": "DPI & Packet Analyzer API"
}
```

### 1.2 Session Metadata
```http
GET /api/metadata
```
**Response (200 OK):**
```json
{
  "session_id": "session-1700000000",
  "pcap_file": "test_dpi.pcap",
  "analyzed_at": "2026-11-22T21:39:00Z",
  "duration_seconds": 0.015,
  "engine_version": "4.0.0",
  "status": "SUCCESS"
}
```

### 1.3 Executive Summary
```http
GET /api/summary
```
**Response (200 OK):**
```json
{
  "total_flows": 27,
  "total_packets": 77,
  "total_bytes": 5738,
  "total_endpoints": 22,
  "total_incidents": 1,
  "total_detections": 4,
  "total_signatures": 0,
  "total_threat_matches": 0,
  "high_critical_incidents": 1,
  "top_protocols": {
    "HTTPS": {"flows": 21, "packets": 64, "bytes": 5070},
    "DNS": {"flows": 4, "packets": 8, "bytes": 300},
    "HTTP": {"flows": 2, "packets": 5, "bytes": 368}
  }
}
```

---

## 2. Analysis & Forensics Endpoints

### 2.1 Trigger PCAP Analysis
```http
POST /api/analyze
Content-Type: application/json

{
  "pcap_file": "pcaps/port_scan_recon.pcap",
  "options": {
    "detect": true,
    "incidents": true,
    "signatures": true,
    "threat_intel": true
  }
}
```
**Response (200 OK):**
```json
{
  "status": "SUCCESS",
  "metadata": {
    "session_id": "session-1700000100",
    "pcap_file": "port_scan_recon.pcap",
    "analyzed_at": "2026-11-22T21:40:00Z",
    "duration_seconds": 0.018,
    "status": "SUCCESS"
  }
}
```

### 2.2 Flow Explorer
```http
GET /api/flows?page=1&limit=50&protocol=TCP&search=192.168.1.100
```
**Response (200 OK):**
```json
{
  "total": 1,
  "page": 1,
  "limit": 50,
  "data": [
    {
      "flow_id": 1,
      "initial_tuple": {
        "src_ip": "192.168.1.100",
        "dst_ip": "93.184.216.34",
        "src_port": 49152,
        "dst_port": 443,
        "protocol": 6
      },
      "detected_app_name": "HTTPS",
      "sni": "example.com",
      "fwd": {"packet_count": 4, "byte_count": 512},
      "rev": {"packet_count": 3, "byte_count": 1400},
      "start_time_us": 1600000000000000,
      "last_time_us": 1600000000050000
    }
  ]
}
```

### 2.3 Endpoint Risk Profiles
```http
GET /api/endpoints?min_risk=40.0
```
**Response (200 OK):**
```json
{
  "total": 1,
  "endpoints": [
    {
      "ip": "192.168.1.200",
      "is_internal": true,
      "role": "CLIENT",
      "total_bytes": 2160,
      "total_flows": 40,
      "risk_score": 85.0,
      "risk_level": "CRITICAL",
      "behavioral_tags": ["SCANNER"],
      "contributing_factors": [
        {
          "name": "SECURITY_INCIDENT_INC-0001",
          "weight": 50.0,
          "explanation": "Network Reconnaissance and Scanning Activity"
        }
      ]
    }
  ]
}
```

### 2.4 Correlated Incidents
```http
GET /api/incidents?severity=CRITICAL
```

### 2.5 Relationship Graph
```http
GET /api/graph
```
**Response (200 OK):**
```json
{
  "nodes": [
    {
      "id": "ep:192.168.1.200",
      "label": "192.168.1.200",
      "category": "ENDPOINT",
      "risk_score": 85.0,
      "risk_level": "CRITICAL",
      "role": "CLIENT"
    }
  ],
  "edges": [
    {
      "id": "edge:1",
      "source": "ep:192.168.1.200",
      "target": "ep:10.0.0.50",
      "protocol": "TCP",
      "category": "FLOW",
      "bytes": 1080,
      "packets": 20,
      "weight": 6.06
    }
  ]
}
```

---

## 3. Investigation Workspace Endpoints

### 3.1 List Investigations
```http
GET /api/investigations
```

### 3.2 Create Investigation
```http
POST /api/investigations
Content-Type: application/json

{
  "title": "Port Sweep Assessment",
  "priority": "HIGH",
  "description": "Assessing anomalous TCP SYN burst from workstation 192.168.1.200",
  "tags": ["RECON", "WORKSTATION"]
}
```

### 3.3 Add Analyst Note
```http
POST /api/investigations/INV-0001/notes
Content-Type: application/json

{
  "author": "analyst_alice",
  "content": "Verified target hosts; all ports closed. Likely automated scan script."
}
```

### 3.4 Attach Evidence Reference
```http
POST /api/investigations/INV-0001/evidence
Content-Type: application/json

{
  "type": "DETECTION_ALERT",
  "source_id": "DET-SCAN-V-001",
  "description": "Vertical scan detection record",
  "raw_content": "{...detection json payload...}"
}
```
**Response (201 Created):**
```json
{
  "evidence_id": "EVID-0001",
  "evidence_type": "DETECTION_ALERT",
  "source_identifier": "DET-SCAN-V-001",
  "integrity_hash": "cbf29ce484222325",
  "captured_at": "2026-11-22T21:40:00Z"
}
```
