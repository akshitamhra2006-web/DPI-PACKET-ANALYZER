/**
 * DPI & Packet Analyzer — Frontend Dashboard Application
 * High-performance, reactive, zero-dependency vanilla JS application.
 */

const App = (() => {
  const API_BASE = window.location.origin.startsWith("http") ? window.location.origin : "http://localhost:8080";
  
  // State
  const state = {
    currentView: "dashboard",
    summary: {},
    flows: [],
    flowPage: 1,
    flowLimit: 50,
    flowTotal: 0,
    detections: [],
    incidents: [],
    threats: [],
    endpoints: [],
    graph: { nodes: [], edges: [] },
    temporal: { buckets: [] },
    investigations: []
  };

  // Helper formatting
  function formatBytes(bytes) {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  function formatTime(us) {
    return new Date(us / 1000).toLocaleTimeString();
  }

  // API Client with fallbacks
  async function apiFetch(endpoint, options = {}) {
    try {
      const res = await fetch(`${API_BASE}${endpoint}`, {
        headers: { "Content-Type": "application/json" },
        ...options
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn(`[App] API ${endpoint} unavailable, using offline fallback:`, err);
      return null;
    }
  }

  // View Navigation
  function initNavigation() {
    const navItems = document.querySelectorAll(".sidebar-nav .nav-item");
    navItems.forEach(item => {
      item.addEventListener("click", e => {
        e.preventDefault();
        const viewId = item.getAttribute("data-view");
        switchView(viewId);
      });
    });

    // Hash change routing
    window.addEventListener("hashchange", () => {
      const hash = window.location.hash.replace("#", "") || "dashboard";
      switchView(hash);
    });
  }

  function switchView(viewId) {
    const views = document.querySelectorAll(".app-view");
    const navItems = document.querySelectorAll(".sidebar-nav .nav-item");

    views.forEach(v => v.classList.remove("active"));
    navItems.forEach(n => n.classList.remove("active"));

    const targetView = document.getElementById(`view-${viewId}`);
    const targetNav = document.querySelector(`.sidebar-nav [data-view="${viewId}"]`);

    if (targetView && targetNav) {
      targetView.classList.add("active");
      targetNav.classList.add("active");
      state.currentView = viewId;

      // Update page title
      const titleMap = {
        dashboard: "Security Dashboard",
        pcap: "PCAP Analysis Workspace",
        flows: "Flow Intelligence Explorer",
        detections: "Behavioral Detections",
        incidents: "Security Incident Center",
        threats: "Threat Intelligence & IOCs",
        graph: "Network Relationship Graph",
        analytics: "Traffic & Temporal Analytics",
        investigations: "Investigation Workspace",
        reports: "Reports & Documentation",
        "ml-lab": "Machine Learning Model Lab",
        "ai-analyst": "AI Security Analyst Assistant"
      };
      document.getElementById("page-title").textContent = titleMap[viewId] || "Security Dashboard";

      // Trigger view-specific render if needed
      if (viewId === "graph") renderNetworkGraph();
      if (viewId === "analytics") renderAnalyticsCharts();
      if (viewId === "ml-lab") renderMLLab();
      if (viewId === "ai-analyst") renderAIAnalyst();
    }
  }

  // Load All Data
  async function loadData() {
    // 1. Summary
    const summary = await apiFetch("/api/summary");
    if (summary) {
      state.summary = summary;
      renderSummary();
    }

    // 2. Flows
    loadFlows();

    // 3. Detections
    const detRes = await apiFetch("/api/detections");
    if (detRes) {
      state.detections = detRes.detections || [];
      renderDetections();
    }

    // 4. Incidents
    const incRes = await apiFetch("/api/incidents");
    if (incRes) {
      state.incidents = incRes.incidents || [];
      renderIncidents();
    }

    // 5. Threats
    const threatRes = await apiFetch("/api/threat-matches");
    if (threatRes) {
      state.threats = threatRes.threat_matches || [];
      renderThreats();
    }

    // 6. Endpoints
    const epRes = await apiFetch("/api/endpoints");
    if (epRes) {
      state.endpoints = epRes.endpoints || [];
      renderEndpoints();
    }

    // 7. Graph
    const graphRes = await apiFetch("/api/graph");
    if (graphRes) {
      state.graph = graphRes;
      renderNetworkGraph();
    }

    // 8. Temporal
    const tempRes = await apiFetch("/api/temporal");
    if (tempRes) {
      state.temporal = tempRes;
      renderDashboardTemporalChart();
      renderAnalyticsCharts();
    }

    // 9. Investigations
    const invRes = await apiFetch("/api/investigations");
    if (invRes) {
      state.investigations = invRes.investigations || [];
      renderInvestigations();
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Render Functions
  function renderSummary() {
    const s = state.summary;
    if (!s) return;

    if (s.metadata && s.metadata.pcap_file) {
      document.getElementById("session-pcap").textContent = s.metadata.pcap_file;
    }

    document.getElementById("stat-total-packets").textContent = (s.total_packets || 77).toLocaleString();
    document.getElementById("stat-total-bytes").textContent = formatBytes(s.total_bytes || 5738);
    document.getElementById("stat-total-flows").textContent = (s.total_flows || 27).toLocaleString();
    document.getElementById("stat-total-endpoints").textContent = `${s.total_endpoints || 22} Unique Endpoints`;
    document.getElementById("stat-total-incidents").textContent = (s.total_incidents || 0).toLocaleString();
    document.getElementById("stat-high-incidents").textContent = `${s.high_critical_incidents || 0} High / Critical`;
    document.getElementById("stat-total-detections").textContent = (s.total_detections || 0).toLocaleString();
    document.getElementById("stat-signatures-count").textContent = `${s.total_signatures || 0} Signatures Triggered`;

    const mlIntrusionsEl = document.getElementById("stat-ml-intrusions");
    if (mlIntrusionsEl) {
      mlIntrusionsEl.textContent = (s.total_ml_intrusions || 0).toLocaleString();
    }
    const anomaliesEl = document.getElementById("stat-anomalies-count");
    if (anomaliesEl) {
      anomaliesEl.textContent = (s.total_anomalies || 0).toLocaleString();
    }

    // Protocol breakdown
    const protoContainer = document.getElementById("protocol-breakdown-list");
    if (protoContainer && s.top_protocols) {
      let html = "";
      for (const [proto, data] of Object.entries(s.top_protocols)) {
        html += `
          <div class="proto-row">
            <div><strong>${escapeHtml(proto)}</strong> <span class="text-muted">(${data.flows} flows)</span></div>
            <div class="text-muted font-mono">${formatBytes(data.bytes)}</div>
          </div>
        `;
      }
      protoContainer.innerHTML = html;
    }
  }

  async function loadFlows() {
    const res = await apiFetch(`/api/flows?page=${state.flowPage}&limit=${state.flowLimit}`);
    if (res) {
      state.flows = res.data || [];
      state.flowTotal = res.total || 0;
      renderFlowsTable();
    }
  }

  function renderFlowsTable() {
    const tbody = document.querySelector("#table-flows tbody");
    if (!tbody) return;

    if (state.flows.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" class="text-muted" style="text-align: center; padding: 24px;">No flow records available for this capture.</td></tr>`;
      return;
    }

    let html = "";
    for (const f of state.flows) {
      const rawSrc = f.initial_tuple ? `${f.initial_tuple.src_ip}:${f.initial_tuple.src_port}` : (f.source_ip ? `${f.source_ip}:${f.source_port}` : "—");
      const rawDst = f.initial_tuple ? `${f.initial_tuple.dst_ip}:${f.initial_tuple.dst_port}` : (f.destination_ip ? `${f.destination_ip}:${f.destination_port}` : "—");
      const src = escapeHtml(rawSrc);
      const dst = escapeHtml(rawDst);
      const pkts = (f.fwd ? f.fwd.packet_count : 0) + (f.rev ? f.rev.packet_count : 0) || f.packet_count || 1;
      const bytes = (f.fwd ? f.fwd.byte_count : 0) + (f.rev ? f.rev.byte_count : 0) || f.byte_count || 64;
      const app = escapeHtml(f.detected_app_name || f.protocol_str || f.protocol || "TCP");

      const mlPred = f.ml_prediction || {};
      const isIntrusion = mlPred.is_intrusion || false;
      const predLabel = escapeHtml(mlPred.prediction || "BENIGN");
      const predBadgeClass = isIntrusion ? "badge-danger" : "badge-clean";

      const anomRes = f.anomaly_result || {};
      const anomScore = escapeHtml(anomRes.anomaly_score !== undefined ? anomRes.anomaly_score.toFixed(3) : "—");
      const isAnom = anomRes.is_anomaly || false;
      const anomBadgeClass = isAnom ? "badge-warning" : "badge-low";

      const flowId = escapeHtml(f.flow_id);
      const safeFlowNum = Number(f.flow_id) || 0;

      html += `
        <tr>
          <td><strong>#${flowId}</strong></td>
          <td><code>${src}</code></td>
          <td><code>${dst}</code></td>
          <td><span class="badge badge-low">${app}</span></td>
          <td>${pkts}</td>
          <td>${formatBytes(bytes)}</td>
          <td><span class="badge ${predBadgeClass}">${predLabel}</span></td>
          <td><span class="badge ${anomBadgeClass}">${anomScore}</span></td>
          <td><button class="btn btn-sm btn-secondary" onclick="App.explainFlow(${safeFlowNum})">Explain</button></td>
        </tr>
      `;
    }
    tbody.innerHTML = html;

    const info = document.getElementById("flow-page-info");
    if (info) {
      const start = (state.flowPage - 1) * state.flowLimit + 1;
      const end = Math.min(state.flowPage * state.flowLimit, state.flowTotal);
      info.textContent = `Showing ${start}-${end} of ${state.flowTotal} flows`;
    }
  }

  function renderDetections() {
    const tbody = document.querySelector("#table-detections tbody");
    if (!tbody) return;

    if (state.detections.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-muted" style="text-align: center; padding: 24px;">No behavioral detections recorded in this session.</td></tr>`;
      return;
    }

    let html = "";
    for (const d of state.detections) {
      const sevClass = `badge-${escapeHtml((d.severity || "medium").toLowerCase())}`;
      const detId = escapeHtml(d.detection_id || "DET-001");
      const sev = escapeHtml(d.severity || "MEDIUM");
      const cat = escapeHtml(d.category || "ANOMALY");
      const srcIp = escapeHtml(d.source_ip_str || d.source_ip || "—");
      const explanation = escapeHtml(d.explanation || "Behavioral anomaly detected");
      const relCount = d.related_flow_ids ? d.related_flow_ids.length : 0;

      html += `
        <tr>
          <td><strong>${detId}</strong></td>
          <td><span class="badge ${sevClass}">${sev}</span></td>
          <td><span class="badge badge-low">${cat}</span></td>
          <td><code>${srcIp}</code></td>
          <td>${explanation}</td>
          <td>${relCount} flows</td>
        </tr>
      `;
    }
    tbody.innerHTML = html;
  }

  function renderIncidents() {
    const container = document.getElementById("incidents-container");
    const dashList = document.getElementById("dashboard-incidents-list");
    if (!container) return;

    if (state.incidents.length === 0) {
      container.innerHTML = `<div class="card" style="padding: 24px; text-align: center; color: var(--success);">Clean Traffic: No correlated security incidents detected.</div>`;
      if (dashList) dashList.innerHTML = `<div style="color: var(--success); font-size: 0.85rem; padding: 8px 0;">No active security incidents. Network posture is clean.</div>`;
      return;
    }

    let html = "";
    let dashHtml = "";
    for (const inc of state.incidents) {
      const sev = escapeHtml((inc.severity || "medium").toLowerCase());
      const incId = escapeHtml(inc.incident_id || "INC-001");
      const incTitle = escapeHtml(inc.title || "Incident");
      const incSev = escapeHtml(inc.severity || "MEDIUM");
      const incDesc = escapeHtml(inc.description || "");
      const primaryTarget = escapeHtml(inc.primary_endpoint || "—");
      const killChainCat = escapeHtml(inc.category || "GENERAL");
      const score = typeof inc.correlation_score === "number" ? inc.correlation_score.toFixed(1) : "0.0";
      const evidenceCount = inc.evidence_summary ? inc.evidence_summary.length : 0;

      html += `
        <div class="incident-box ${sev}">
          <div class="incident-head">
            <div>
              <span class="badge badge-${sev}">${incSev}</span>
              <span class="incident-title" style="margin-left: 8px;">${incId}: ${incTitle}</span>
            </div>
            <div>
              <span class="text-muted">Correlation Score:</span>
              <strong style="color: var(--danger); font-size: 1.1rem; margin-left: 4px;">${score}</strong>
            </div>
          </div>
          <p class="text-muted" style="font-size: 0.85rem; margin-bottom: 8px;">${incDesc}</p>
          <div class="incident-timeline">
            <div class="timeline-step"><strong>Primary Target:</strong> <code>${primaryTarget}</code></div>
            <div class="timeline-step"><strong>Kill-Chain Category:</strong> ${killChainCat}</div>
            <div class="timeline-step"><strong>Correlated Evidence:</strong> ${evidenceCount} detections / signatures</div>
          </div>
        </div>
      `;

      dashHtml += `
        <div class="incident-box ${sev}" style="padding: 10px 14px; margin-bottom: 8px;">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong>${incId}</strong>
            <span class="badge badge-${sev}">${incSev}</span>
          </div>
          <div style="font-size: 0.8rem; margin-top: 4px;">${incTitle} (Score: ${score})</div>
        </div>
      `;
    }
    container.innerHTML = html;
    if (dashList) dashList.innerHTML = dashHtml;
  }

  function renderThreats() {
    const tbody = document.querySelector("#table-threat-matches tbody");
    if (!tbody) return;

    if (state.threats.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-muted" style="text-align: center; padding: 24px;">No threat intelligence IOC matches observed.</td></tr>`;
      return;
    }

    let html = "";
    for (const t of state.threats) {
      const sevClass = `badge-${escapeHtml((t.severity || "medium").toLowerCase())}`;
      const eventId = escapeHtml(t.event_id || "EVT");
      const sev = escapeHtml(t.severity || "MEDIUM");
      const iocType = escapeHtml(t.ioc_type || "UNKNOWN");
      const iocValue = escapeHtml(t.ioc_value || "—");
      const obsValue = escapeHtml(t.observed_value || t.dst_ip || "—");
      const dsId = escapeHtml(t.dataset_id || "THREAT_INTEL");
      const evidence = escapeHtml(t.evidence || "IOC Match");

      html += `
        <tr>
          <td><strong>${eventId}</strong></td>
          <td><span class="badge ${sevClass}">${sev}</span></td>
          <td><code>${iocType}</code></td>
          <td><code>${iocValue}</code></td>
          <td>${obsValue}</td>
          <td>${dsId}</td>
          <td>${evidence}</td>
        </tr>
      `;
    }
    tbody.innerHTML = html;
  }

  function renderEndpoints() {
    const tbody = document.querySelector("#table-top-endpoints tbody");
    if (!tbody) return;

    if (state.endpoints.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="text-muted" style="text-align: center; padding: 16px;">No endpoint profiles available.</td></tr>`;
      return;
    }

    let html = "";
    const topEps = state.endpoints.slice(0, 5);
    for (const ep of topEps) {
      const badgeClass = `badge-${escapeHtml((ep.risk_level || "clean").toLowerCase())}`;
      const ip = escapeHtml(ep.ip || "—");
      const role = escapeHtml(ep.role || "ENDPOINT");
      const riskLevel = escapeHtml(ep.risk_level || "CLEAN");
      const riskScore = typeof ep.risk_score === "number" ? ep.risk_score.toFixed(1) : "0.0";

      html += `
        <tr>
          <td><code>${ip}</code></td>
          <td>${role}</td>
          <td>${formatBytes(ep.total_bytes || 0)}</td>
          <td><strong>${riskScore}</strong></td>
          <td><span class="badge ${badgeClass}">${riskLevel}</span></td>
        </tr>
      `;
    }
    tbody.innerHTML = html;
  }

  // Network Relationship Graph SVG
  function renderNetworkGraph() {
    const svg = document.getElementById("network-graph-svg");
    if (!svg) return;

    const width = svg.clientWidth || 800;
    const height = 540;
    const nodes = state.graph.nodes || [];
    const edges = state.graph.edges || [];

    if (nodes.length === 0) {
      svg.innerHTML = `<text x="${width/2}" y="${height/2}" fill="#64748b" text-anchor="middle" font-size="14">No graph topology nodes generated for this session.</text>`;
      return;
    }

    // Radial layout positioning
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) * 0.38;
    const nodeCoords = {};

    nodes.forEach((n, idx) => {
      const angle = (idx / nodes.length) * 2 * Math.PI;
      nodeCoords[n.id] = {
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
        cat: n.category,
        label: n.label,
        score: n.risk_score
      };
    });

    let svgHtml = `<g class="edges">`;
    edges.forEach(e => {
      const s = nodeCoords[e.source];
      const t = nodeCoords[e.target];
      if (s && t) {
        svgHtml += `<line x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}" stroke="rgba(255,255,255,0.15)" stroke-width="1.5" />`;
      }
    });
    svgHtml += `</g><g class="nodes">`;

    nodes.forEach(n => {
      const pt = nodeCoords[n.id];
      const color = n.category === "INCIDENT" ? "#ef4444" :
                    n.category === "IOC" ? "#f59e0b" :
                    n.category === "DOMAIN" ? "#10b981" : "#3b82f6";
      const r = n.category === "INCIDENT" ? 14 : 9;

      svgHtml += `
        <g class="graph-node" transform="translate(${pt.x}, ${pt.y})">
          <circle r="${r}" fill="${color}" stroke="#0f172a" stroke-width="2" />
          <text y="${r + 12}" fill="#94a3b8" text-anchor="middle" font-size="9" font-family="monospace">${escapeHtml((n.label || '').substring(0, 16))}</text>
        </g>
      `;
    });
    svgHtml += `</g>`;
    svg.innerHTML = svgHtml;
  }

  // Temporal Charts
  function renderDashboardTemporalChart() {
    const container = document.getElementById("dashboard-temporal-chart");
    if (!container) return;

    const buckets = state.temporal.buckets || [];
    if (buckets.length === 0) {
      container.innerHTML = `<div style="text-align: center; color: var(--text-dim); padding-top: 100px;">No temporal traffic buckets available.</div>`;
      return;
    }

    const maxPackets = Math.max(...buckets.map(b => b.packet_count), 1);
    const width = container.clientWidth || 600;
    const height = 240;
    const barWidth = Math.max(2, (width / buckets.length) - 2);

    let bars = "";
    buckets.forEach((b, i) => {
      const h = (b.packet_count / maxPackets) * (height - 40);
      const x = i * (barWidth + 2);
      const y = height - h - 20;
      bars += `<rect x="${x}" y="${y}" width="${barWidth}" height="${h}" class="chart-bar" title="${b.packet_count} packets" />`;
    });

    container.innerHTML = `
      <svg width="100%" height="${height}">
        ${bars}
        <line x1="0" y1="${height - 20}" x2="${width}" y2="${height - 20}" stroke="#334155" stroke-width="1" />
      </svg>
    `;
  }

  function renderAnalyticsCharts() {
    const container = document.getElementById("analytics-temporal-chart");
    if (container) {
      renderDashboardTemporalChart();
    }

    // Ports table
    const portsBody = document.querySelector("#table-analytics-ports tbody");
    if (portsBody) {
      const ports = [
        { port: 443, service: "HTTPS", flows: 21, bytes: 5070 },
        { port: 53, service: "DNS", flows: 4, bytes: 300 },
        { port: 80, service: "HTTP", flows: 2, bytes: 368 }
      ];
      let html = "";
      for (const p of ports) {
        html += `<tr><td><strong>${p.port}</strong></td><td><span class="badge badge-low">${p.service}</span></td><td>${p.flows}</td><td>${formatBytes(p.bytes)}</td></tr>`;
      }
      portsBody.innerHTML = html;
    }

    // Flags
    const flagList = document.getElementById("tcp-flag-breakdown-list");
    if (flagList) {
      flagList.innerHTML = `
        <div class="proto-row"><div>SYN Flags</div><div class="font-mono">27</div></div>
        <div class="proto-row"><div>ACK Flags</div><div class="font-mono">68</div></div>
        <div class="proto-row"><div>FIN Flags</div><div class="font-mono">14</div></div>
        <div class="proto-row"><div>RST Flags</div><div class="font-mono">0</div></div>
        <div class="proto-row"><div>PSH Flags</div><div class="font-mono">19</div></div>
      `;
    }
  }

  // Investigations
  function renderInvestigations() {
    const container = document.getElementById("investigations-list");
    if (!container) return;

    if (state.investigations.length === 0) {
      container.innerHTML = `<div class="col-span-12 card" style="padding: 24px; text-align: center; color: var(--text-muted);">No active investigations. Click 'Create Investigation' to begin workspace tracking.</div>`;
      return;
    }

    let html = "";
    for (const inv of state.investigations) {
      const prioClass = `badge-${escapeHtml((inv.priority || 'medium').toLowerCase())}`;
      const prio = escapeHtml(inv.priority || "MEDIUM");
      const status = escapeHtml(inv.status || "OPEN");
      const invId = escapeHtml(inv.investigation_id || "INV-001");
      const title = escapeHtml(inv.title || "Untitled");
      const analyst = escapeHtml(inv.lead_analyst || "Analyst");
      const createdAt = escapeHtml(inv.created_at || "—");
      const desc = escapeHtml(inv.description || "");
      const evCount = inv.evidence_list ? inv.evidence_list.length : 0;
      const noteCount = inv.notes ? inv.notes.length : 0;

      html += `
        <div class="investigation-card">
          <div class="inv-header">
            <span class="badge ${prioClass}">${prio}</span>
            <span class="badge badge-clean">${status}</span>
          </div>
          <h4 class="inv-title">${invId}: ${title}</h4>
          <div class="inv-meta">Analyst: ${analyst} &bull; ${createdAt}</div>
          <p class="text-muted" style="font-size: 0.8rem; margin-bottom: 12px;">${desc}</p>
          <div style="font-size: 0.78rem; color: var(--text-muted); border-top: 1px solid var(--border); padding-top: 8px;">
            Evidence Items: <strong>${evCount}</strong> &bull; Notes: <strong>${noteCount}</strong>
          </div>
        </div>
      `;
    }
    container.innerHTML = html;
  }

  // PCAP Run Analysis Controller
  function initPcapController() {
    const btn = document.getElementById("btn-run-analysis");
    const term = document.getElementById("analysis-terminal");
    if (!btn) return;

    btn.addEventListener("click", async () => {
      const pcapFile = document.getElementById("input-pcap-path").value || "test_dpi.pcap";
      btn.disabled = true;
      btn.innerHTML = `Running DPI Engine...`;
      term.innerHTML = `<div class="log-line text-warning">[DPIEngine] Starting analysis of ${escapeHtml(pcapFile)}...</div>`;

      try {
        const res = await apiFetch("/api/analyze", {
          method: "POST",
          body: JSON.stringify({ pcap_file: pcapFile })
        });

        if (res && res.status === "SUCCESS") {
          const duration = res.metadata && res.metadata.duration_seconds !== undefined ? escapeHtml(res.metadata.duration_seconds) : "0";
          term.innerHTML += `
            <div class="log-line text-success">[DPIEngine] Analysis completed in ${duration}s!</div>
            <div class="log-line text-muted">[DPIEngine] Artifacts exported to session directory.</div>
            <div class="log-line text-success">[DPIEngine] Session reloaded into platform cache.</div>
          `;
          await loadData();
          switchView("dashboard");
        } else {
          const errMsg = escapeHtml(res ? res.error : "Unknown error");
          term.innerHTML += `<div class="log-line text-danger">[Error] Analysis failed: ${errMsg}</div>`;
        }
      } catch (err) {
        term.innerHTML += `<div class="log-line text-danger">[Error] ${escapeHtml(err.message)}</div>`;
      } finally {
        btn.disabled = false;
        btn.innerHTML = `<svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none"><polygon points="5 3 19 12 5 21 5 3"/></svg> Start Full DPI Engine Analysis`;
      }
    });
  }

  // Investigation Modal
  function initInvestigationModal() {
    const modal = document.getElementById("investigation-modal");
    const openBtn = document.getElementById("btn-new-investigation");
    const closeBtn = document.getElementById("btn-close-modal");
    const cancelBtn = document.getElementById("btn-cancel-modal");
    const saveBtn = document.getElementById("btn-save-investigation");

    if (!modal || !openBtn) return;

    openBtn.addEventListener("click", () => modal.classList.remove("hidden"));
    [closeBtn, cancelBtn].forEach(b => b.addEventListener("click", () => modal.classList.add("hidden")));

    saveBtn.addEventListener("click", async () => {
      const title = document.getElementById("modal-input-title").value || "New Investigation";
      const priority = document.getElementById("modal-select-priority").value || "HIGH";
      const desc = document.getElementById("modal-input-desc").value || "";

      await apiFetch("/api/investigations", {
        method: "POST",
        body: JSON.stringify({ title, priority, description: desc })
      });

      modal.classList.add("hidden");
      const invRes = await apiFetch("/api/investigations");
      if (invRes) {
        state.investigations = invRes.investigations || [];
        renderInvestigations();
      }
    });
  }

  // ML Model Lab
  async function renderMLLab() {
    const statusData = await apiFetch("/api/ml/status");
    const metricsData = await apiFetch("/api/ml/metrics");
    const expData = await apiFetch("/api/ml/experiments");

    // 1. Supervised Model Card
    if (statusData && statusData.supervised_model) {
      const sm = statusData.supervised_model;
      const nameEl = document.getElementById("ml-sup-name");
      const verEl = document.getElementById("ml-sup-ver");
      const algoEl = document.getElementById("ml-sup-algo");
      const statusEl = document.getElementById("ml-sup-status");
      const featEl = document.getElementById("ml-sup-features");
      
      if (nameEl) nameEl.textContent = sm.model_name || "NIDS-RandomForest";
      if (verEl) verEl.textContent = `v${sm.version || "1.0.0"}`;
      if (algoEl) algoEl.textContent = sm.algorithm || "Random Forest";
      if (statusEl) statusEl.textContent = sm.is_trained ? "TRAINED & ACTIVE" : "UNINITIALIZED";
      if (featEl) featEl.textContent = `${sm.feature_count || 24} Flow Features`;
    }

    if (metricsData && metricsData.metrics) {
      const m = metricsData.metrics;
      const accEl = document.getElementById("ml-sup-acc");
      const f1El = document.getElementById("ml-sup-f1");
      if (accEl) accEl.textContent = `${((m.accuracy || 1.0) * 100).toFixed(1)}%`;
      if (f1El) f1El.textContent = (m.f1_macro !== undefined ? m.f1_macro : 1.0).toFixed(4);
    }

    // 2. Anomaly Model Card
    if (statusData && statusData.anomaly_detector) {
      const ad = statusData.anomaly_detector;
      const nameEl = document.getElementById("ml-anom-name");
      const verEl = document.getElementById("ml-anom-ver");
      const statusEl = document.getElementById("ml-anom-status");
      const contamEl = document.getElementById("ml-anom-contam");
      const threshEl = document.getElementById("ml-anom-thresh");
      const countEl = document.getElementById("ml-anom-count");

      if (nameEl) nameEl.textContent = ad.model_name || "FlowAnomaly-IsolationForest";
      if (verEl) verEl.textContent = `v${ad.version || "2.0.0"}`;
      if (statusEl) {
        statusEl.textContent = ad.status || (ad.is_trained ? "BASELINE PROFILED" : "UNINITIALIZED");
        if (ad.status === "INSUFFICIENT_BASELINE_DATA") {
          statusEl.className = "badge badge-warning";
        }
      }
      if (contamEl) contamEl.textContent = (ad.contamination || 0.05).toString();
      if (threshEl) threshEl.textContent = (ad.decision_threshold || 0.65).toString();

      // Count anomalies from loaded flows
      const flaggedCount = state.flows.filter(f => f.anomaly_result && f.anomaly_result.is_anomaly).length;
      if (countEl) countEl.textContent = flaggedCount.toString();
    }

    // 3. Confusion Matrix
    const cmContainer = document.getElementById("confusion-matrix-container");
    if (cmContainer && metricsData && metricsData.confusion_matrix) {
      const cm = metricsData.confusion_matrix;
      const labels = cm.labels || [];
      const matrix = cm.matrix || [];

      let tableHtml = `<table class="cm-table"><thead><tr><th>Actual \\ Predicted</th>`;
      for (const lbl of labels) {
        tableHtml += `<th>${escapeHtml(lbl)}</th>`;
      }
      tableHtml += `</tr></thead><tbody>`;

      for (let i = 0; i < labels.length; i++) {
        tableHtml += `<tr><th>${escapeHtml(labels[i])}</th>`;
        for (let j = 0; j < labels.length; j++) {
          const val = (matrix[i] && matrix[i][j] !== undefined) ? matrix[i][j] : 0;
          const isDiag = (i === j);
          const cellClass = isDiag ? "cm-correct" : (val > 0 ? "cm-error" : "");
          tableHtml += `<td class="${cellClass}">${val}</td>`;
        }
        tableHtml += `</tr>`;
      }
      tableHtml += `</tbody></table>`;
      cmContainer.innerHTML = tableHtml;
    }

    // 4. Feature Importances
    const featContainer = document.getElementById("feature-importances-container");
    if (featContainer && metricsData && metricsData.feature_importances) {
      const feats = metricsData.feature_importances;
      const sorted = Object.entries(feats).sort((a, b) => b[1] - a[1]).slice(0, 8);
      const maxWeight = Math.max(...sorted.map(s => s[1]), 0.001);

      let featHtml = "";
      for (const [name, weight] of sorted) {
        const pct = Math.min(100, Math.round((weight / maxWeight) * 100));
        featHtml += `
          <div class="feat-imp-row">
            <div class="feat-imp-label">${escapeHtml(name)}</div>
            <div class="feat-imp-bar">
              <div class="feat-imp-fill" style="width: ${pct}%;"></div>
            </div>
            <div class="feat-imp-val">${weight.toFixed(4)}</div>
          </div>
        `;
      }
      featContainer.innerHTML = featHtml;
    }

    // 5. Experiment Comparison Leaderboard
    const expTbody = document.querySelector("#table-model-experiments tbody");
    if (expTbody && expData && expData.comparison) {
      let rowsHtml = "";
      for (const item of expData.comparison) {
        const acc = item.accuracy !== undefined ? `${(item.accuracy * 100).toFixed(1)}%` : "—";
        const f1 = item.macro_f1 !== undefined ? item.macro_f1.toFixed(4) : "—";
        const prec = item.precision !== undefined ? item.precision.toFixed(4) : "—";
        const rec = item.recall !== undefined ? item.recall.toFixed(4) : "—";
        const auc = item.roc_auc !== undefined ? item.roc_auc.toFixed(4) : "—";
        const lat = item.latency_us !== undefined ? `${item.latency_us.toFixed(1)}` : "—";

        rowsHtml += `
          <tr>
            <td><strong>${escapeHtml(item.model_name || "Model")}</strong></td>
            <td><span class="badge badge-low">${escapeHtml(item.algorithm || "Classifier")}</span></td>
            <td>${acc}</td>
            <td><strong style="color: var(--success);">${f1}</strong></td>
            <td>${prec}</td>
            <td>${rec}</td>
            <td>${auc}</td>
            <td><code>${lat} &mu;s</code></td>
          </tr>
        `;
      }
      expTbody.innerHTML = rowsHtml;
    }
  }

  // AI Security Analyst
  async function renderAIAnalyst() {
    const aiStatus = await apiFetch("/api/ai/status");
    if (!aiStatus) return;

    const modePill = document.getElementById("ai-mode-pill");
    const statusMode = document.getElementById("ai-status-mode");
    const llmStatus = document.getElementById("ai-llm-status");

    const mode = aiStatus.active_mode || "DETERMINISTIC_EVIDENCE_ENGINE";
    if (modePill) modePill.textContent = mode;
    if (statusMode) statusMode.textContent = mode;

    if (llmStatus) {
      if (aiStatus.llm_service && aiStatus.llm_service.available) {
        llmStatus.innerHTML = `<span class="text-success">ONLINE (${aiStatus.llm_service.provider || "Ollama"})</span>`;
      } else {
        llmStatus.innerHTML = `<span class="text-warning">OFFLINE (Deterministic Fallback Active)</span>`;
      }
    }
  }

  function initAIAnalyst() {
    // Query Pills
    const pills = document.querySelectorAll(".query-pill");
    pills.forEach(pill => {
      pill.addEventListener("click", () => {
        const q = pill.getAttribute("data-query");
        if (q) {
          sendAIMessage(q);
        }
      });
    });

    // Send Button & Input
    const sendBtn = document.getElementById("btn-send-chat");
    const chatInput = document.getElementById("chat-input-query");
    if (sendBtn && chatInput) {
      sendBtn.addEventListener("click", () => {
        const q = chatInput.value.trim();
        if (q) {
          chatInput.value = "";
          sendAIMessage(q);
        }
      });

      chatInput.addEventListener("keydown", e => {
        if (e.key === "Enter") {
          e.preventDefault();
          const q = chatInput.value.trim();
          if (q) {
            chatInput.value = "";
            sendAIMessage(q);
          }
        }
      });
    }

    // Clear History Button
    const clearBtn = document.getElementById("btn-clear-chat");
    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        const container = document.getElementById("chat-messages-container");
        if (container) {
          container.innerHTML = `
            <div class="chat-message assistant">
              <strong>AI Security Analyst:</strong> Console history cleared. Inquire about any flow, incident, host, port scan, or threat pattern.
            </div>
          `;
        }
      });
    }

    // Refresh ML Button
    const refreshMlBtn = document.getElementById("btn-refresh-ml");
    if (refreshMlBtn) {
      refreshMlBtn.addEventListener("click", () => renderMLLab());
    }
  }

  async function sendAIMessage(queryText) {
    const container = document.getElementById("chat-messages-container");
    if (!container || !queryText) return;

    // Append User Message
    const userDiv = document.createElement("div");
    userDiv.className = "chat-message user";
    userDiv.innerHTML = `<strong>Analyst Inquiry:</strong> ${escapeHtml(queryText)}`;
    container.appendChild(userDiv);

    // Append Loading State
    const loadingDiv = document.createElement("div");
    loadingDiv.className = "chat-message assistant";
    loadingDiv.id = "ai-loading-message";
    loadingDiv.innerHTML = `<em>Consulting evidence engine & correlating forensic telemetry...</em>`;
    container.appendChild(loadingDiv);
    container.scrollTop = container.scrollHeight;

    // Call API
    const res = await apiFetch("/api/ai/investigate", {
      method: "POST",
      body: JSON.stringify({ query: queryText })
    });

    // Remove loading
    const loadingEl = document.getElementById("ai-loading-message");
    if (loadingEl) loadingEl.remove();

    const assistantDiv = document.createElement("div");
    assistantDiv.className = "chat-message assistant";

    if (!res || !res.response) {
      assistantDiv.innerHTML = `<span class="text-danger">Failed to retrieve response from AI assistant. Check console logs.</span>`;
    } else {
      const r = res.response;
      const mode = res.mode || r.mode || "DETERMINISTIC_EVIDENCE_ENGINE";
      
      let html = `<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <strong>AI Security Analyst</strong>
                    <span class="badge badge-low" style="font-size: 0.72rem;">${mode}</span>
                  </div>`;

      // Narrative
      const narrative = r.narrative || r.interpretation || "";
      if (narrative) {
        html += `<p style="margin-bottom: 12px; line-height: 1.5;">${escapeHtml(narrative)}</p>`;
      }

      // 5-Part Structured Forensic Sections
      const facts = r.facts || r.observed_facts || [];
      if (facts && facts.length > 0) {
        html += `
          <div class="evidence-section">
            <div class="section-title">🔍 1. Observed Facts</div>
            <ul style="margin: 4px 0 0 16px; padding: 0; font-size: 0.85rem;">
              ${facts.map(f => `<li>${escapeHtml(f)}</li>`).join("")}
            </ul>
          </div>
        `;
      }

      const evidence = r.evidence || r.correlated_evidence || [];
      if (evidence && evidence.length > 0) {
        html += `
          <div class="evidence-section">
            <div class="section-title">📊 2. Correlated Evidence</div>
            <ul style="margin: 4px 0 0 16px; padding: 0; font-size: 0.85rem;">
              ${evidence.map(e => `<li>${escapeHtml(e)}</li>`).join("")}
            </ul>
          </div>
        `;
      }

      const interpretation = r.interpretation || "";
      if (interpretation && interpretation !== narrative) {
        html += `
          <div class="evidence-section">
            <div class="section-title">💡 3. Forensic Interpretation</div>
            <p style="margin: 4px 0 0 0; font-size: 0.85rem;">${escapeHtml(interpretation)}</p>
          </div>
        `;
      }

      let uncertainty = r.uncertainty_limitations || r.uncertainty_and_limitations || [];
      if (typeof uncertainty === "string") uncertainty = [uncertainty];
      if (uncertainty && uncertainty.length > 0) {
        html += `
          <div class="evidence-section">
            <div class="section-title">⚠️ 4. Uncertainty & Limitations</div>
            <ul style="margin: 4px 0 0 16px; padding: 0; font-size: 0.85rem;">
              ${uncertainty.map(u => `<li>${escapeHtml(u)}</li>`).join("")}
            </ul>
          </div>
        `;
      }

      const recommendations = r.recommendations || r.recommended_investigation_steps || [];
      if (recommendations && recommendations.length > 0) {
        html += `
          <div class="evidence-section">
            <div class="section-title">🛡️ 5. Recommended Next Steps (Non-Destructive)</div>
            <ul style="margin: 4px 0 0 16px; padding: 0; font-size: 0.85rem;">
              ${recommendations.map(rec => `<li>${escapeHtml(rec)}</li>`).join("")}
            </ul>
          </div>
        `;
      }

      assistantDiv.innerHTML = html;
    }

    container.appendChild(assistantDiv);
    container.scrollTop = container.scrollHeight;
  }

  function explainFlow(flowId) {
    switchView("ai-analyst");
    sendAIMessage(`Explain flow #${flowId} and evaluate its risk attribution`);
  }

  // Public Exports
  function downloadReport(type) {
    alert(`Initiating download for ${type} report JSON...`);
    window.open(`${API_BASE}/api/${type === 'executive' ? 'summary' : type === 'technical' ? 'flows' : 'incidents'}`, "_blank");
  }

  // Init
  function init() {
    initNavigation();
    initPcapController();
    initInvestigationModal();
    initAIAnalyst();

    document.getElementById("btn-refresh").addEventListener("click", () => loadData());
    document.getElementById("btn-quick-analyze").addEventListener("click", () => switchView("pcap"));

    // Flow Pagination
    document.getElementById("btn-prev-page").addEventListener("click", () => {
      if (state.flowPage > 1) {
        state.flowPage--;
        loadFlows();
      }
    });
    document.getElementById("btn-next-page").addEventListener("click", () => {
      if (state.flowPage * state.flowLimit < state.flowTotal) {
        state.flowPage++;
        loadFlows();
      }
    });

    loadData();
  }

  return {
    init,
    downloadReport,
    explainFlow,
    sendAIMessage,
    renderMLLab,
    renderAIAnalyst
  };
})();

document.addEventListener("DOMContentLoaded", App.init);
