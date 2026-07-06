// ══ GEO MAP ══
const lmap = L.map('threatMap', { center: [20, 0], zoom: 1.5, zoomControl: true, attributionControl: false });
window._leafletMap = lmap;
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { maxZoom: 18 }).addTo(lmap);
const ACOL = { 'Brute Force':'#f4522d','Lateral Movement':'#e8294a','Data Exfiltration':'#e8294a','Command & Control':'#7c3aed','Reconnaissance':'#00cfdd' };
(GEO_ALERTS || []).forEach(a => {
  if (!a.lat || !a.lon) return;
  const c = ACOL[a.attack_type] || '#2979ff';
  L.circleMarker([a.lat, a.lon], { radius: Math.max(4, Math.min(12, a.risk_score / 10)), color: c, fillColor: c, fillOpacity: .5, weight: 1.5 })
   .addTo(lmap).bindPopup(`<b>${a.attack_type}</b><br>${a.city}, ${a.country}`);
});

// ══ ATTACK GRAPH ══
let cy;
async function loadGraph() {
  const r = await fetch('/api/v1/graph-data').catch(() => null);
  if (!r) return;
  const d = await r.json();
  if (!cy) {
    cy = cytoscape({ container: document.getElementById('cyGraph'), elements: [...d.nodes, ...d.edges],
      style: [
        { selector: 'node', style: { label: 'data(label)', color: '#e4eaf8', 'font-size': '9px', 'text-valign': 'top', width: 26, height: 26 } },
        { selector: 'node[type="target"]', style: { 'background-color': '#2979ff', shape: 'hexagon', width: 40, height: 40 } },
        { selector: 'node[type="attacker-critical"]', style: { 'background-color': '#e8294a' } },
        { selector: 'node[type="attacker-high"]', style: { 'background-color': '#f4522d' } },
        { selector: 'node[type="attacker"]', style: { 'background-color': '#f0ac2b' } },
        { selector: 'edge', style: { label: 'data(label)', color: '#3d4f75', 'font-size': '8px', width: 1.5, 'line-color': '#243060', 'target-arrow-color': '#243060', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier' } }
      ],
      layout: { name: 'concentric', spacingFactor: 1.3 }
    });
  }
}
function toggleView(v) {
  document.getElementById('threatMap').style.display = v === 'map' ? 'block' : 'none';
  document.getElementById('cyGraph').style.display = v === 'graph' ? 'block' : 'none';
  document.getElementById('btn-map').className = v === 'map' ? 'btn btn-p' : 'btn btn-g';
  document.getElementById('btn-graph').className = v === 'graph' ? 'btn btn-p' : 'btn btn-g';
  if (v === 'graph') loadGraph();
  else lmap.invalidateSize();
}

// ══ THREAT GAUGE ══
function updateGauge(score) {
  const arc = document.getElementById('gauge-arc');
  const val = document.getElementById('gauge-val');
  const lbl = document.getElementById('gauge-label');
  const total = 157;
  arc.setAttribute('stroke-dasharray', `${(score / 100 * total).toFixed(1)} ${total}`);
  const color = score >= 80 ? 'var(--crit)' : score >= 60 ? 'var(--high)' : score >= 30 ? 'var(--med)' : 'var(--low)';
  arc.setAttribute('stroke', color);
  val.textContent = score; val.style.color = color;
  lbl.textContent = score >= 80 ? 'Critical' : score >= 60 ? 'High Risk' : score >= 30 ? 'Moderate' : 'Low Risk';
}
async function refreshGauge() {
  const r = await fetch('/api/ml/stats').catch(() => null);
  if (!r) return;
  const d = await r.json();
  const score = Math.min(100, Math.round((d.anomaly_rate_pct || 0) * 1.2 + (d.fp_rate_pct || 0) * 0.4));
  updateGauge(score);
}

// ══ ANOMALY SPARKLINE ══
async function refreshAnomalySparkline() {
  const r = await fetch('/api/ml/stats').catch(() => null);
  if (!r) return;
  const d = await r.json();
  const hourly = d.hourly_anomaly_counts || Array(24).fill(0);
  const max = Math.max(...hourly, 1);
  const wrap = document.getElementById('anom-sparkline');
  wrap.innerHTML = hourly.map((v, i) => {
    const pct = Math.max(4, Math.round(v / max * 100));
    const col = pct > 70 ? 'var(--crit)' : pct > 40 ? 'var(--high)' : 'var(--accent)';
    return `<div class="sparkline-bar" style="height:${pct}%;background:${col}" title="Hour ${String(i).padStart(2,'0')}:00 — ${v} anomalies"></div>`;
  }).join('');
  document.getElementById('anom-pct-badge').textContent = (d.anomaly_rate_pct || 0).toFixed(1) + '%';
}

// ══ RISK BANNER ══
async function refreshRiskBanner() {
  const r = await fetch('/api/forecast/risk').catch(() => null);
  if (!r) return;
  const d = await r.json();
  const banner = document.getElementById('risk-banner');
  banner.style.display = 'flex';
  if (d.trend === 'up') {
    banner.className = 'risk-banner trending-up';
    document.getElementById('rb-icon').textContent = '↑';
    document.getElementById('rb-text').textContent = `Risk INCREASING — forecast predicts ${d.predicted_peak} alerts on ${d.peak_day}. Consider pre-emptive block policies.`;
  } else if (d.trend === 'down') {
    banner.className = 'risk-banner trending-down';
    document.getElementById('rb-icon').textContent = '↓';
    document.getElementById('rb-text').textContent = `Risk DECREASING — 7-day forecast shows ~${d.predicted_avg} alerts/day. Threat activity is subsiding.`;
  } else {
    banner.className = 'risk-banner stable';
    document.getElementById('rb-icon').textContent = '→';
    document.getElementById('rb-text').textContent = `Risk STABLE — forecast shows consistent activity (~${d.predicted_avg} alerts/day next 7 days).`;
  }
  document.getElementById('rb-ts').textContent = new Date().toLocaleTimeString();
}

// ══ IP REPUTATION LOOKUP (Dashboard) ══
async function lookupReputation() {
  const ip = document.getElementById('rep-ip-inp').value.trim();
  if (!ip) return;
  const container = document.getElementById('rep-result');
  container.innerHTML = '<div class="skel" style="height:50px"></div>';
  const r = await fetch(`/api/v1/network/ip-reputation?ip=${encodeURIComponent(ip)}`).catch(() => null);
  if (!r) { container.innerHTML = '<span style="color:var(--crit)">Lookup failed</span>'; return; }
  const d = await r.json();
  const cls = d.score < 30 ? 'safe' : d.score < 60 ? 'suspicious' : 'malicious';
  container.innerHTML = `<div class="rep-score ${cls}">${d.score}</div><div style="font-size:.72rem;color:var(--t2)">${d.label} · ${d.country}</div><div style="font-size:.67rem;color:var(--t3);margin-top:.3rem">${d.details}</div>`;
}

// ══ PLAYBOOK MINI FEED (Dashboard) ══
async function refreshPlaybookMini() {
  const r = await fetch('/api/v1/playbooks/executions?limit=3').catch(() => null);
  if (!r) return;
  const d = await r.json();
  const items = d.executions || [];
  const feed = document.getElementById('pb-mini-feed');
  if (!items.length) { feed.innerHTML = '<div style="color:var(--t3)">No executions yet.</div>'; return; }
  feed.innerHTML = items.map(e => `<div class="pb-feed-item" style="padding:.35rem 0;border-bottom:1px solid var(--border)">
    <div class="pb-icon" style="width:20px;height:20px;font-size:.65rem">${e.action_type === 'block_ip' ? '🛡' : '▶'}</div>
    <div><div style="font-weight:600;font-size:.73rem">${e.playbook_name}</div><div style="font-size:.68rem;color:var(--t3)">${e.action_type} · ${String(e.executed_at || '').slice(11, 16)}</div></div>
    <span class="badge ${e.success ? 'b-l' : 'b-c'}" style="margin-left:auto;font-size:.58rem">${e.success ? 'OK' : 'ERR'}</span>
  </div>`).join('');
}

