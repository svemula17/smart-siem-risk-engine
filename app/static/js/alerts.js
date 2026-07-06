// ══ ALERTS ══
let allAlerts = [];
async function fetchAlerts() {
  const r = await fetch('/scored-alerts').catch(() => null);
  if (!r) return;
  allAlerts = await r.json();
  renderAlerts(allAlerts);
}
function renderAlerts(data) {
  document.getElementById('alerts-body').innerHTML = data.slice(0, 300).map(a => {
    const cls = a.risk_score >= 80 ? 'b-c' : a.risk_score >= 60 ? 'b-h' : a.risk_score >= 30 ? 'b-m' : 'b-l';
    const ip = a.source_ip || '—';
    const tpScore = Math.min(99, Math.round(a.risk_score * 0.9));
    const ipCell = ip !== '—'
      ? `<a href="javascript:void(0)" onclick="openPivot('ip','${ip}')" style="color:var(--accent);text-decoration:none">${ip}</a> <button onclick="copyIP('${ip}')" style="background:none;border:none;cursor:pointer;color:var(--t3);font-size:.65rem" title="Copy">📋</button>`
      : '—';
    const blockBtn = ip !== '—' ? `<button class="qa-btn" title="Block IP" onclick="qaBlock('${ip}','${a.raw_alert_id}')">🚫</button>` : '';
    const iocBtn = ip !== '—' ? `<button class="qa-btn" title="Add to IOC" onclick="qaAddIOC('${ip}')">🎯</button>` : '';
    return `<tr>
      <td class="mono" style="font-size:.72rem"><a href="javascript:void(0)" onclick="openPivot('alert','${a.raw_alert_id}')" style="color:var(--accent);text-decoration:none">${(a.raw_alert_id || '').slice(0, 10)}…</a></td>
      <td><span class="badge ${cls}">${a.risk_score}</span></td>
      <td style="font-size:.75rem">${a.attack_type || '—'}</td>
      <td class="mono" style="font-size:.72rem">${ipCell}</td>
      <td style="font-size:.72rem">${(a.recommended_action || '').replace(/_/g, ' ')}</td>
      <td style="font-size:.72rem;color:var(--t3)">${String(a.processed_at || '').slice(0, 16)}</td>
      <td style="white-space:nowrap">
        ${blockBtn}
        ${iocBtn}
        <button class="qa-btn" title="Create Incident" onclick="qaIncident('${a.raw_alert_id}','${(a.attack_type||'').replace(/'/g,'')}')">🚨</button>
        <button class="qa-btn" title="Mark False Positive" onclick="markFP('${a.raw_alert_id}')">FP</button>
      </td>
    </tr>`;
  }).join('') || '<tr><td colspan="7" style="text-align:center;color:var(--t3);padding:2rem">No alerts.</td></tr>';
}
function filterAlerts(q) {
  q = q.toLowerCase();
  renderAlerts(allAlerts.filter(a => (a.raw_alert_id || '').toLowerCase().includes(q) || (a.attack_type || '').toLowerCase().includes(q) || (a.source_ip || '').includes(q)));
}
function copyIP(ip) {
  navigator.clipboard.writeText(ip).then(() => toast(`Copied: ${ip}`, 'info', 1500));
}
async function markFP(id) {
  const reason = window.prompt('Reason for false positive (optional):');
  if (reason === null) return;
  await fetch('/api/ai/false-positive', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ raw_alert_id: id, analyst: 'admin', reason: reason || '' }) });
  toast('Alert marked as False Positive', 'success');
  loadFPCount();
}
async function loadFPCount() {
  const r = await fetch('/api/ai/fp-stats').catch(() => null);
  if (!r) return;
  const d = await r.json();
  document.getElementById('s-fp').textContent = d.total_false_positives;
  const fpEl = document.getElementById('fp-rate');
  if (fpEl) fpEl.textContent = d.fp_rate_pct + '%';
}

// ══ ATTACK ANALYSIS ══
let attkFullChart;
async function fetchAttacks() {
  const r = await fetch('/api/attack-type-stats').catch(() => null);
  if (!r) return;
  const d = await r.json();
  const types = d.attack_types || [];
  const total = types.reduce((s, t) => s + t.count, 0);
  const COLORS = { 'Brute Force':'#f4522d','Lateral Movement':'#e8294a','Data Exfiltration':'#e8294a','Command & Control':'#7c3aed','Port Scanning':'#f0ac2b','Reconnaissance':'#00cfdd' };
  document.getElementById('atk-list').innerHTML = types.map(t => {
    const pct = total > 0 ? (t.count / total * 100).toFixed(1) : 0;
    const w = total > 0 ? (t.count / Math.max(...types.map(x => x.count)) * 100).toFixed(0) : 0;
    const c = COLORS[t.attack_type] || '#2979ff';
    return `<div class="ar"><span style="font-size:.8rem;font-weight:500;min-width:155px">${t.attack_type}</span><div class="ab-out"><div class="ab-in" style="width:${w}%;background:${c}"></div></div><span class="mono" style="font-size:.78rem;min-width:55px;text-align:right">${t.count.toLocaleString()}</span><span style="font-size:.68rem;color:var(--t3);min-width:42px;text-align:right">${pct}%</span></div>`;
  }).join('');
  if (attkFullChart) attkFullChart.destroy();
  attkFullChart = buildBarChart('attkfull', types.map(t => t.attack_type).slice(0, 10), types.map(t => t.count).slice(0, 10));
}
async function fetchClusters() {
  const r = await fetch('/api/alert-clusters').catch(() => null);
  const d = r ? await r.json() : {};
  const list = document.getElementById('clusterlist');
  const clusters = (d.clusters || []).sort((a, b) => b.alert_count - a.alert_count).slice(0, 8);
  if (!clusters.length) { list.innerHTML = '<div style="color:var(--t3);text-align:center;padding:2rem;font-size:.78rem">Not enough data for clustering.</div>'; return; }
  list.innerHTML = clusters.map(c => {
    const cls = c.avg_risk_score >= 80 ? 'b-c' : c.avg_risk_score >= 60 ? 'b-h' : 'b-m';
    return `<div class="ag-card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.35rem"><span style="font-weight:600;font-size:.8rem">${c.label}</span><span class="badge ${cls}">Avg ${c.avg_risk_score}</span></div><div style="font-size:.72rem;color:var(--t2)">🎯 ${c.top_attack_type} · ${c.alert_count} alerts · ${c.unique_sources} sources</div></div>`;
  }).join('');
}

// ══ THREAT HUNTING ══
function setHunt(q) { document.getElementById('hq').value = q; }
let huntChart;
async function hunt() {
  const q = document.getElementById('hq').value.trim();
  if (!q) return;
  const r = await fetch('/api/hunt', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: q }) }).catch(() => null);
  if (!r) { toast('Hunt query failed', 'error'); return; }
  const d = await r.json();
  document.getElementById('hresults').innerHTML = d.results.map(r => {
    const cls = r.risk_score >= 80 ? 'b-c' : r.risk_score >= 60 ? 'b-h' : 'b-m';
    return `<tr><td class="mono" style="font-size:.7rem">${(r.alert_id || '').slice(0, 8)}…</td><td style="font-size:.7rem">${String(r.timestamp || '').slice(11, 19)}</td><td><span class="badge ${cls}">${r.risk_score}</span></td><td style="font-size:.7rem">${r.attack_type || '—'}</td><td style="font-size:.7rem">${(r.action || '').replace(/_/g, ' ')}</td></tr>`;
  }).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--t3);padding:1.5rem">No results.</td></tr>';
  const tctx = document.getElementById('huntchart');
  if (huntChart) huntChart.destroy();
  huntChart = new Chart(tctx, { type: 'bar', data: { labels: d.timeline.map(t => t.time.slice(-5)), datasets: [{ label: 'Events', data: d.timeline.map(t => t.count), backgroundColor: 'rgba(41,121,255,0.55)', borderColor: '#2979ff', borderWidth: 1, borderRadius: 3 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } } });
}

// ══ KILL CHAIN ══
const TACTICS = [
  { id:'recon', name:'Reconnaissance', color:'#00cfdd', types:['Reconnaissance','Port Scanning'], mitre:'T1595' },
  { id:'init',  name:'Initial Access',  color:'#f4522d', types:['Phishing','Exploitation','Initial Access'], mitre:'T1190' },
  { id:'exec',  name:'Execution',       color:'#f4522d', types:['Command Execution'], mitre:'T1059' },
  { id:'persist',name:'Persistence',    color:'#f0ac2b', types:['Persistence','Account Manipulation'], mitre:'T1053' },
  { id:'priv',  name:'Priv Escalation', color:'#e8294a', types:['Privilege Escalation'], mitre:'T1068' },
  { id:'defen', name:'Defense Evasion', color:'#7c3aed', types:['Defense Evasion','Obfuscation'], mitre:'T1070' },
  { id:'cred',  name:'Cred Access',     color:'#e8294a', types:['Brute Force','Credential Theft'], mitre:'T1110' },
  { id:'lateral',name:'Lateral Movement',color:'#e8294a',types:['Lateral Movement'], mitre:'T1021' },
  { id:'c2',    name:'C2',              color:'#7c3aed', types:['Command & Control','C2 File Transfer'], mitre:'T1071' },
  { id:'exfil', name:'Exfiltration',    color:'#e8294a', types:['Data Exfiltration'], mitre:'T1048' },
  { id:'impact',name:'Impact',          color:'#e8294a', types:['Ransomware','DDoS Attack'], mitre:'T1486' },
];
let tacticChart;
async function loadKillChain() {
  const r = await fetch('/api/attack-type-stats').catch(() => null);
  const d = r ? await r.json() : {};
  const typeMap = {};
  (d.attack_types || []).forEach(t => typeMap[t.attack_type] = t.count);
  const chain = document.getElementById('killchain-steps');
  chain.innerHTML = '';
  const labels = [], values = [], colors = [];
  TACTICS.forEach((tac, i) => {
    const count = tac.types.reduce((s, t) => s + (typeMap[t] || 0), 0);
    labels.push(tac.name); values.push(count); colors.push(tac.color + '99');
    if (i > 0) chain.innerHTML += '<span class="kc-arrow">→</span>';
    const el = document.createElement('div');
    el.className = 'kc-step';
    el.style.cssText = `border-color:${tac.color};color:${tac.color};background:${tac.color}18`;
    el.innerHTML = `${tac.name} <span class="badge" style="background:${tac.color}33;color:${tac.color};margin-left:4px">${count.toLocaleString()}</span>`;
    el.onclick = () => {
      document.getElementById('ai-explain').innerHTML = '<div class="skel"></div><div class="skel" style="width:75%"></div>';
      fetch(`/api/ai/explain/${encodeURIComponent(tac.types[0])}`).then(r => r.json()).then(d => { document.getElementById('ai-explain').textContent = d.explanation; }).catch(() => {});
    };
    chain.appendChild(el);
  });
  const ctx = document.getElementById('tacticchart');
  if (tacticChart) tacticChart.destroy();
  tacticChart = new Chart(ctx, { type: 'radar', data: { labels, datasets: [{ label: 'Alert Count', data: values, backgroundColor: 'rgba(41,121,255,0.15)', borderColor: '#2979ff', borderWidth: 2, pointBackgroundColor: '#2979ff', pointRadius: 4 }] }, options: { responsive: true, maintainAspectRatio: false, scales: { r: { grid: { color: '#1a2545' }, ticks: { display: false }, pointLabels: { font: { size: 9 }, color: '#7d8fba' } } }, plugins: { legend: { display: false } } } });
}

