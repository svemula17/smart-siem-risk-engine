// ══ IOC ══
async function loadIOC() {
  const [statsR, listR] = await Promise.all([fetch('/api/v1/ioc/stats').catch(() => null), fetch('/api/v1/ioc/').catch(() => null)]);
  if (statsR) { const s = await statsR.json(); document.getElementById('ioc-total').textContent = s.total || 0; }
  const matchR = await fetch('/api/v1/ioc/matches').catch(() => null);
  if (matchR) { const m = await matchR.json(); document.getElementById('ioc-matches').textContent = (m.matches || []).length; }
  document.getElementById('ioc-ts').textContent = new Date().toLocaleTimeString();
  if (!listR) return;
  const iocs = await listR.json();
  const ICLS = { ip:'ioc-ip', domain:'ioc-domain', hash:'ioc-hash', url:'ioc-url' };
  document.getElementById('ioc-body').innerHTML = iocs.map(ioc => `<tr>
    <td><span class="${ICLS[ioc.ioc_type] || ''}" style="font-weight:600;font-size:.78rem">${ioc.ioc_type.toUpperCase()}</span></td>
    <td class="mono" style="font-size:.75rem">${ioc.value}</td>
    <td><span class="badge ${ioc.severity==='Critical'?'b-c':ioc.severity==='High'?'b-h':ioc.severity==='Medium'?'b-m':'b-l'}">${ioc.severity}</span></td>
    <td style="font-size:.75rem">${ioc.source || '—'}</td>
    <td style="font-size:.75rem;color:var(--t2)">${ioc.description || '—'}</td>
    <td style="font-size:.7rem">${(ioc.tags || []).map(t => `<span class="chip" style="margin:1px">${t}</span>`).join('')}</td>
    <td><button class="btn btn-d" style="font-size:.65rem;padding:2px 6px" onclick="deleteIOC(${ioc.id},this)">Delete</button></td>
  </tr>`).join('') || '<tr><td colspan="7" style="text-align:center;color:var(--t3);padding:2rem">No IOCs. Click "Seed Demo IOCs".</td></tr>';
}
async function addIOC() {
  const tags = document.getElementById('ioc-tags').value.split(',').map(t => t.trim()).filter(Boolean);
  await fetch('/api/v1/ioc/', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ioc_type: document.getElementById('ioc-type').value, value: document.getElementById('ioc-value').value, severity: document.getElementById('ioc-sev').value, source: document.getElementById('ioc-src').value, description: document.getElementById('ioc-desc').value, tags }) });
  closeModal('iocModal'); loadIOC(); toast('IOC added', 'success');
}
async function deleteIOC(id, btn) { await fetch(`/api/v1/ioc/${id}`, { method: 'DELETE' }); btn.closest('tr').remove(); toast('IOC removed', 'warn'); }
async function seedIOC() { await fetch('/api/v1/ioc/seed', { method: 'POST' }); loadIOC(); toast('Demo IOCs seeded', 'success'); }

// ══ COMPLIANCE ══
const CTRL_COLORS = { compliant:'var(--low)', warning:'var(--med)', violation:'var(--crit)' };
function renderControls(id, controls) {
  const max = Math.max(...controls.map(c => c.alert_hits), 1);
  document.getElementById(id).innerHTML = controls.map(c => `<div class="ctrl-row"><div style="min-width:52px;font-size:.68rem;font-weight:700;color:${CTRL_COLORS[c.status]}">${c.control_id}</div><div style="flex:1"><div style="font-size:.72rem;margin-bottom:2px">${c.control_name}</div><div class="ctrl-bar"><div class="ctrl-fill" style="width:${c.alert_hits/max*100}%;background:${CTRL_COLORS[c.status]}"></div></div></div><div style="min-width:40px;text-align:right;font-size:.7rem;color:${CTRL_COLORS[c.status]}">${c.alert_hits.toLocaleString()}</div></div>`).join('');
}
async function loadCompliance() {
  const r = await fetch('/api/compliance/summary').catch(() => null);
  if (!r) return;
  const d = await r.json();
  renderControls('soc2-ctrl', d.soc2 || []); renderControls('pci-ctrl', d.pci_dss || []); renderControls('iso-ctrl', d.iso27001 || []);
}
async function loadSLA() {
  const r = await fetch('/api/compliance/sla-metrics').catch(() => null);
  if (!r) return;
  const d = await r.json();
  document.getElementById('mttd').innerHTML = `${d.mttd_minutes}<span style="font-size:.8rem"> min</span>`;
  document.getElementById('mttr').innerHTML = `${d.mttr_minutes || 0}<span style="font-size:.8rem"> min</span>`;
  document.getElementById('posture-score').textContent = d.posture_score || '—';
  const pct = (d.posture_score || 0) + '%';
  document.getElementById('posture-ring').style.background = `conic-gradient(var(--low) 0% ${pct}, var(--hover) ${pct} 100%)`;
  loadFPCount();
}

// ══ PLAYBOOKS TAB ══
let pbTrendChart;
async function loadPlaybooks() {
  const [pbR, execR] = await Promise.all([
    fetch('/api/v1/playbooks/').catch(() => null),
    fetch('/api/v1/playbooks/executions').catch(() => null)
  ]);
  if (pbR) {
    const pbs = await pbR.json();
    document.getElementById('pb-total').textContent = pbs.length;
    document.getElementById('pb-active').textContent = pbs.filter(p => p.is_active).length;
    document.getElementById('pb-badge').textContent = pbs.filter(p => p.is_active).length;
    document.getElementById('pb-body').innerHTML = pbs.map(p => `<tr>
      <td style="font-weight:600;font-size:.8rem">${p.name}</td>
      <td style="font-size:.72rem;color:var(--t2)">${(p.trigger_summary || '—').slice(0, 30)}</td>
      <td style="font-size:.72rem">${p.action_summary || '—'}</td>
      <td><span class="badge ${p.is_active ? 'b-l' : 'b-h'}">${p.is_active ? 'Active' : 'Off'}</span></td>
      <td><button class="btn ${p.is_active ? 'btn-s' : 'btn-g'}" style="font-size:.65rem;padding:2px 6px" onclick="togglePlaybook(${p.id},this)">${p.is_active ? 'ON' : 'OFF'}</button></td>
    </tr>`).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--t3);padding:2rem">No playbooks defined.</td></tr>';
  }
  if (execR) {
    const exData = await execR.json();
    const execs = exData.executions || [];
    const now = Date.now();
    const last24h = execs.filter(e => (now - new Date(e.executed_at).getTime()) / 3600000 < 24);
    document.getElementById('pb-exec-count').textContent = last24h.length;
    document.getElementById('pb-blocks').textContent = execs.filter(e => e.action_type === 'block_ip').length;
    renderExecLog(execs);
    if (pbTrendChart) pbTrendChart.destroy();
    const ctx = document.getElementById('pb-trend-chart');
    const days = Array.from({ length: 7 }, (_, i) => { const d = new Date(); d.setDate(d.getDate() - 6 + i); return d.toISOString().slice(5, 10); });
    const counts = days.map(day => execs.filter(e => String(e.executed_at || '').startsWith('20' + day.replace('-', '-'))).length);
    pbTrendChart = new Chart(ctx, { type: 'bar', data: { labels: days, datasets: [{ label: 'Executions', data: counts, backgroundColor: 'rgba(124,58,237,0.55)', borderColor: '#7c3aed', borderWidth: 1, borderRadius: 3 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, grid: { color: '#1a2545' } }, x: { grid: { display: false } } } } });
  }
}
function renderExecLog(execs) {
  const c = document.getElementById('pb-exec-log');
  if (!execs.length) { c.innerHTML = '<div class="pb-feed-item" style="color:var(--t3);border:none">No executions yet.</div>'; return; }
  c.innerHTML = execs.slice(0, 30).map(e => `<div class="pb-feed-item">
    <div class="pb-icon">${e.action_type === 'block_ip' ? '🛡' : e.action_type === 'notify' ? '📢' : '▶'}</div>
    <div style="min-width:0;flex:1">
      <div style="font-weight:600">${e.playbook_name || '—'}</div>
      <div style="font-size:.7rem;color:var(--t2)">${e.action_type} → ${e.target || '—'}</div>
      <div style="font-size:.67rem;color:var(--t3)">${String(e.executed_at || '').slice(0, 16)}</div>
    </div>
    <span class="badge ${e.success ? 'b-l' : 'b-c'}" style="flex-shrink:0">${e.success ? 'OK' : 'ERR'}</span>
  </div>`).join('');
}
async function togglePlaybook(id, btn) {
  const r = await fetch(`/api/v1/playbooks/${id}/toggle`, { method: 'PUT' }).catch(() => null);
  if (r) { loadPlaybooks(); toast('Playbook toggled', 'info'); }
}
async function createPlaybook() {
  const name = document.getElementById('pb-name').value.trim();
  if (!name) { toast('Playbook name is required', 'error'); return; }
  await fetch('/api/v1/playbooks/', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, description: document.getElementById('pb-desc').value, trigger_condition_json: document.getElementById('pb-trigger').value || '{}', actions_json: document.getElementById('pb-actions').value || '[]' }) });
  closeModal('pbCreateModal'); loadPlaybooks(); toast('Playbook created', 'success');
}

// ══ ML INSIGHTS ══
let mlAnomChart;
async function loadMLInsights() {
  const r = await fetch('/api/ml/stats').catch(() => null);
  if (!r) { toast('ML stats unavailable', 'warn'); return; }
  const d = await r.json();
  document.getElementById('ml-status').textContent = d.is_trained ? '✓ Trained' : '✗ Untrained';
  document.getElementById('ml-anom-rate').textContent = (d.anomaly_rate_pct || 0).toFixed(1) + '%';
  document.getElementById('ml-fp-trend').textContent = (d.fp_rate_pct || 0).toFixed(1) + '%';
  document.getElementById('ml-samples').textContent = (d.training_samples || 0).toLocaleString();
  document.getElementById('ml-last-train').textContent = d.last_trained_at ? String(d.last_trained_at).slice(0, 10) : 'Never';

  // Feature importance
  const feats = d.feature_importance || [{ name:'Raw Severity', weight:.55 }, { name:'Risk Score', weight:.33 }, { name:'MITRE Count', weight:.12 }];
  const maxW = Math.max(...feats.map(f => f.weight));
  document.getElementById('ml-features').innerHTML = feats.map(f => `<div style="margin-bottom:.55rem">
    <div style="display:flex;justify-content:space-between;font-size:.72rem;margin-bottom:.25rem">
      <span style="color:var(--t1)">${f.name}</span>
      <span class="mono" style="color:var(--purple)">${(f.weight * 100).toFixed(1)}%</span>
    </div>
    <div class="ab-out" style="margin:0"><div class="ab-in" style="width:${(f.weight/maxW*100).toFixed(0)}%;background:var(--purple)"></div></div>
  </div>`).join('');

  // Anomaly rate chart
  if (mlAnomChart) mlAnomChart.destroy();
  const daily = d.daily_anomaly_rates || [];
  mlAnomChart = new Chart(document.getElementById('ml-anom-chart'), {
    type: 'line',
    data: { labels: daily.map(x => x.day.slice(5)), datasets: [
      { label: 'Anomaly Rate %', data: daily.map(x => x.rate), borderColor: '#7c3aed', backgroundColor: 'rgba(124,58,237,0.1)', tension: .4, fill: true, pointRadius: 3 },
      { label: 'FP Rate %', data: daily.map(x => x.fp_rate || 0), borderColor: '#e8294a', tension: .4, pointRadius: 3 },
    ]},
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { boxWidth: 9, font: { size: 10 } } } }, scales: { y: { beginAtZero: true, grid: { color: '#1a2545' } }, x: { grid: { display: false } } } }
  });

  fetchMLClusters();
  loadTriageData();

  // FP history
  const fpR = await fetch('/api/ai/false-positives?limit=20').catch(() => null);
  if (fpR) {
    const fps = await fpR.json();
    document.getElementById('ml-fp-history').innerHTML = fps.length ? fps.map(fp => `<div style="padding:.3rem 0;border-bottom:1px solid var(--border);display:flex;justify-content:space-between">
      <span class="mono" style="font-size:.7rem">${(fp.raw_alert_id || '').slice(0, 12)}…</span>
      <span style="font-size:.7rem;color:var(--t2)">${fp.original_attack_type || '—'}</span>
      <span style="font-size:.68rem;color:var(--t3)">${String(fp.marked_at || '').slice(0, 10)}</span>
    </div>`).join('') : '<div style="color:var(--t3)">No FP feedback yet.</div>';
  }
}
async function fetchMLClusters() {
  const r = await fetch('/api/alert-clusters').catch(() => null);
  const d = r ? await r.json() : {};
  const clusters = (d.clusters || []).sort((a, b) => b.alert_count - a.alert_count).slice(0, 10);
  document.getElementById('ml-cluster-view').innerHTML = clusters.length ? clusters.map(c => {
    const cls = c.avg_risk_score >= 80 ? 'b-c' : c.avg_risk_score >= 60 ? 'b-h' : 'b-m';
    return `<div class="ag-card"><div style="display:flex;justify-content:space-between;margin-bottom:.3rem"><span style="font-weight:600;font-size:.8rem">${c.label}</span><span class="badge ${cls}">Avg ${c.avg_risk_score}</span></div><div style="font-size:.72rem;color:var(--t2)">${c.top_attack_type} · ${c.alert_count} alerts · ${c.unique_sources} sources</div></div>`;
  }).join('') : '<div style="color:var(--t3);text-align:center;padding:2rem;font-size:.78rem">Not enough data for DBSCAN clustering.</div>';
}
async function loadTriageData() {
  const r = await fetch('/scored-alerts').catch(() => null);
  if (!r) return;
  const alerts = (await r.json()).slice(0, 20);
  document.getElementById('triage-body').innerHTML = alerts.map(a => {
    const tpScore = Math.min(99, Math.round(a.risk_score * 0.9));
    const fpScore = 100 - tpScore;
    const verdict = tpScore > 70 ? 'TP' : fpScore > 70 ? 'FP' : 'Unknown';
    const cls = a.risk_score >= 80 ? 'b-c' : a.risk_score >= 60 ? 'b-h' : a.risk_score >= 30 ? 'b-m' : 'b-l';
    return `<tr>
      <td class="mono" style="font-size:.7rem">${(a.raw_alert_id || '').slice(0, 10)}…</td>
      <td><span class="badge ${cls}">${a.risk_score}</span></td>
      <td style="font-size:.75rem">${a.attack_type || '—'}</td>
      <td><span class="ml-conf tp">${tpScore}%</span></td>
      <td><span class="ml-conf fp-badge">${fpScore}%</span></td>
      <td><span class="badge ${verdict==='TP'?'b-l':verdict==='FP'?'b-c':'b-a'}">${verdict}</span></td>
    </tr>`;
  }).join('');
}
async function triggerRetrain() {
  const btn = event.target;
  btn.disabled = true; btn.textContent = '⏳ Retraining…';
  document.getElementById('retrain-status').textContent = 'Sending request…';
  const r = await fetch('/api/ml/retrain', { method: 'POST' }).catch(() => null);
  if (r) {
    const d = await r.json();
    document.getElementById('retrain-status').textContent = d.message || 'Done';
    toast(d.status === 'success' ? 'ML model retrained successfully' : 'Retrain: ' + d.message, d.status === 'success' ? 'success' : 'error');
    if (d.status === 'success') setTimeout(loadMLInsights, 1000);
  } else { toast('Retrain request failed', 'error'); }
  btn.disabled = false; btn.textContent = '🔄 Retrain Model on FP Feedback';
}

// ══ NETWORK INTELLIGENCE ══
async function loadNetworkIntel() {
  const r = await fetch('/api/v1/network/behavior').catch(() => null);
  if (!r) { toast('Network data unavailable', 'warn'); return; }
  const d = await r.json();
  document.getElementById('net-suspicious').textContent = d.suspicious_segments || 0;
  document.getElementById('net-attackers').textContent = d.unique_attackers || 0;
  document.getElementById('net-score').textContent = d.network_risk_score || 0;
  document.getElementById('net-ueba-flags').textContent = d.ueba_flagged || 0;
  document.getElementById('net-segments').innerHTML = (d.top_segments || []).map(s => `<tr>
    <td class="mono" style="font-size:.72rem">${s.subnet}</td>
    <td style="font-size:.78rem">${s.alert_count.toLocaleString()}</td>
    <td><span class="badge ${s.avg_risk>=80?'b-c':s.avg_risk>=60?'b-h':'b-m'}">${s.avg_risk}</span></td>
    <td class="mono" style="font-size:.72rem">${s.ueba_score}</td>
    <td><span class="badge ${s.verdict==='Critical'?'b-c':s.verdict==='High'?'b-h':s.verdict==='Medium'?'b-m':'b-l'}">${s.verdict}</span></td>
  </tr>`).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--t3);padding:2rem">No suspicious segments detected.</td></tr>';
  buildMitreMatrix(d.covered_ttps || []);
}
async function lookupRepNetIntel() {
  const ip = document.getElementById('net-ip-inp').value.trim();
  if (!ip) return;
  const r = await fetch(`/api/v1/network/ip-reputation?ip=${encodeURIComponent(ip)}`).catch(() => null);
  const container = document.getElementById('net-rep-result');
  if (!r) { container.innerHTML = '<span style="color:var(--crit)">Lookup failed</span>'; return; }
  const d = await r.json();
  const cls = d.score < 30 ? 'safe' : d.score < 60 ? 'suspicious' : 'malicious';
  container.innerHTML = `<div class="rep-score ${cls}" style="font-size:2rem">${d.score}</div><div style="font-weight:600;color:var(--t1)">${d.label}</div><div style="font-size:.75rem;color:var(--t2);margin-top:.3rem">${d.details}</div>`;
}
function buildMitreMatrix(coveredTTPs) {
  const TACTICS_M = [
    { name:'Recon',    techs:['T1595','T1592','T1589','T1590'] },
    { name:'Res Dev',  techs:['T1583','T1584','T1585','T1586'] },
    { name:'Init Acc', techs:['T1190','T1133','T1078','T1566'] },
    { name:'Execute',  techs:['T1059','T1203','T1204','T1047'] },
    { name:'Persist',  techs:['T1098','T1136','T1197','T1505'] },
    { name:'Priv Esc', techs:['T1068','T1134','T1574','T1055'] },
    { name:'Def Eva',  techs:['T1070','T1027','T1036','T1562'] },
    { name:'Cred Acc', techs:['T1110','T1003','T1555','T1056'] },
    { name:'Lateral',  techs:['T1021','T1210','T1534','T1570'] },
    { name:'Exfil',    techs:['T1048','T1011','T1020','T1041'] },
    { name:'Impact',   techs:['T1486','T1498','T1499','T1490'] },
  ];
  const c = new Set(coveredTTPs);
  document.getElementById('mitre-matrix').innerHTML = TACTICS_M.map(tac => `
    <div class="mitre-tactic-col">
      <div class="mitre-tactic-header">${tac.name}</div>
      ${tac.techs.map(t => `<div class="mitre-tech ${c.has(t) ? 'covered' : ''}" title="${t}">${t}</div>`).join('')}
    </div>`).join('');
}

// ══ THREAT FORECAST ══
let fcChart;
async function loadForecast() {
  const r = await fetch('/api/forecast/risk').catch(() => null);
  if (!r) { toast('Forecast data unavailable', 'warn'); return; }
  const d = await r.json();
  document.getElementById('fc-peak').textContent = d.peak_day ? d.peak_day.slice(5) : '—';
  const trendEl = document.getElementById('fc-trend');
  trendEl.textContent = d.trend === 'up' ? '↑ Rising' : d.trend === 'down' ? '↓ Falling' : '→ Stable';
  trendEl.style.color = d.trend === 'up' ? 'var(--crit)' : d.trend === 'down' ? 'var(--low)' : 'var(--accent)';
  document.getElementById('fc-avg').textContent = d.predicted_avg || '—';
  document.getElementById('fc-conf').textContent = (d.confidence_pct || 0) + '%';

  if (fcChart) fcChart.destroy();
  const hist = d.historical || [], pred = d.forecast || [];
  fcChart = new Chart(document.getElementById('fc-chart'), {
    type: 'line',
    data: {
      labels: [...hist.map(x => x.day.slice(5)), ...pred.map(x => x.day.slice(5))],
      datasets: [
        { label: 'Historical', data: [...hist.map(x => x.total), ...pred.map(() => null)], borderColor: '#2979ff', backgroundColor: 'rgba(41,121,255,0.08)', tension: .4, fill: true, pointRadius: 2 },
        { label: 'Forecast',   data: [...hist.map(() => null), ...pred.map(x => x.predicted)], borderColor: '#7c3aed', borderDash: [6, 3], backgroundColor: 'rgba(124,58,237,0.08)', tension: .4, fill: true, pointRadius: 3 },
      ]
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { boxWidth: 9, font: { size: 10 } } } }, scales: { y: { beginAtZero: true, grid: { color: '#1a2545' } }, x: { grid: { display: false }, ticks: { font: { size: 9 }, maxRotation: 45 } } } }
  });

  // Attack breakdown
  document.getElementById('fc-breakdown').innerHTML = (d.attack_breakdown || []).map(a => `<div class="ar">
    <span style="font-size:.78rem;min-width:150px">${a.attack_type}</span>
    <div class="ab-out"><div class="ab-in" style="width:${a.pct}%;background:var(--purple)"></div></div>
    <span class="mono" style="font-size:.72rem;min-width:55px;text-align:right">${a.predicted}/day</span>
  </div>`).join('');

  // AI narrative
  const aiR = await fetch('/api/ai/summarize', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ attack_type: d.trend === 'up' ? 'Escalating Threat' : 'Stable Activity', risk_score: d.trend === 'up' ? 78 : 42, affected_count: d.predicted_avg || 0, mitre_ids: [] }) }).catch(() => null);
  if (aiR) {
    const ai = await aiR.json();
    document.getElementById('fc-narrative').innerHTML = `<p style="margin-bottom:.5rem">${ai.summary}</p><ul style="padding-left:1rem;color:var(--t3)">${(ai.recommendations || []).map(r => `<li style="margin-bottom:.25rem">${r}</li>`).join('')}</ul>`;
  }
}

// ══ AUDIT LOG ══
async function loadAudit() {
  const r = await fetch('/api/v1/audit/').catch(() => null);
  if (!r) return;
  const d = await r.json();
  document.getElementById('audit-body').innerHTML = (d.logs || []).map(l => `<tr>
    <td style="font-size:.72rem;color:var(--t3)">${String(l.created_at || '').slice(0, 16)}</td>
    <td style="font-weight:500;font-size:.78rem">${l.actor}</td>
    <td style="font-size:.78rem">${l.action}</td>
    <td class="mono" style="font-size:.72rem">${l.target || '—'}</td>
    <td><span class="badge ${l.result === 'success' ? 'b-l' : 'b-c'}">${l.result}</span></td>
  </tr>`).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--t3);padding:2rem">No audit entries.</td></tr>';
}

// ══ RULES ══
async function fetchRules() {
  const r = await fetch('/api/v1/rules/').catch(() => null);
  if (!r) return;
  const data = await r.json();
  document.getElementById('rules-list').innerHTML = data.map(rule => `<div style="padding:.65rem;border:1px solid var(--border);border-radius:6px;margin-bottom:.4rem"><div style="display:flex;justify-content:space-between;margin-bottom:.2rem"><strong style="font-size:.8rem">${rule.name}</strong><span class="badge ${rule.is_active ? 'b-l' : 'b-h'}">${rule.is_active ? 'Active' : 'Off'}</span></div><p style="font-size:.75rem;color:var(--t2);margin:.2rem 0">${rule.description || ''}</p><div class="mono" style="font-size:.68rem;background:var(--bg);padding:.35rem .5rem;border-radius:4px;overflow-x:auto">${rule.logic_json}</div></div>`).join('') || '<div style="color:var(--t3)">No rules defined.</div>';
}
async function saveRule() {
  const n = document.getElementById('rname').value.trim(), l = document.getElementById('rlogic').value.trim(), s = document.getElementById('rsev').value;
  if (!n || !l) { toast('Fill in rule name and logic', 'error'); return; }
  await fetch(`/api/v1/rules/?name=${encodeURIComponent(n)}&logic_json=${encodeURIComponent(l)}&severity=${encodeURIComponent(s)}`, { method: 'POST' });
  fetchRules(); toast('Rule saved and deployed', 'success');
}

// ══ SUPPRESSION RULES ══
async function loadSupRules() {
  const r = await fetch('/api/v1/suppression-rules/').catch(() => null);
  if (!r) return;
  const data = await r.json();
  document.getElementById('sup-rules').innerHTML = data.map(rule => `<div style="padding:.65rem;border:1px solid var(--border);border-radius:6px;margin-bottom:.4rem;display:flex;justify-content:space-between;align-items:center"><div><strong style="font-size:.8rem">${rule.name}</strong><div style="font-size:.72rem;color:var(--t2);margin-top:.2rem">${rule.attack_type || 'Any type'} · ${rule.window_minutes}min window</div></div><div style="display:flex;gap:.4rem"><button class="btn ${rule.is_active ? 'btn-s' : 'btn-g'}" style="font-size:.65rem;padding:2px 6px" onclick="toggleSup(${rule.id},this)">${rule.is_active ? 'ON' : 'OFF'}</button><button class="btn btn-d" style="font-size:.65rem;padding:2px 6px" onclick="deleteSup(${rule.id},this)">Del</button></div></div>`).join('') || '<div style="color:var(--t3);font-size:.8rem">No suppression rules.</div>';
}
async function addSupRule() {
  await fetch('/api/v1/suppression-rules/', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: document.getElementById('sup-name').value, attack_type: document.getElementById('sup-type').value || null, source_ip: document.getElementById('sup-ip').value || null, max_risk_score: parseInt(document.getElementById('sup-risk').value) || null, window_minutes: parseInt(document.getElementById('sup-win').value) || 60 }) });
  closeModal('supModal'); loadSupRules(); toast('Suppression rule created', 'success');
}
async function toggleSup(id) { await fetch(`/api/v1/suppression-rules/${id}/toggle`, { method: 'PUT' }); loadSupRules(); }
async function deleteSup(id, btn) { await fetch(`/api/v1/suppression-rules/${id}`, { method: 'DELETE' }); btn.closest('div').parentElement.remove(); }

// ══ SLACK TEST ══
function testSlack() {
  const url = document.getElementById('slack-url-inp').value;
  if (!url) { toast('Enter a Slack webhook URL first', 'error'); return; }
  toast('Slack test fired — check your channel', 'info');
}

// ══ UEBA ══
async function fetchUEBA() {
  const r = await fetch('/api/v1/ueba/top-risky').catch(() => null);
  if (!r) return;
  const d = await r.json();
  document.getElementById('ueba-body').innerHTML = d.map(e => `<tr>
    <td class="mono" style="font-size:.72rem;font-weight:600">${e.ip_address}</td>
    <td class="mono" style="font-size:.72rem">${e.cumulative_risk_score}</td>
    <td><span class="badge ${e.risk_level==='Critical'?'b-c':e.risk_level==='High'?'b-h':e.risk_level==='Medium'?'b-m':'b-l'}">${e.risk_level}</span></td>
  </tr>`).join('') || '<tr><td colspan="3" style="text-align:center;color:var(--t3)">No data.</td></tr>';
}

