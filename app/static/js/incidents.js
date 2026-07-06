// ══ INCIDENTS ══
let curInc = null;
async function fetchIncidents() {
  const r = await fetch('/api/v1/incidents/').catch(() => null);
  if (!r) return;
  const data = await r.json();
  const open = data.filter(i => i.status !== 'Closed');
  animateCount(document.getElementById('s-inc'), open.length);
  document.getElementById('inc-badge').textContent = open.length;
  document.getElementById('inc-body').innerHTML = data.map(inc => {
    const cls = inc.severity === 'Critical' ? 'b-c' : inc.severity === 'High' ? 'b-h' : 'b-m';
    const sla = inc.sla || {};
    const slaColor = sla.sla_status === 'breached' ? '#e74c3c' : sla.sla_status === 'warning' ? '#f39c12' : sla.sla_status === 'met' ? '#2ecc71' : 'var(--low)';
    const slaLabel = sla.sla_status === 'breached' ? '⚠ BREACH' : sla.sla_status === 'warning' ? '◐ ' + (sla.breach_pct||0).toFixed(0) + '%' : sla.sla_status === 'met' ? '✓ Met' : '✓ ' + (sla.breach_pct||0).toFixed(0) + '%';
    const slaTitle = `Elapsed ${(sla.elapsed_hours||0).toFixed(1)}h / SLA ${sla.threshold_hours||'?'}h`;
    return `<tr style="cursor:pointer" onclick="openInc('${inc.id}')">
      <td onclick="event.stopPropagation()"><input type="checkbox" class="inc-cb" data-id="${inc.id}" onchange="updateIncSelCount()"></td>
      <td class="mono" style="font-size:.72rem">${inc.id.slice(0, 8)}…</td>
      <td style="font-weight:500">${inc.title}</td>
      <td><span class="badge ${cls}">${inc.severity}</span></td>
      <td>${inc.status}</td>
      <td style="color:var(--t3);font-size:.72rem">${new Date(inc.created_at).toLocaleString()}</td>
      <td title="${slaTitle}"><span style="font-size:.7rem;font-weight:600;color:${slaColor}">${slaLabel}</span></td>
      <td><button class="btn btn-purple" style="font-size:.65rem;padding:2px 6px" onclick="aiSumInc(event,'${inc.id}','${inc.severity}')">🤖 AI</button></td>
      <td><a class="btn btn-g" style="font-size:.65rem;padding:2px 6px" href="/api/v1/incidents/${inc.id}/report" download onclick="event.stopPropagation()">⬇ Download</a></td>
    </tr>`;
  }).join('') || '<tr><td colspan="9" style="text-align:center;color:var(--t3);padding:2rem">No incidents.</td></tr>';
  updateIncSelCount();
}

function toggleSelectAllIncidents(checked) {
  document.querySelectorAll('.inc-cb').forEach(cb => cb.checked = checked);
  updateIncSelCount();
}
function updateIncSelCount() {
  const n = document.querySelectorAll('.inc-cb:checked').length;
  const el = document.getElementById('inc-sel-count');
  if (el) el.textContent = `${n} selected`;
}
async function bulkCloseIncidents() {
  const ids = [...document.querySelectorAll('.inc-cb:checked')].map(cb => cb.dataset.id);
  if (!ids.length) { toast('No incidents selected', 'warn'); return; }
  if (!confirm(`Close ${ids.length} incident(s)?`)) return;
  const r = await fetch('/api/v1/incidents/bulk/close', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ incident_ids: ids, user: 'Admin' })
  }).catch(() => null);
  if (r) { const d = await r.json(); toast(`Closed ${d.count} incident(s)`, 'success'); fetchIncidents(); }
  else toast('Bulk close failed', 'error');
}

async function openInc(id) {
  curInc = id;
  const r = await fetch(`/api/v1/incidents/${id}`).catch(() => null);
  if (!r) return;
  const d = await r.json();
  document.getElementById('m-title').textContent = d.incident.title;
  document.getElementById('m-desc').textContent = d.incident.description || 'No description.';
  document.getElementById('m-stat').textContent = d.incident.status;
  const s = document.getElementById('m-sev');
  s.textContent = d.incident.severity;
  s.className = 'badge ' + (d.incident.severity === 'Critical' ? 'b-c' : 'b-h');
  document.getElementById('m-tl').innerHTML = (d.timeline || []).map(t => `<li style="padding:.35rem 0;border-bottom:1px dashed var(--border)"><span style="color:var(--t3)">[${new Date(t.created_at).toLocaleTimeString()}]</span> ${t.event_description}</li>`).join('') || '<li style="color:var(--t3)">No events.</li>';
  const aiEl = document.getElementById('m-ai');
  aiEl.innerHTML = '<div class="skel"></div><div class="skel" style="width:80%"></div>';
  const sev = d.incident.severity;
  const risk = sev === 'Critical' ? 90 : sev === 'High' ? 70 : 50;
  const aiR = await fetch('/api/ai/summarize', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ attack_type: 'Unknown', risk_score: risk, affected_count: 1, mitre_ids: [] }) }).catch(() => null);
  if (aiR) {
    const ai = await aiR.json();
    aiEl.innerHTML = `<p style="margin-bottom:.5rem">${ai.summary}</p><ul style="padding-left:1rem;color:var(--t3)">${(ai.recommendations || []).map(r => `<li>${r}</li>`).join('')}</ul>`;
  } else { aiEl.textContent = 'AI analysis unavailable.'; }
  openModal('incModal');
}

async function aiSumInc(e, id, sev) {
  e.stopPropagation();
  const risk = sev === 'Critical' ? 90 : sev === 'High' ? 70 : 50;
  const r = await fetch('/api/ai/summarize', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ attack_type: 'Unknown', risk_score: risk, affected_count: 1, mitre_ids: [] }) }).catch(() => null);
  if (r) { const d = await r.json(); toast(`${d.summary}`, 'info', 6000); }
}

function downloadIncReport() {
  if (!curInc) return;
  window.open(`/api/v1/incidents/${curInc}/report`, '_blank');
}

// ══ QUICK ACTIONS ══
async function qaBlock(ip, alertId) {
  if (!confirm(`Block IP ${ip}?`)) return;
  const r = await fetch('/api/v1/alerts/block-ip', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, raw_alert_id: alertId, reason: 'Manual block from alerts table' })
  }).catch(() => null);
  if (!r) return toast('Block failed', 'error');
  const d = await r.json();
  toast(d.status === 'already_blocked' ? `${ip} already blocked` : `Blocked ${ip}`, 'success');
}
async function qaAddIOC(ip) {
  const desc = prompt(`Add ${ip} as an IOC. Description (optional):`);
  if (desc === null) return;
  const r = await fetch('/api/v1/ioc/', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ioc_type: 'ip', value: ip, severity: 'High', source: 'Manual', description: desc || `Flagged from alert table`, tags: ['manual'] })
  }).catch(() => null);
  if (!r) return toast('IOC add failed', 'error');
  toast(`Added ${ip} to IOC database`, 'success');
}
async function qaIncident(alertId, attackType) {
  const sev = prompt('Severity (Critical/High/Medium/Low):', 'High');
  if (!sev) return;
  const r = await fetch('/api/v1/alerts/create-incident', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ raw_alert_id: alertId, severity: sev, title: '' })
  }).catch(() => null);
  if (!r || !r.ok) return toast('Incident creation failed', 'error');
  const d = await r.json();
  toast(`Incident created: ${d.incident_id.slice(0,8)}…`, 'success');
  fetchIncidents && fetchIncidents();
}

