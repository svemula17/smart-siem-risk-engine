// ══ PIVOT SEARCH ══
async function openPivot(type, value) {
  document.getElementById('pv-title').textContent = `Pivot: ${type.toUpperCase()} = ${value}`;
  document.getElementById('pv-summary').textContent = 'Loading…';
  document.getElementById('pv-content').innerHTML = '<div class="skel"></div><div class="skel" style="width:80%"></div>';
  openModal('pivotModal');
  const r = await fetch(`/api/v1/pivot/${type}/${encodeURIComponent(value)}`).catch(() => null);
  if (!r) { document.getElementById('pv-content').innerHTML = '<div style="color:var(--crit)">Pivot lookup failed</div>'; return; }
  const d = await r.json();
  const s = d.summary;
  document.getElementById('pv-summary').innerHTML =
    `<b>${s.alert_count}</b> alerts · <b>${s.incident_count}</b> incidents · <b>${s.ioc_hits}</b> IOC hits · <b>${s.blocked}</b> blocks · max risk <b>${s.max_risk_score}</b>`;
  const sec = (title, html) => `<div style="margin-bottom:1rem"><div style="font-size:.72rem;font-weight:700;text-transform:uppercase;color:var(--t3);letter-spacing:.05em;margin-bottom:.4rem">${title}</div>${html}</div>`;

  let html = '';
  if (d.ueba) {
    html += sec('UEBA Profile', `<div style="background:var(--hover);padding:.6rem;border-radius:6px">Risk: <b>${d.ueba.risk_level}</b> · Alerts seen: ${d.ueba.total_alerts_seen} · Cumulative risk: ${d.ueba.cumulative_risk_score}</div>`);
  }
  if (d.iocs.length) {
    html += sec('IOC Hits', d.iocs.map(i => `<div style="padding:.3rem 0;border-bottom:1px dashed var(--border)">[${i.severity}] ${i.type} — ${i.description||'—'} <span style="color:var(--t3)">(${i.source||'—'})</span></div>`).join(''));
  }
  if (d.blocked.length) {
    html += sec('Block History', d.blocked.map(b => `<div style="padding:.3rem 0;border-bottom:1px dashed var(--border)">${b.reason} <span style="color:var(--t3)">— alert ${b.raw_alert_id.slice(0,12)}…</span></div>`).join(''));
  }
  if (s.attack_breakdown.length) {
    html += sec('Attack Breakdown',
      `<div style="display:flex;flex-wrap:wrap;gap:.4rem">` +
      s.attack_breakdown.map(a => `<span class="badge b-h">${a.attack_type}: ${a.count}</span>`).join('') +
      `</div>`);
  }
  if (d.incidents.length) {
    html += sec('Linked Incidents', d.incidents.map(i =>
      `<div style="padding:.35rem 0;border-bottom:1px dashed var(--border);display:flex;gap:.5rem;align-items:center">
        <span class="badge ${i.severity==='Critical'?'b-c':i.severity==='High'?'b-h':'b-m'}">${i.severity}</span>
        <span style="flex:1">${i.title}</span>
        <span style="color:var(--t3);font-size:.7rem">${i.status}</span>
      </div>`).join(''));
  }
  if (d.alerts.length) {
    html += sec(`Related Alerts (${d.alerts.length})`,
      `<table style="width:100%"><thead><tr><th>ID</th><th>Risk</th><th>Attack</th><th>Source IP</th><th>Action</th></tr></thead><tbody>` +
      d.alerts.slice(0, 50).map(a => {
        const cls = a.risk_score >= 80 ? 'b-c' : a.risk_score >= 60 ? 'b-h' : a.risk_score >= 30 ? 'b-m' : 'b-l';
        return `<tr>
          <td class="mono" style="font-size:.7rem">${(a.raw_alert_id||'').slice(0,10)}…</td>
          <td><span class="badge ${cls}">${a.risk_score}</span></td>
          <td style="font-size:.72rem">${a.attack_type}</td>
          <td class="mono" style="font-size:.7rem">${a.source_ip||'—'}</td>
          <td style="font-size:.7rem;color:var(--t3)">${(a.recommended_action||'').replace(/_/g,' ')}</td>
        </tr>`;
      }).join('') + `</tbody></table>`);
  }
  if (!html) html = '<div style="color:var(--t3);text-align:center;padding:2rem">No related artifacts found.</div>';
  document.getElementById('pv-content').innerHTML = html;
}

// ══ AI CHAT ══
function toggleChat() {
  document.getElementById('ai-chat-panel').classList.toggle('open');
}
async function sendChat() {
  const inp = document.getElementById('chat-input');
  const q = inp.value.trim();
  if (!q) return;
  const body = document.getElementById('chat-body');
  body.insertAdjacentHTML('beforeend', `<div class="chat-msg-u">${q}</div><div class="chat-msg-a" id="chat-pending">Thinking…</div>`);
  body.scrollTop = body.scrollHeight;
  inp.value = '';
  const r = await fetch('/api/ai/chat', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ question: q })
  }).catch(() => null);
  const pending = document.getElementById('chat-pending');
  pending.id = '';
  if (!r) { pending.textContent = 'Investigator unavailable.'; return; }
  const d = await r.json();
  pending.textContent = d.answer;
  body.scrollTop = body.scrollHeight;
}

// ══ MITRE HEATMAP ══
async function loadMitreHeatmap() {
  const grid = document.getElementById('mh-grid');
  grid.innerHTML = '<div style="color:var(--t3);text-align:center;padding:2rem">Loading…</div>';
  const r = await fetch('/api/v1/mitre/heatmap').catch(() => null);
  if (!r) { grid.innerHTML = '<div style="color:var(--t3);text-align:center;padding:2rem">Unavailable</div>'; return; }
  const d = await r.json();
  document.getElementById('mh-techs').textContent = d.total_techniques;
  document.getElementById('mh-hits').textContent = d.total_alerts_with_ttp;
  document.getElementById('mh-peak').textContent = d.max_count;
  const cellHtml = (t) => {
    const intensity = t.intensity || 0;
    const bg = `rgba(231, 76, 60, ${0.15 + intensity * 0.7})`;
    return `<div style="background:${bg};padding:.4rem .55rem;border-radius:4px;font-size:.72rem;display:flex;justify-content:space-between;gap:.4rem;align-items:center;border:1px solid rgba(231,76,60,.25)"><span class="mono" style="font-weight:600">${t.id}</span><span style="font-weight:700">${t.count}</span></div>`;
  };
  grid.innerHTML = d.tactics.map(tac => `
    <div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:.75rem">
      <div style="font-size:.78rem;font-weight:700;color:var(--t2);margin-bottom:.55rem;text-transform:uppercase;letter-spacing:.04em">${tac.name}</div>
      ${tac.techniques.length ? tac.techniques.map(cellHtml).join('') : '<div style="color:var(--t3);font-size:.72rem">No activity</div>'}
    </div>`).join('');
}

// ══ GEO MAP ══
let _geoMap = null;
async function loadGeoMap() {
  const r = await fetch('/api/v1/network/geoip?top=50').catch(() => null);
  if (!r) { toast('Geo map unavailable', 'error'); return; }
  const d = await r.json();
  document.getElementById('gm-uniq').textContent = d.total_unique_ips;
  document.getElementById('gm-res').textContent = d.resolved_points;
  document.getElementById('gm-top').textContent = (d.top_countries[0] && d.top_countries[0].country) || '—';
  document.getElementById('gm-countries').innerHTML = d.top_countries.map(c =>
    `<div style="display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px dashed var(--border)"><span>${c.country}</span><span style="color:var(--t3)">${c.alerts} alerts</span></div>`
  ).join('') || '<div style="color:var(--t3)">No data</div>';

  if (!_geoMap) {
    _geoMap = L.map('geomap-canvas', { center: [20, 0], zoom: 2, attributionControl: false });
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { maxZoom: 18 }).addTo(_geoMap);
  } else {
    _geoMap.eachLayer(l => { if (l instanceof L.CircleMarker) _geoMap.removeLayer(l); });
  }
  setTimeout(() => _geoMap.invalidateSize(), 100);
  const maxCount = Math.max(...d.points.map(p => p.alert_count), 1);
  d.points.forEach(p => {
    const radius = 4 + (p.alert_count / maxCount) * 18;
    L.circleMarker([p.lat, p.lon], {
      radius, color: '#e74c3c', fillColor: '#e74c3c', fillOpacity: 0.55, weight: 1.5
    }).addTo(_geoMap).bindPopup(`<b>${p.ip}</b><br>${p.city || ''} ${p.country}<br>Alerts: ${p.alert_count}`);
  });
}

async function resolveInc() {
  if (!curInc) return;
  await fetch(`/api/v1/incidents/${curInc}/status?status=Closed&user=Admin`, { method: 'PUT' });
  closeModal('incModal'); fetchIncidents(); toast('Incident marked resolved', 'success');
}

