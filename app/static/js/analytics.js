// ══ INIT ══
fetchIncidents();
fetchRules();
fetchUEBA();
loadFPCount();
refreshGauge();
refreshAnomalySparkline();
refreshRiskBanner();
refreshPlaybookMini();

setInterval(() => {
  document.getElementById('ts').textContent = new Date().toLocaleString() + '  ·  Real-Time SOC v3';
  fetchUEBA();
  document.getElementById('zeekEps').textContent = 400 + Math.floor(Math.random() * 100);
  document.getElementById('cylanceLat').textContent = 10 + Math.floor(Math.random() * 8);
  fetch('/api/webhook/events').then(r => r.json()).then(d => { document.getElementById('wh-count').textContent = (d.events || []).length; }).catch(() => {});
}, 5000);

setInterval(() => {
  refreshGauge();
  refreshAnomalySparkline();
  refreshRiskBanner();
  refreshPlaybookMini();
}, 30000);

document.getElementById('ts').textContent = new Date().toLocaleString() + '  ·  Real-Time SOC v3';

// ══════════════════════════ ATTACK GRAPH ══════════════════════════
const GRAPH_COLORS = { ip:'#3b82f6', user:'#a855f7', host:'#10b981', process:'#f59e0b', domain:'#ef4444', hash:'#6b7280' };
let _cy = null;

function _buildCy(payload) {
  if (typeof cytoscape === 'undefined') {
    document.getElementById('graph-cy').innerHTML = '<div style="padding:1rem;color:var(--t3)">Cytoscape failed to load (offline?).</div>';
    return;
  }
  const elements = [];
  (payload.nodes || []).forEach(n => {
    elements.push({ data: { id: n.id, label: n.value, type: n.type, tier: n.tier || '', risk: n.risk_score || 0, focus: !!n.focus } });
  });
  (payload.edges || []).forEach(e => {
    elements.push({ data: { id: `${e.source}->${e.target}:${e.relation}`, source: e.source, target: e.target, relation: e.relation, count: e.count || 1 } });
  });
  if (_cy) { try { _cy.destroy(); } catch(_) {} }
  _cy = cytoscape({
    container: document.getElementById('graph-cy'),
    elements,
    style: [
      { selector: 'node', style: {
        'background-color': ele => GRAPH_COLORS[ele.data('type')] || '#94a3b8',
        'label': 'data(label)',
        'font-size': 9,
        'color': '#e2e8f0',
        'text-outline-width': 2,
        'text-outline-color': '#0b1220',
        'width': ele => 14 + Math.min(30, (ele.data('risk') || 0) / 4),
        'height': ele => 14 + Math.min(30, (ele.data('risk') || 0) / 4),
        'border-width': ele => ele.data('focus') ? 3 : 0,
        'border-color': '#fbbf24',
      }},
      { selector: 'edge', style: {
        'width': ele => Math.min(6, 1 + Math.log2((ele.data('count') || 1) + 1)),
        'line-color': '#475569',
        'target-arrow-color': '#475569',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'opacity': 0.7,
        'label': 'data(relation)',
        'font-size': 7,
        'color': '#94a3b8',
        'text-rotation': 'autorotate',
        'text-background-opacity': 0,
      }},
      { selector: 'node:selected', style: { 'border-width': 3, 'border-color': '#22d3ee' } },
    ],
    layout: { name: 'cose', animate: false, idealEdgeLength: 90, nodeRepulsion: 8000 },
  });
  _cy.on('tap', 'node', evt => {
    const d = evt.target.data();
    loadNodeDetail(d.type, d.label);
  });
}

async function graphRefresh() {
  try {
    const s = await fetch('/api/v1/graph/stats').then(r => r.json());
    document.getElementById('graph-stats').textContent = `${s.nodes || 0} nodes · ${s.edges || 0} edges`;
  } catch (e) {}
  loadLateralChains();
  graphLoadAll();
}

async function graphLoadAll() {
  try {
    const r = await fetch('/api/v1/graph/all?limit=200').then(r => r.json());
    _buildCy(r);
  } catch (e) { console.warn('graph all failed', e); }
}

async function graphLoadFocus() {
  const value = document.getElementById('graph-focus').value.trim();
  const type = document.getElementById('graph-focus-type').value;
  const depth = document.getElementById('graph-depth').value;
  if (!value) { graphLoadAll(); return; }
  try {
    const r = await fetch(`/api/v1/graph/neighborhood/${type}/${encodeURIComponent(value)}?depth=${depth}`).then(r => r.json());
    if (!r.nodes || r.nodes.length === 0) {
      document.getElementById('graph-cy').innerHTML = `<div style="padding:1rem;color:var(--t3)">No graph data for ${type}:${value} yet.</div>`;
      return;
    }
    _buildCy(r);
    loadNodeDetail(type, value);
  } catch (e) { console.warn('focus load failed', e); }
}

async function graphScan() {
  try {
    const r = await fetch('/api/v1/graph/scan', { method:'POST' }).then(r => r.json());
    if (typeof showToast === 'function') showToast(`Scanned ${r.scanned_nodes} nodes, ${r.incidents?.length || 0} new chains`, 'info');
    loadLateralChains();
  } catch (e) { console.warn('scan failed', e); }
}

async function loadLateralChains() {
  try {
    const rows = await fetch('/api/v1/graph/lateral-chains?limit=25').then(r => r.json());
    const open = rows.filter(r => r.status === 'open');
    const badge = document.getElementById('lm-badge');
    if (badge) badge.textContent = open.length;
    const html = rows.length === 0
      ? '<div style="color:var(--t3);padding:.4rem">No lateral-movement chains detected yet.</div>'
      : rows.map(r => `
        <div style="padding:.45rem;border-bottom:1px solid var(--border)">
          <div style="display:flex;justify-content:space-between;gap:.4rem">
            <span style="font-weight:600;color:var(--t1)">${r.pattern.replace(/_/g,' ')}</span>
            <span class="badge" style="background:rgba(239,68,68,.15);color:#ef4444">${r.severity}</span>
          </div>
          <div style="font-size:.68rem;color:var(--t2);margin-top:.2rem">${r.description || ''}</div>
          <div style="font-size:.62rem;color:var(--t3);margin-top:.15rem">${r.path.join(' → ')}</div>
          <div style="margin-top:.25rem;display:flex;gap:.3rem">
            <button class="btn btn-g" style="font-size:.62rem;padding:1px 5px" onclick="graphHighlightPath(${JSON.stringify(r.path).replace(/"/g,'&quot;')})">View</button>
            ${r.status === 'open' ? `<button class="btn btn-g" style="font-size:.62rem;padding:1px 5px" onclick="closeChain(${r.id})">Close</button>` : ''}
          </div>
        </div>`).join('');
    document.getElementById('lateral-chains').innerHTML = html;
  } catch (e) {
    document.getElementById('lateral-chains').innerHTML = '<div style="color:var(--t3);padding:.4rem">Failed to load chains.</div>';
  }
}

async function closeChain(id) {
  await fetch(`/api/v1/graph/lateral-chains/${id}/close`, { method:'POST' });
  loadLateralChains();
}

function graphHighlightPath(path) {
  if (!_cy || !path || path.length === 0) return;
  _cy.elements().removeClass('hl');
  path.forEach(k => { const n = _cy.getElementById(k); if (n) n.select(); });
  const first = _cy.getElementById(path[0]);
  if (first && first.length) _cy.center(first);
}

async function loadNodeDetail(type, value) {
  document.getElementById('node-detail-title').textContent = `${type}: ${value}`;
  try {
    const d = await fetch(`/api/v1/graph/node/${type}/${encodeURIComponent(value)}`).then(r => r.json());
    if (d.detail) { document.getElementById('node-detail').innerHTML = `<div style="color:var(--t3)">${d.detail}</div>`; return; }
    const edges = (d.edges || []).slice(0, 20).map(e => `
      <div style="padding:.25rem 0;border-bottom:1px dashed var(--border);font-size:.68rem">
        <span style="color:var(--t3)">${e.direction === 'out' ? '→' : '←'}</span>
        <span style="color:var(--t1)">${e.other.type}:${e.other.value}</span>
        <span style="color:var(--t3)"> · ${e.relation} · ×${e.count}</span>
      </div>`).join('');
    document.getElementById('node-detail').innerHTML = `
      <div style="margin-bottom:.4rem">
        <div><b>Type:</b> ${d.node.type} · <b>Tier:</b> ${d.node.tier || '—'}</div>
        <div><b>Risk:</b> ${d.node.risk_score} · <b>Last seen:</b> ${(d.node.last_seen || '').slice(0,19)}</div>
        <div style="margin-top:.3rem;display:flex;gap:.3rem">
          <button class="btn btn-p" style="font-size:.62rem;padding:1px 5px" onclick="investigateNode('${type}','${value.replace(/'/g,"\\'")}')">🤖 Investigate</button>
          <button class="btn btn-g" style="font-size:.62rem;padding:1px 5px" onclick="document.getElementById('graph-focus').value='${value.replace(/'/g,"\\'")}';document.getElementById('graph-focus-type').value='${type}';graphLoadFocus()">⌖ Focus</button>
        </div>
      </div>
      <div style="font-weight:600;color:var(--t2);margin-top:.4rem;margin-bottom:.2rem">Edges (${(d.edges || []).length})</div>
      ${edges || '<div style="color:var(--t3)">No edges</div>'}
    `;
  } catch (e) {
    document.getElementById('node-detail').innerHTML = '<div style="color:var(--t3)">Failed to load node.</div>';
  }
}

async function investigateNode(type, value) {
  try {
    const r = await fetch('/api/v1/graph/investigate', {
      method:'POST', headers:{ 'Content-Type':'application/json' },
      body: JSON.stringify({ node_type:type, value, depth:2 }),
    }).then(r => r.json());
    _buildCy(r.subgraph);
    const patterns = (r.patterns || []).map(p => `<div style="color:#ef4444">⚠ ${p.pattern}: ${p.description}</div>`).join('');
    document.getElementById('node-detail').innerHTML = `
      <div style="margin-bottom:.4rem;font-size:.72rem;color:var(--t1)">${r.narrative}</div>
      ${patterns}
    `;
  } catch (e) { console.warn('investigate failed', e); }
}

// Lazy-load when tab opens
(function () {
  const orig = window.sw;
  if (typeof orig !== 'function') return;
  window.sw = function (tab, el) {
    orig(tab, el);
    if (tab === 'graph') graphRefresh();
  };
})();

// Prime the badge on load
setTimeout(loadLateralChains, 1500);
setInterval(loadLateralChains, 30000);
