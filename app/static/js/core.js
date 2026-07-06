// ══ TOAST ══
function toast(msg, type='info', dur=3500) {
  const tc = document.getElementById('toast-container');
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = msg;
  tc.appendChild(t);
  setTimeout(() => {
    t.style.transition = 'all .3s';
    t.style.opacity = '0';
    t.style.transform = 'translateX(110%)';
    setTimeout(() => t.remove(), 300);
  }, dur);
}

// ══ SOUND ══
let soundEnabled = false, audioCtx = null;
function toggleSound() {
  soundEnabled = !soundEnabled;
  document.getElementById('soundBtn').textContent = soundEnabled ? '🔊' : '🔇';
  toast(soundEnabled ? 'Alert sounds ON' : 'Alert sounds OFF', 'info', 1800);
}
function playAlert() {
  if (!soundEnabled) return;
  try {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator(), gain = audioCtx.createGain();
    osc.connect(gain); gain.connect(audioCtx.destination);
    osc.frequency.setValueAtTime(880, audioCtx.currentTime);
    osc.frequency.setValueAtTime(440, audioCtx.currentTime + 0.1);
    gain.gain.setValueAtTime(0.25, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.4);
    osc.start(); osc.stop(audioCtx.currentTime + 0.4);
  } catch(e) {}
}

// ══ THEME ══
function toggleTheme() {
  const r = document.documentElement;
  const t = r.getAttribute('data-theme') === 'light' ? '' : 'light';
  r.setAttribute('data-theme', t);
  localStorage.setItem('siem-theme', t);
  toast('Theme switched', 'info', 1500);
}
(function() { const t = localStorage.getItem('siem-theme'); if (t) document.documentElement.setAttribute('data-theme', t); })();

// ══ SIDEBAR COLLAPSE ══
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('collapsed');
}

// ══ KEYBOARD SHORTCUTS ══
document.addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
    if (e.key === 'Escape') { e.target.blur(); return; }
    return;
  }
  if (e.key === 'Escape') { document.querySelectorAll('.modal.active').forEach(m => m.classList.remove('active')); return; }
  const map = { d:'dashboard', i:'incidents', a:'alerts', h:'hunting', k:'killchain', c:'compliance', m:'ml', f:'forecast', b:null };
  if (e.key === 'b') { toggleSidebar(); return; }
  if (e.key === '/') { e.preventDefault(); document.getElementById('global-search').focus(); return; }
  if (e.key === '?') { openModal('kbModal'); return; }
  const tab = map[e.key.toLowerCase()];
  if (tab) sw(tab, document.querySelector(`[data-tab="${tab}"]`));
});

// ══ GLOBAL SEARCH ══
function globalSearch(q) {
  if (!q || q.length < 2) return;
  const lq = q.toLowerCase();
  const matches = allAlerts.filter(a =>
    (a.raw_alert_id || '').toLowerCase().includes(lq) ||
    (a.attack_type || '').toLowerCase().includes(lq) ||
    (a.source_ip || '').includes(lq)
  );
  if (matches.length > 0) {
    sw('alerts', document.querySelector('[data-tab="alerts"]'));
    renderAlerts(matches);
    toast(`Found ${matches.length} alert(s) matching "${q}"`, 'info');
  }
}

// ══ TAB SYSTEM ══
const TAB_TITLES = {
  dashboard:'Global Security Posture', incidents:'Incident Management',
  alerts:'Alert Investigations', attacks:'Attack Pattern Analysis',
  hunting:'Threat Hunting Engine', killchain:'Kill Chain View',
  ioc:'IOC Manager', compliance:'Compliance & SLA',
  playbooks:'Automated Playbooks', ml:'ML Insights & Model Metrics',
  netintel:'Network Intelligence', forecast:'Threat Forecast (7-Day)',
  mitremap:'MITRE ATT&CK Heatmap', geomap:'Geo Threat Map',
  sources:'Data Connectors', audit:'Audit Log', settings:'Platform Settings'
};
function sw(id, el) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  const tab = document.getElementById('tab-' + id);
  if (tab) tab.classList.add('active');
  document.querySelectorAll('.ni').forEach(n => n.classList.remove('active'));
  const ni = el || document.querySelector(`[data-tab="${id}"]`);
  if (ni) ni.classList.add('active');
  document.getElementById('topbar-pg').textContent = TAB_TITLES[id] || id;
  const on = {
    incidents: fetchIncidents,
    alerts: fetchAlerts,
    attacks: () => { fetchAttacks(); fetchClusters(); },
    killchain: loadKillChain,
    ioc: loadIOC,
    compliance: () => { loadCompliance(); loadSLA(); },
    audit: loadAudit,
    settings: () => { fetchRules(); loadSupRules(); },
    playbooks: loadPlaybooks,
    ml: loadMLInsights,
    netintel: loadNetworkIntel,
    mitremap: loadMitreHeatmap,
    geomap: loadGeoMap,
    forecast: loadForecast,
  };
  if (on[id]) on[id]();
  if (id === 'dashboard' && window._leafletMap) window._leafletMap.invalidateSize();
}

// ══ MODAL ══
function openModal(id) { document.getElementById(id).classList.add('active'); }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }

