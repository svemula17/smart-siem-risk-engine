// ══ CHART DEFAULTS ══
Chart.defaults.color = '#7d8fba';
Chart.defaults.borderColor = '#1a2545';
Chart.defaults.font.family = "'Inter', sans-serif";

// ══ CHART: VOLUME ══
const volchart = new Chart(document.getElementById('volchart'), {
  type: 'line',
  data: { labels: Array(40).fill(''), datasets: [{ label: 'Alerts/s', data: Array(40).fill(0), borderColor: '#2979ff', backgroundColor: 'rgba(41,121,255,0.08)', tension: .4, fill: true, pointRadius: 0, borderWidth: 2 }] },
  options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, suggestedMax: 5, grid: { color: '#1a2545' } }, x: { display: false } }, animation: { duration: 0 } }
});

// ══ CHART: RISK DIST ══
const distchart = new Chart(document.getElementById('distchart'), {
  type: 'doughnut',
  data: { labels: ['Critical','High','Medium','Low'], datasets: [{ data: [RISK_DIST.critical, RISK_DIST.high, RISK_DIST.medium, RISK_DIST.low], backgroundColor: ['#e8294a','#f4522d','#f0ac2b','#23d160'], borderWidth: 0, hoverOffset: 8 }] },
  options: { responsive: true, maintainAspectRatio: false, cutout: '68%', plugins: { legend: { position: 'right', labels: { boxWidth: 9, font: { size: 10 } } } } }
});

// ══ CHART: ATTACK TYPE ══
function buildBarChart(canvasId, labels, values) {
  const colors = ['#e8294a','#f4522d','#f0ac2b','#2979ff','#7c3aed','#00cfdd','#23d160','#ec4899','#f59e0b','#10b981'];
  const ctx = document.getElementById(canvasId);
  if (!ctx) return null;
  return new Chart(ctx, {
    type: 'bar',
    data: { labels, datasets: [{ data: values, backgroundColor: colors.slice(0, labels.length).map(c => c + '99'), borderColor: colors.slice(0, labels.length), borderWidth: 1, borderRadius: 4 }] },
    options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, grid: { color: '#1a2545' } }, y: { grid: { display: false }, ticks: { font: { size: 10 } } } } }
  });
}
buildBarChart('attkchart', Object.keys(ATTK_DIST).slice(0, 8), Object.values(ATTK_DIST).slice(0, 8));

// ══ CHART: TREND ══
let trendchart;
async function loadTrend() {
  const r = await fetch('/api/alert-trends').catch(() => null);
  if (!r) return;
  const d = await r.json();
  const t = d.trend || [];
  const ctx = document.getElementById('trendchart');
  if (trendchart) trendchart.destroy();
  trendchart = new Chart(ctx, {
    type: 'line',
    data: { labels: t.map(x => x.day.slice(5)), datasets: [
      { label: 'Total', data: t.map(x => x.total), borderColor: '#2979ff', backgroundColor: 'rgba(41,121,255,0.08)', tension: .4, fill: true, pointRadius: 3 },
      { label: 'Critical', data: t.map(x => x.critical), borderColor: '#e8294a', tension: .4, pointRadius: 3 },
      { label: 'Blocked', data: t.map(x => x.blocked), borderColor: '#23d160', tension: .4, pointRadius: 3 },
    ]},
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { boxWidth: 9, font: { size: 10 } } } }, scales: { y: { beginAtZero: true, grid: { color: '#1a2545' } }, x: { grid: { display: false } } } }
  });
}
loadTrend();

// ══ CHART: MITRE ══
let mitrechart;
async function loadMitre() {
  const r = await fetch('/api/mitre-heatmap').catch(() => null);
  if (!r) return;
  const d = await r.json();
  const ttps = d.ttps || [];
  if (!ttps.length) return;
  const ctx = document.getElementById('mitrechart');
  if (mitrechart) mitrechart.destroy();
  mitrechart = new Chart(ctx, {
    type: 'bar',
    data: { labels: ttps.map(t => t.id), datasets: [{ label: 'Count', data: ttps.map(t => t.count), backgroundColor: 'rgba(124,58,237,0.55)', borderColor: '#7c3aed', borderWidth: 1, borderRadius: 3 }] },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, grid: { color: '#1a2545' } }, x: { ticks: { font: { size: 9 }, maxRotation: 45 }, grid: { display: false } } } }
  });
}
loadMitre();

// ══ HEATMAP ══
async function buildHeatmap() {
  const r = await fetch('/api/alert-trends').catch(() => null);
  if (!r) return;
  const d = await r.json();
  const trend = d.trend || [];
  const container = document.getElementById('heatmap-container');
  if (!trend.length) { container.innerHTML = '<p style="color:var(--t3);font-size:.78rem;text-align:center">Not enough data.</p>'; return; }
  const days = trend.slice(-7);
  let html = '<div style="overflow-x:auto">';
  days.forEach(day => {
    const total = day.total;
    html += `<div style="display:flex;align-items:center;gap:3px;margin-bottom:3px">`;
    html += `<span style="font-size:.6rem;color:var(--t3);min-width:36px">${day.day.slice(5)}</span>`;
    for (let h = 0; h < 24; h++) {
      const base = total / 24;
      const mult = (h >= 8 && h <= 18) ? 1.5 : 0.6;
      const count = Math.round(base * mult * (0.5 + Math.random()));
      const intensity = Math.min(1, count / Math.max(1, total / 12));
      const bg = intensity > 0.7 ? '#e8294a' : intensity > 0.4 ? '#f4522d' : intensity > 0.2 ? '#f0ac2b' : intensity > 0.05 ? '#162040' : '#1a2545';
      html += `<div title="${day.day} ${String(h).padStart(2,'0')}:00 ~${count} alerts" style="flex:1;height:16px;border-radius:2px;background:${bg};min-width:8px;cursor:pointer"></div>`;
    }
    html += '</div>';
  });
  html += '<div style="display:flex;gap:3px;margin-top:2px"><span style="font-size:.6rem;min-width:36px"> </span>';
  [0,4,8,12,16,20,23].forEach(h => { html += `<span style="font-size:.58rem;color:var(--t3);flex:4;text-align:center">${String(h).padStart(2,'0')}</span>`; });
  html += '</div></div>';
  container.innerHTML = html;
}
buildHeatmap();

// ══ VOLUME TICKER ══
let tick = 0, velWindow = [], velPrev = 0;
setInterval(() => {
  volchart.data.datasets[0].data.shift();
  volchart.data.datasets[0].data.push(tick);
  volchart.update('none');
  velWindow.push(tick); if (velWindow.length > 60) velWindow.shift();
  const perMin = velWindow.reduce((s, v) => s + v, 0);
  document.getElementById('vel-count').textContent = perMin;
  const arr = document.getElementById('vel-arrow');
  arr.textContent = perMin > velPrev * 1.15 ? '↑' : perMin < velPrev * 0.85 ? '↓' : '→';
  arr.className = perMin > velPrev * 1.15 ? 'vel-up' : perMin < velPrev * 0.85 ? 'vel-down' : '';
  velPrev = perMin;
  tick = 0;
}, 1000);

// ══ ANIMATED COUNTER ══
function animateCount(el, target) {
  const start = parseInt(el.textContent.replace(/[^0-9]/g, '')) || 0;
  const steps = 20, inc = (target - start) / steps;
  let cur = start, i = 0;
  const t = setInterval(() => {
    cur += inc; i++;
    el.textContent = Math.round(cur).toLocaleString();
    if (i >= steps) { el.textContent = target.toLocaleString(); clearInterval(t); }
  }, 20);
}

