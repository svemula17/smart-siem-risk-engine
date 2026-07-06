// ══ WEBSOCKET ══
let ws, ackSet = new Set(), notifCount = 0;
function connectWS() {
  ws = new WebSocket(`ws://${location.host}/ws/dashboard`);
  ws.onmessage = e => {
    try {
      const d = JSON.parse(e.data);
      if (!d.risk_score) return;
      tick++;
      if (d.risk_score >= 80) { playAlert(); notifCount++; document.getElementById('notif-count').textContent = notifCount > 99 ? '99+' : notifCount; }

      const feed = document.getElementById('livefeed');
      const tr = document.createElement('tr');
      const cls = d.risk_score >= 80 ? 'b-c' : d.risk_score >= 60 ? 'b-h' : d.risk_score >= 30 ? 'b-m' : 'b-l';
      const aml = d.is_anomaly ? '<span class="badge b-p" style="font-size:.58rem;margin-left:3px">AI</span>' : '';
      const aid = d.alert_id || Math.random().toString(36).slice(2, 8);
      const critPulse = d.risk_score >= 80 ? ' pulse' : '';
      tr.innerHTML = `<td><span class="badge ${cls}${critPulse}">${d.risk_score}</span>${aml}</td><td style="font-size:.75rem">${d.attack_type || 'Unknown'}</td><td style="font-size:.72rem">${(d.action_taken || '').replace(/_/g, ' ')}</td><td><button onclick="ack('${aid}',this)" class="btn btn-g" style="padding:1px 6px;font-size:.65rem">ACK</button></td>`;
      feed.prepend(tr);
      if (feed.children.length > 30) feed.removeChild(feed.lastChild);

      const el = document.getElementById('s-alr');
      el.textContent = (parseInt(el.textContent.replace(/,/g, '')) || 0) + 1;

      let idx = d.risk_score >= 80 ? 0 : d.risk_score >= 60 ? 1 : d.risk_score >= 30 ? 2 : 3;
      distchart.data.datasets[0].data[idx]++;
      distchart.update('none');
    } catch(ex) {}
  };
  ws.onclose = () => setTimeout(connectWS, 2000);
}
connectWS();

function ack(id, btn) {
  ackSet.add(id);
  btn.textContent = '✓'; btn.style.color = 'var(--low)'; btn.disabled = true;
}

