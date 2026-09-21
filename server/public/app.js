/* Safeguradrail console: plain JS, polls the control plane API. */
(function () {
  'use strict';
  const $ = s => document.querySelector(s);
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const sev = l => `<span class="sev ${esc(l)}">${esc(l)}</span>`;
  const ago = ts => { const s = Math.max(0, (Date.now() - Date.parse(ts)) / 1000); return s < 60 ? `${Math.round(s)}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : `${Math.round(s / 3600)}h ago`; };
  const time = ts => new Date(ts).toLocaleTimeString();
  const api = (p, opt) => fetch(p, opt).then(r => r.json());
  const post = (p, body) => api(p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  const levelColor = { info: 'var(--info)', low: 'var(--low)', medium: 'var(--medium)', high: 'var(--high)', critical: 'var(--critical)' };

  let taxonomy = null;

  document.querySelectorAll('nav button').forEach(b => b.addEventListener('click', () => {
    document.querySelectorAll('nav button').forEach(x => x.classList.toggle('active', x === b));
    document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.id === 'tab-' + b.dataset.tab));
    refresh();
  }));
  document.querySelectorAll('button.sim').forEach(b => b.addEventListener('click', async () => {
    b.disabled = true; await post('/api/simulate', { scenario: b.dataset.scenario }); b.disabled = false; refresh();
  }));
  $('#resetBtn').addEventListener('click', async () => { if (confirm('Clear all events, alerts, approvals, devices and ledger?')) { await post('/api/reset'); refresh(); } });

  async function refresh() {
    const active = document.querySelector('.tab.active').id.replace('tab-', '');
    const ov = await api('/api/overview');
    renderOverview(ov);
    if (active === 'alerts') renderAlerts(await api('/api/alerts'));
    if (active === 'approvals') renderApprovals(await api('/api/approvals'));
    if (active === 'events') renderEvents(await api('/api/events?limit=300'));
    if (active === 'extensions') renderCensus(await api('/api/extensions'));
    if (active === 'risk') { if (!taxonomy) taxonomy = await api('/api/taxonomy'); renderRisk(taxonomy); }
    if (active === 'ledger') renderLedger(await api('/api/ledger?limit=200'));
  }

  function renderOverview(ov) {
    const c = ov.counts;
    $('#alertBadge').textContent = c.openAlerts || '';
    $('#approvalBadge').textContent = c.pendingApprovals || '';
    $('#ledgerState').textContent = ov.ledger.ok ? `ledger intact · ${ov.ledger.length} entries` : `LEDGER BROKEN at #${ov.ledger.brokenAt}`;
    $('#ledgerState').className = 'pill ' + (ov.ledger.ok ? 'ok' : 'bad');
    $('#policyState').textContent = `policy ${ov.policy.version} · ${ov.policy.etag}`;
    $('#cards').innerHTML = [
      ['Devices', c.devices], ['AI extensions seen', c.aiExtensions, c.aiExtensions > 0], ['Open alerts', c.openAlerts, c.openAlerts > 0],
      ['Critical', c.critical, c.critical > 0], ['Pending approvals', c.pendingApprovals, c.pendingApprovals > 0], ['Events (24h store)', c.events]
    ].map(([l, n, hot]) => `<div class="card ${hot ? 'hot' : ''}"><div class="n">${n}</div><div class="l">${l}</div></div>`).join('');
    const tb = $('#devices tbody');
    tb.innerHTML = ov.devices.length ? ov.devices.sort((a, b) => (b.risk ? b.risk.score : 0) - (a.risk ? a.risk.score : 0)).map(d => {
      const r = d.risk || { score: 0, level: 'info', chains: [] };
      return `<tr><td><b>${esc(d.label || d.id)}</b><br><span class="mono muted">${esc(d.id)}</span></td>
        <td><span class="risk-bar"><i style="width:${r.score}%;background:${levelColor[r.level]}"></i></span>${sev(r.level)} <span class="muted">${r.score}</span></td>
        <td>${d.aiExtensions == null ? '–' : d.aiExtensions}</td>
        <td>${d.enforcement ? `<span class="tag ${d.enforcement.egress === 'block' ? 'ok' : 'ai'}">${esc(d.enforcement.egress)}</span>` : '–'}</td>
        <td>${d.stale ? '<span class="sev critical">stale</span> ' : ''}${ago(d.lastSeen)}</td>
        <td>${(r.chains || []).map(ch => `<span class="tag ai">${esc(ch.id)} ${esc(ch.title)}</span>`).join(' ') || '–'}</td></tr>`;
    }).join('') : '<tr><td colspan="6" class="empty">No devices enrolled yet. Load the Sentinel extension or run a simulation.</td></tr>';
    $('#apps').innerHTML = ov.policy.apps.map(a => `<li><b>${esc(a.name)}</b><br><span class="mono muted">${a.origins.map(esc).join(', ')}</span></li>`).join('');
    $('#families').innerHTML = Object.entries(ov.familyCounts).map(([f, n]) => `<li>${esc(f)} <span class="muted">${n}</span></li>`).join('') || '<li class="muted">none yet</li>';
  }

  function renderAlerts(list) {
    $('#alerts').innerHTML = list.length ? list.map(a => `<div class="item ${esc(a.level)} ${a.acknowledged ? 'acked' : ''}">
      <div class="t"><span>${sev(a.level)} <b>${esc(a.title)}</b> <span class="muted">· ${esc(a.device)}</span></span>
      <span class="muted">${time(a.ts)} ${a.acknowledged ? '' : `<button class="act" data-ack="${a.id}">Acknowledge</button>`}</span></div>
      <div class="d">${esc(a.detail)}</div></div>`).join('') : '<div class="empty">No alerts.</div>';
    document.querySelectorAll('[data-ack]').forEach(b => b.addEventListener('click', async () => { await post(`/api/alerts/${b.dataset.ack}/ack`); refresh(); }));
  }

  function renderApprovals(list) {
    $('#approvals').innerHTML = list.length ? list.map(a => `<div class="item ${a.status === 'pending' ? 'high' : (a.status === 'approved' ? 'low' : 'medium')}">
      <div class="t"><span><b>${esc(a.label || a.actionId)}</b> <span class="muted">· ${esc(a.device)} · ${esc(a.app || '')}</span></span>
      <span class="muted">${time(a.ts)} · <b>${esc(a.status)}</b>${a.approver ? ' by ' + esc(a.approver) : ''}</span></div>
      <div class="ctx">${esc(JSON.stringify(a.context || {}))}</div>
      <div class="d">Requested from ${esc(a.url || '')}${a.provenance ? ' · human presence ' + esc(a.provenance.presence) + ' · trusted ' + esc(a.provenance.isTrusted) : ''}</div>
      ${a.status === 'pending' ? `<div class="row" style="margin-top:8px"><button class="act primary" data-decide="approve" data-id="${a.id}">Approve</button><button class="act" data-decide="deny" data-id="${a.id}">Deny</button></div>` : ''}
    </div>`).join('') : '<div class="empty">No approval requests.</div>';
    document.querySelectorAll('[data-decide]').forEach(b => b.addEventListener('click', async () => {
      const note = b.dataset.decide === 'deny' ? (prompt('Reason for denial (optional)') || '') : '';
      await post(`/api/approvals/${b.dataset.id}/decide`, { decision: b.dataset.decide, approver: 'console-user', note }); refresh();
    }));
  }

  function renderEvents(list) {
    $('#events tbody').innerHTML = list.length ? list.map(e => `<tr><td class="mono">${time(e.ts)}</td><td class="mono">${esc(e.device)}</td>
      <td class="mono">${esc(e.code)}</td><td>${sev(e.severity)}</td><td>${esc(e.title)}</td><td class="muted">${esc(e.detail)}</td>
      <td class="mono">${e.provenance ? esc(`trusted=${e.provenance.isTrusted} presence=${e.provenance.presence ?? '–'}`) : ''}${e.extension ? '<br>' + esc(e.extension.name || e.extension.id) : ''}</td></tr>`).join('')
      : '<tr><td colspan="7" class="empty">No events.</td></tr>';
  }

  function renderCensus(list) {
    $('#census').innerHTML = list.length ? list.map(c => `<h3 style="margin:14px 0 6px;font-size:13px">${esc(c.device)} <span class="muted">· ${ago(c.ts)}</span></h3>
      <table><thead><tr><th>Extension</th><th>Category</th><th>Risk</th><th>Capabilities</th><th>Why</th></tr></thead><tbody>
      ${c.extensions.sort((a, b) => b.risk - a.risk).map(e => `<tr><td><b>${esc(e.name)}</b> <span class="muted">v${esc(e.version)}${e.enabled ? '' : ' (disabled)'}</span><br><span class="mono muted">${esc(e.id)}</span></td>
        <td><span class="tag ${e.category.startsWith('unsanctioned') ? 'ai' : (e.category === 'sanctioned-ai' ? 'ok' : '')}">${esc(e.category)}</span></td>
        <td>${e.risk}</td>
        <td>${Object.entries(e.capabilities).filter(([, v]) => v).map(([k]) => `<span class="tag">${esc(k)}</span>`).join('')}</td>
        <td class="muted">${e.reasons.map(esc).join('; ')}</td></tr>`).join('')}</tbody></table>`).join('')
      : '<div class="empty">No census reports yet.</div>';
  }

  function renderRisk(t) {
    $('#dims').innerHTML = Object.entries(t.dimensions).map(([k, v]) => `<div class="dim"><b>${esc(k)}</b>${Object.entries(v).map(([c, d]) => `<span><span class="tag">${c}</span> ${esc(d)}</span>`).join('')}</div>`).join('');
    $('#taxonomy tbody').innerHTML = Object.entries(t.taxonomy).map(([code, x]) => `<tr><td class="mono">${code}</td><td>${esc(x.family)}</td><td>${sev(x.severity)}</td>
      <td><b>${esc(x.title)}</b><div class="muted">${esc(x.desc)}</div></td><td>${x.dims.map(d => `<span class="tag">${d}</span>`).join('')}</td><td class="muted">${esc(x.detects)}</td></tr>`).join('');
    $('#chains tbody').innerHTML = t.chains.map(c => `<tr><td class="mono">${c.id}<br><b>${esc(c.title)}</b></td><td>${sev(c.level)}</td>
      <td>${c.steps.map(s => s.map(x => `<span class="tag">${x}</span>`).join(' or ')).join(' <b>→</b> ')}${c.repeat ? ` × ${c.repeat}` : ''}</td><td>${Math.round(c.within / 60000)} min</td><td class="muted">${esc(c.desc)}</td></tr>`).join('');
  }

  function renderLedger(l) {
    $('#ledgerVerify').textContent = l.verify.ok ? `Chain verified: ${l.verify.length} entries, head ${l.verify.head.slice(0, 16)}…` : `Chain BROKEN at entry ${l.verify.brokenAt}: ${l.verify.reason}`;
    $('#ledger tbody').innerHTML = l.entries.length ? l.entries.map(e => `<tr><td class="mono">${e.seq}</td><td class="mono">${time(e.ts)}</td><td>${esc(e.type)}</td>
      <td class="mono muted">${esc(JSON.stringify(e.data)).slice(0, 220)}</td><td class="mono muted">${e.hash.slice(0, 14)}…</td></tr>`).join('') : '<tr><td colspan="5" class="empty">Empty.</td></tr>';
  }

  refresh();
  setInterval(refresh, 3000);
})();
