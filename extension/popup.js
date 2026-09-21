(function () {
  const $ = s => document.querySelector(s);
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  let cp = 'http://localhost:4173';

  function render(st) {
    if (!st || st.error) { $('#device').textContent = 'service worker not ready'; return; }
    cp = st.cp;
    $('#ver').textContent = 'v' + st.version;
    $('#device').textContent = (st.label ? st.label + ' · ' : '') + st.deviceId;
    $('#policy').textContent = st.policy ? `${st.policy.version} (${st.policy.etag})` : 'not loaded';
    $('#egress').innerHTML = st.enforcement.egress === 'block' ? '<span class="ok">blocking</span>' : `<span class="bad">${esc(st.enforcement.egress)}</span>`;
    $('#tabs').textContent = st.protectedTabs.length;
    $('#queued').textContent = st.queued;
    $('#cp').value = st.cp; $('#label').value = st.label || '';
    const list = st.census.slice().sort((a, b) => b.risk - a.risk);
    $('#census').innerHTML = list.length ? list.map(c => `<li><span>${esc(c.name)}${c.enabled ? '' : ' <i>(disabled)</i>'}</span><span class="tag ${c.category.startsWith('unsanctioned') ? 'ai' : ''}">${esc(c.category)} · ${c.risk}</span></li>`).join('') : '<li>no other extensions</li>';
  }
  function refresh() { chrome.runtime.sendMessage({ type: 'status' }, render); }
  $('#save').addEventListener('click', () => chrome.runtime.sendMessage({ type: 'config:set', controlPlaneUrl: $('#cp').value.trim() || 'http://localhost:4173', deviceLabel: $('#label').value.trim() }, refresh));
  $('#census-now').addEventListener('click', () => chrome.runtime.sendMessage({ type: 'census:now' }, refresh));
  $('#console').addEventListener('click', () => chrome.tabs.create({ url: cp + '/' }));
  refresh();
})();
