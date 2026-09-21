'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

process.env.SGR_DATA = path.join(os.tmpdir(), 'sgr-test-' + process.pid + '.json');
process.env.PORT = '0';
const { server } = require('../server/index.js');

let base;
test.before(async () => { await new Promise(r => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port; });
test.after(() => { server.close(); try { fs.unlinkSync(process.env.SGR_DATA); } catch (e) { /* ignore */ } });

const post = (p, body) => fetch(base + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(r => r.json());
const get = p => fetch(base + p).then(r => r.json());

test('serves policy with etag and honours If-None-Match', async () => {
  const r = await fetch(base + '/policy');
  assert.equal(r.status, 200);
  const etag = r.headers.get('etag');
  assert.ok(etag);
  const r2 = await fetch(base + '/policy', { headers: { 'If-None-Match': etag } });
  assert.equal(r2.status, 304);
});

test('ingests events, redacts sensitive values, scores chains, raises alerts', async () => {
  const r = await post('/events', { device: 'dev_test', events: [
    { code: 'SR-X08', detail: 'canary leaked, IBAN DE44 5001 0517 5407 3249 31 in body' },
    { code: 'SR-A01', detail: 'synthetic approve blocked', provenance: { isTrusted: false } }
  ] });
  assert.equal(r.accepted, 2);
  assert.equal(r.risk.level, 'critical');
  const events = await get('/api/events?device=dev_test');
  assert.ok(events.every(e => !e.detail.includes('5001 0517')), 'IBAN must be redacted at rest');
  const alerts = await get('/api/alerts');
  assert.ok(alerts.some(a => a.meta.chain === 'CH-1'));
});

test('census classifies and creates posture events once per fingerprint', async () => {
  const ext = [{ id: 'abc', name: 'Summarise AI', description: 'chatgpt for any page', version: '1', enabled: true, installType: 'normal', permissions: ['activeTab'], hostPermissions: ['<all_urls>'] }];
  const r1 = await post('/census', { device: 'dev_census', extensions: ext });
  assert.equal(r1.classified[0].category, 'unsanctioned-ai');
  await post('/census', { device: 'dev_census', extensions: ext });
  const events = await get('/api/events?device=dev_census');
  assert.equal(events.filter(e => e.code === 'SR-S01').length, 1);
});

test('approval lifecycle: request, poll pending, decide, poll decided', async () => {
  const a = await post('/approvals', { device: 'dev_test', actionId: 'approve-payment', label: 'Approve', context: { amount: '$48,200.00', payee: 'Northwind' } });
  assert.ok(a.id);
  assert.equal((await get('/approvals/' + a.id)).status, 'pending');
  const d = await post('/api/approvals/' + a.id + '/decide', { decision: 'deny', approver: 'cfo', note: 'duplicate invoice' });
  assert.equal(d.status, 'denied');
  const s = await get('/approvals/' + a.id);
  assert.equal(s.status, 'denied');
  assert.equal(s.note, 'duplicate invoice');
  const again = await fetch(base + '/api/approvals/' + a.id + '/decide', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ decision: 'approve' }) });
  assert.equal(again.status, 409);
});

test('ledger stays verifiable and simulate scenarios work', async () => {
  const s = await post('/api/simulate', { scenario: 'injected-bank-change' });
  assert.ok(s.risk.chains.some(c => c.id === 'CH-2'));
  const v = await get('/api/ledger/verify');
  assert.ok(v.ok);
  assert.ok(v.length > 5);
});

test('static routes: dashboard, demo app, 404', async () => {
  assert.equal((await fetch(base + '/')).status, 200);
  assert.equal((await fetch(base + '/demo/')).status, 200);
  assert.equal((await fetch(base + '/demo/app.js')).status, 200);
  assert.equal((await fetch(base + '/nope.html')).status, 404);
});
