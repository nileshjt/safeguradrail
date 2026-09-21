'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const risk = require('../server/lib/risk');

const at = (min, code, extra) => Object.assign({ id: code + '@' + min, code, ts: new Date(Date.UTC(2026, 8, 21, 10, min)).toISOString(), severity: risk.TAXONOMY[code].severity }, extra || {});
const NOW = Date.UTC(2026, 8, 21, 11, 0);

test('every taxonomy entry has a family, severity, dimensions and detector', () => {
  for (const [code, t] of Object.entries(risk.TAXONOMY)) {
    assert.match(code, /^SR-[A-Z]\d{2}$/);
    assert.ok(t.family && t.title && t.desc && t.detects, code);
    assert.ok(risk.SEVERITY_WEIGHT[t.severity] !== undefined, code + ' severity');
    for (const d of t.dims) {
      const dim = Object.values(risk.DIMENSIONS).find(x => x[d]);
      assert.ok(dim, `${code}: unknown dimension ${d}`);
    }
  }
});

test('unknown codes normalise to SR-UNK with low severity', () => {
  const n = risk.normaliseEvent({ code: 'SR-ZZZ' });
  assert.equal(n.code, 'SR-UNK');
  assert.equal(n.severity, 'low');
});

test('scrape-then-act chain is detected in order and within window', () => {
  const r = risk.evaluateDevice([at(0, 'SR-S01'), at(1, 'SR-X08'), at(5, 'SR-A01')], NOW);
  assert.ok(r.chains.some(c => c.id === 'CH-1'));
  assert.equal(r.level, 'critical');
  assert.ok(r.score >= 80);
});

test('chain is not matched when the action precedes the scrape', () => {
  const r = risk.evaluateDevice([at(0, 'SR-A01'), at(5, 'SR-X01')], NOW);
  assert.ok(!r.chains.some(c => c.id === 'CH-1'));
});

test('chain is not matched outside its time window', () => {
  const r = risk.evaluateDevice([at(0, 'SR-X01'), at(30, 'SR-A01')], NOW);
  assert.ok(!r.chains.some(c => c.id === 'CH-1'), 'CH-1 window is 10 minutes');
});

test('injected bank change chain', () => {
  const r = risk.evaluateDevice([at(0, 'SR-I02'), at(2, 'SR-A02')], NOW);
  assert.ok(r.chains.some(c => c.id === 'CH-2'));
});

test('bulk harvest requires three exfil events within five minutes', () => {
  assert.ok(risk.evaluateDevice([at(0, 'SR-X01'), at(1, 'SR-X01'), at(3, 'SR-X05')], NOW).chains.some(c => c.id === 'CH-4'));
  assert.ok(!risk.evaluateDevice([at(0, 'SR-X01'), at(4, 'SR-X01'), at(9, 'SR-X01')], NOW).chains.some(c => c.id === 'CH-4'));
});

test('a lone informational event scores zero', () => {
  const r = risk.evaluateDevice([at(0, 'SR-V01')], NOW);
  assert.equal(r.score, 0);
  assert.equal(r.level, 'info');
});

test('posture events derive from census and only fire SR-S02 on permission gain', () => {
  const SGR = require('../extension/shared/patterns.js');
  const before = [SGR.classifyExtension({ id: 'x', name: 'Tab Notes', version: '1.0', permissions: ['storage'], hostPermissions: [] })];
  const after = [SGR.classifyExtension({ id: 'x', name: 'Tab Notes', version: '1.1', permissions: ['storage', 'cookies'], hostPermissions: ['<all_urls>'] })];
  const codes = risk.postureEventsFromCensus(after, before).map(p => p.code);
  assert.ok(codes.includes('SR-S02'));
  assert.ok(codes.includes('SR-X06'));
  assert.ok(!codes.includes('SR-S01'), 'not an AI extension');
});
