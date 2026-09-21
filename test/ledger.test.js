'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Ledger } = require('../server/lib/ledger');

test('ledger chains hashes and verifies', () => {
  const l = new Ledger();
  l.append('event', { a: 1 });
  l.append('alert', { b: 2 });
  const v = l.verify();
  assert.ok(v.ok);
  assert.equal(v.length, 2);
  assert.equal(l.entries[1].prev, l.entries[0].hash);
});

test('tampering with an entry breaks verification at that entry', () => {
  const l = new Ledger();
  l.append('event', { code: 'SR-A01' });
  l.append('event', { code: 'SR-X01' });
  l.append('event', { code: 'SR-I01' });
  l.entries[1].data.code = 'SR-V01';
  const v = l.verify();
  assert.equal(v.ok, false);
  assert.equal(v.brokenAt, 2);
});

test('deleting an entry breaks verification', () => {
  const l = new Ledger();
  l.append('a', {}); l.append('b', {}); l.append('c', {});
  l.entries.splice(1, 1);
  assert.equal(l.verify().ok, false);
});
