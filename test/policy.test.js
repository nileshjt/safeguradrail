'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const policy = require('../server/lib/policy');

test('default policy loads, validates, and gets defaults applied', () => {
  const p = policy.load(path.join(__dirname, '..', 'server', 'policies', 'default.json'));
  assert.ok(p.etag);
  assert.ok(p.aiEndpoints.includes('api.openai.com'));
  assert.equal(p.egress.mode, 'block');
  const app = p.protectedApps[0];
  assert.equal(app.pathPrefix, '/demo');
  assert.ok(app.actions.every(a => a.event && a.control));
});

test('validation rejects bad origins and unknown controls', () => {
  const problems = policy.validate({ version: '1', protectedApps: [{ id: 'x', origins: ['http://a.example/path'], actions: [{ id: 'y', selector: 'b', control: 'magic' }] }], egress: { mode: 'sometimes' } });
  assert.ok(problems.some(p => /origin/.test(p)));
  assert.ok(problems.some(p => /unknown control/.test(p)));
  assert.ok(problems.some(p => /egress.mode/.test(p)));
});

test('findApp matches origin plus path prefix only', () => {
  const p = policy.withDefaults({ version: '1', protectedApps: [{ id: 'ap', origins: ['http://localhost:4173'], pathPrefix: '/demo' }] });
  assert.equal(policy.findApp(p, 'http://localhost:4173/demo/#payments').id, 'ap');
  assert.equal(policy.findApp(p, 'http://localhost:4173/'), null, 'dashboard is not protected');
  assert.equal(policy.findApp(p, 'http://localhost:4174/demo/'), null);
});
