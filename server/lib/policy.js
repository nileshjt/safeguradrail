'use strict';
/*
 * Policy loading and validation. The policy is the single document that tells
 * Sentinel which origins are finance tools, which controls are high-risk, and
 * how strictly to enforce. It is served verbatim to every enrolled browser.
 */
const fs = require('node:fs');
const crypto = require('node:crypto');
const SGR = require('../../extension/shared/patterns.js');

const CONTROLS = new Set(['observe', 'deny-synthetic', 'step-up', 'dual-control']);

function validate(policy) {
  const problems = [];
  if (!policy || typeof policy !== 'object') return ['policy is not an object'];
  if (!policy.version) problems.push('missing version');
  if (!Array.isArray(policy.protectedApps) || !policy.protectedApps.length) problems.push('protectedApps must be a non-empty array');
  for (const app of policy.protectedApps || []) {
    if (!app.id) problems.push('app without id');
    if (!Array.isArray(app.origins) || !app.origins.length) problems.push(`app ${app.id}: origins required`);
    for (const o of app.origins || []) {
      try { const u = new URL(o); if (u.origin !== o) problems.push(`app ${app.id}: origin "${o}" must be scheme://host[:port] only`); }
      catch (e) { problems.push(`app ${app.id}: invalid origin "${o}"`); }
    }
    for (const a of app.actions || []) {
      if (!a.id || !a.selector) problems.push(`app ${app.id}: action needs id and selector`);
      if (a.control && !CONTROLS.has(a.control)) problems.push(`app ${app.id}: action ${a.id} has unknown control "${a.control}"`);
    }
  }
  if (policy.egress && !['block', 'alert', 'off'].includes(policy.egress.mode)) problems.push('egress.mode must be block|alert|off');
  if (policy.clipboard && !['redact', 'alert', 'off'].includes(policy.clipboard.mode)) problems.push('clipboard.mode must be redact|alert|off');
  return problems;
}

function withDefaults(policy) {
  const p = JSON.parse(JSON.stringify(policy));
  p.aiEndpoints = Array.from(new Set([...(p.aiEndpoints || []), ...SGR.DEFAULT_AI_ENDPOINTS]));
  p.sanctionedExtensions = p.sanctionedExtensions || [];
  p.egress = Object.assign({ mode: 'block', blockUnknownWithCanary: true }, p.egress || {});
  p.clipboard = Object.assign({ mode: 'redact' }, p.clipboard || {});
  p.rail = Object.assign({ maxActionsPerMinute: 12, presenceWindowMs: 4000, minPointerSamples: 5, approvalTimeoutSeconds: 300 }, p.rail || {});
  p.controlPlane = Object.assign({ heartbeatSeconds: 60, censusSeconds: 300, flushSeconds: 10 }, p.controlPlane || {});
  p.census = Object.assign({ aiKeywords: SGR.AI_KEYWORDS }, p.census || {});
  for (const app of p.protectedApps) {
    app.pathPrefix = app.pathPrefix || '/';
    app.shield = Object.assign({ selectors: ['body'], revealSeconds: 8, maskInputs: true }, app.shield || {});
    app.untrustedContent = Object.assign({ selectors: [] }, app.untrustedContent || {});
    app.actions = (app.actions || []).map(a => Object.assign({ event: 'click', control: 'deny-synthetic', context: {} }, a));
  }
  p.etag = crypto.createHash('sha1').update(JSON.stringify(p)).digest('hex').slice(0, 12);
  return p;
}

function load(file) {
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  const problems = validate(raw);
  if (problems.length) throw new Error('Invalid policy: ' + problems.join('; '));
  return withDefaults(raw);
}

function findApp(policy, url) {
  let u;
  try { u = new URL(url); } catch (e) { return null; }
  for (const app of policy.protectedApps) {
    if (app.origins.includes(u.origin) && u.pathname.startsWith(app.pathPrefix)) return app;
  }
  return null;
}

module.exports = { load, validate, withDefaults, findApp, CONTROLS };
