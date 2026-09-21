/*
 * Safeguradrail Sentinel: service worker.
 * Responsibilities: policy sync, extension census, egress watch (network
 * requests from other extensions and from protected tabs), event relay,
 * approval brokering, heartbeat.
 */
importScripts('shared/patterns.js');

const DEFAULT_CP = 'http://localhost:4173';
const VERSION = chrome.runtime.getManifest().version;

const state = {
  cp: DEFAULT_CP,
  label: '',
  deviceId: null,
  policy: null,
  enforcement: { egress: 'unknown' },
  queue: [],
  canaries: new Map(),      // token -> { tabId, url, at }
  protectedTabs: new Map(), // tabId -> { url, app }
  census: [],
  ready: null
};

function log(...a) { console.log('[sentinel]', ...a); }

// ------------------------------------------------------------ config/policy
async function loadConfig() {
  let managed = {};
  try { managed = await chrome.storage.managed.get(['controlPlaneUrl', 'deviceLabel']); } catch (e) { /* not managed */ }
  const local = await chrome.storage.local.get(['controlPlaneUrl', 'deviceLabel', 'deviceId', 'policy']);
  state.cp = (managed.controlPlaneUrl || local.controlPlaneUrl || DEFAULT_CP).replace(/\/$/, '');
  state.label = managed.deviceLabel || local.deviceLabel || '';
  if (!local.deviceId) {
    local.deviceId = 'dev_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12);
    await chrome.storage.local.set({ deviceId: local.deviceId });
  }
  state.deviceId = local.deviceId;
  if (local.policy) state.policy = local.policy;
}

async function fetchPolicy() {
  try {
    const headers = state.policy && state.policy.etag ? { 'If-None-Match': state.policy.etag } : {};
    const r = await fetch(state.cp + '/policy', { headers });
    if (r.status === 304) return state.policy;
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const policy = await r.json();
    state.policy = policy;
    await chrome.storage.local.set({ policy, policyFetchedAt: Date.now() });
    log('policy', policy.version, policy.etag);
    await refreshProtectedTabs();
    return policy;
  } catch (err) {
    log('policy fetch failed:', err.message);
    return state.policy;
  }
}

function findApp(url) {
  const policy = state.policy;
  if (!policy || !url) return null;
  let u; try { u = new URL(url); } catch (e) { return null; }
  return policy.protectedApps.find(a => a.origins.includes(u.origin) && u.pathname.startsWith(a.pathPrefix || '/')) || null;
}

// ------------------------------------------------------------ tabs
async function refreshProtectedTabs() {
  state.protectedTabs.clear();
  const tabs = await chrome.tabs.query({});
  for (const t of tabs) { const app = findApp(t.url); if (app) state.protectedTabs.set(t.id, { url: t.url, app: app.id }); }
  updateBadge();
}
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (!info.url && !info.status) return;
  const app = findApp(tab.url);
  if (app) state.protectedTabs.set(tabId, { url: tab.url, app: app.id }); else state.protectedTabs.delete(tabId);
  updateBadge();
});
chrome.tabs.onRemoved.addListener(tabId => { state.protectedTabs.delete(tabId); for (const [k, v] of state.canaries) if (v.tabId === tabId) state.canaries.delete(k); updateBadge(); });

function updateBadge() {
  const ai = state.census.filter(c => c.enabled && (c.category === 'unsanctioned-ai' || c.category === 'unsanctioned-ai-agent')).length;
  chrome.action.setBadgeText({ text: ai ? String(ai) : (state.protectedTabs.size ? 'on' : '') });
  chrome.action.setBadgeBackgroundColor({ color: ai ? '#b3121b' : '#0f6b5c' });
}

// ------------------------------------------------------------ events
function emit(event) {
  const e = Object.assign({ ts: new Date().toISOString() }, event);
  if (e.detail) e.detail = SGR.redact(e.detail);
  state.queue.push(e);
  if (state.queue.length >= 20) flush();
}

async function flush() {
  if (!state.queue.length || !state.deviceId) return;
  const batch = state.queue.splice(0, 100);
  try {
    const r = await fetch(state.cp + '/events', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device: state.deviceId, events: batch }) });
    if (!r.ok) throw new Error('HTTP ' + r.status);
  } catch (err) {
    log('flush failed, re-queueing', err.message);
    state.queue.unshift(...batch);
    if (state.queue.length > 500) state.queue.length = 500;
  }
}

async function heartbeat() {
  try {
    await fetch(state.cp + '/heartbeat', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device: state.deviceId, label: state.label, version: VERSION, enforcement: state.enforcement,
        policyEtag: state.policy && state.policy.etag, protectedTabs: state.protectedTabs.size }) });
  } catch (e) { /* offline */ }
}

// ------------------------------------------------------------ census
async function census() {
  let all = [];
  try { all = await chrome.management.getAll(); } catch (err) { log('management.getAll failed', err.message); return; }
  const list = all.filter(x => x.id !== chrome.runtime.id && x.type !== 'theme').map(x => ({
    id: x.id, name: x.name, shortName: x.shortName, description: x.description, version: x.version, enabled: x.enabled,
    installType: x.installType, permissions: x.permissions || [], hostPermissions: x.hostPermissions || [], homepageUrl: x.homepageUrl
  }));
  const opts = state.policy ? { aiKeywords: state.policy.census.aiKeywords, sanctionedExtensions: state.policy.sanctionedExtensions } : {};
  state.census = list.map(x => SGR.classifyExtension(x, opts));
  updateBadge();
  try {
    await fetch(state.cp + '/census', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device: state.deviceId, label: state.label, extensions: list }) });
  } catch (e) { log('census upload failed', e.message); }
}
for (const ev of ['onInstalled', 'onUninstalled', 'onEnabled', 'onDisabled']) {
  chrome.management[ev].addListener(() => { setTimeout(census, 500); });
}

// ------------------------------------------------------------ egress watch
function bodyToText(requestBody) {
  if (!requestBody) return '';
  try {
    if (requestBody.raw) {
      const dec = new TextDecoder('utf-8', { fatal: false });
      return requestBody.raw.map(p => p.bytes ? dec.decode(p.bytes) : '').join('');
    }
    if (requestBody.formData) return JSON.stringify(requestBody.formData);
  } catch (e) { /* binary */ }
  return '';
}

function onBeforeRequest(details) {
  const policy = state.policy;
  const initiator = details.initiator || '';
  const fromExtension = initiator.startsWith('chrome-extension://');
  const extId = fromExtension ? initiator.slice('chrome-extension://'.length) : null;
  if (extId === chrome.runtime.id) return;
  if (!fromExtension && initiator.startsWith('chrome')) return;

  const host = SGR.hostOf(details.url);
  const aiHosts = policy ? policy.aiEndpoints : SGR.DEFAULT_AI_ENDPOINTS;
  const isAI = SGR.hostMatches(host, aiHosts);
  const tabProtected = state.protectedTabs.get(details.tabId);
  // A request from the finance tool itself to a non-AI host is normal traffic; skip early for performance.
  if (!fromExtension && !isAI) return;

  const body = bodyToText(details.requestBody);
  const canaries = SGR.findCanaries(body);
  const sensitive = body ? SGR.findSensitive(body) : [];
  const sanctioned = !!(policy && extId && policy.sanctionedExtensions.includes(extId));

  let code = null, detailParts = [];
  if (canaries.length && isAI) code = 'SR-X01';
  else if (canaries.length) code = 'SR-X05';
  else if (isAI && sensitive.length) code = 'SR-X01';
  else if (isAI && !fromExtension && tabProtected) code = 'SR-X01'; // AI call issued from inside a protected tab (content script)
  else if (isAI && fromExtension && tabProtected) code = null;      // AI extension chatting while a finance tab exists: not evidence by itself
  if (!code) return;

  const canaryMeta = canaries.map(t => state.canaries.get(t)).filter(Boolean);
  const silent = canaryMeta.length && canaryMeta.every(m => !m.interacted);
  if (code === 'SR-X01' && silent) code = 'SR-X08';

  const mode = policy ? policy.egress.mode : 'alert';
  const shouldBlock = mode === 'block' && !sanctioned && (isAI || (canaries.length && policy && policy.egress.blockUnknownWithCanary));
  const blocked = shouldBlock && state.enforcement.egress === 'block';

  const ext = extId ? state.census.find(c => c.id === extId) : null;
  detailParts.push(`${details.method} ${host}${new URL(details.url).pathname.slice(0, 60)}`);
  if (canaries.length) detailParts.push(`${canaries.length} canary token(s) from ${canaryMeta.map(m => m.url).filter(Boolean).slice(0, 2).join(', ') || 'a protected page'}`);
  if (sensitive.length) detailParts.push(sensitive.slice(0, 5).map(s => s.label).join(', ') + ' present in body');
  if (silent) detailParts.push('no user interaction before send');
  detailParts.push(blocked ? 'BLOCKED' : (shouldBlock ? 'not blocked (observe mode)' : 'allowed by policy'));

  emit({ code, url: (tabProtected && tabProtected.url) || (canaryMeta[0] && canaryMeta[0].url), detail: detailParts.join('; '),
    extension: extId ? { id: extId, name: ext ? ext.name : undefined, sanctioned } : { id: 'page', name: 'request from page context' },
    data: { host, blocked, canaries: canaries.length, sensitiveTypes: Array.from(new Set(sensitive.map(s => s.id))).join(',') } });
  flush();
  if (blocked) return { cancel: true };
}

try {
  chrome.webRequest.onBeforeRequest.addListener(onBeforeRequest, { urls: ['<all_urls>'] }, ['blocking', 'requestBody']);
  state.enforcement.egress = 'block';
  log('egress watch: blocking mode');
} catch (err) {
  chrome.webRequest.onBeforeRequest.addListener(onBeforeRequest, { urls: ['<all_urls>'] }, ['requestBody']);
  state.enforcement.egress = 'observe';
  log('egress watch: observe mode (webRequestBlocking needs a policy-installed extension):', err.message);
}

// ------------------------------------------------------------ messages
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    await state.ready;
    const tabId = sender.tab ? sender.tab.id : undefined;
    switch (msg && msg.type) {
      case 'policy:get': return reply({ policy: state.policy, deviceId: state.deviceId });
      case 'canary': state.canaries.set(msg.token, { tabId, url: msg.url, at: Date.now(), interacted: false }); return reply({ ok: true });
      case 'interaction': for (const [, v] of state.canaries) if (v.tabId === tabId) v.interacted = true; return reply({ ok: true });
      case 'event': emit(Object.assign({ url: sender.url }, msg.event)); if (['critical', 'high'].includes(msg.event.severity) || /^SR-(A|I0[35])/.test(msg.event.code)) flush(); return reply({ ok: true });
      case 'approval:request': {
        try {
          const r = await fetch(state.cp + '/approvals', { method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(Object.assign({ device: state.deviceId, url: sender.url }, msg.payload)) });
          return reply(await r.json());
        } catch (e) { return reply({ error: e.message }); }
      }
      case 'approval:poll': {
        try { const r = await fetch(state.cp + '/approvals/' + encodeURIComponent(msg.id)); return reply(await r.json()); }
        catch (e) { return reply({ error: e.message }); }
      }
      case 'status': return reply({ deviceId: state.deviceId, cp: state.cp, label: state.label, version: VERSION, enforcement: state.enforcement,
        policy: state.policy ? { version: state.policy.version, etag: state.policy.etag, apps: state.policy.protectedApps.map(a => a.name) } : null,
        census: state.census, protectedTabs: Array.from(state.protectedTabs.values()), queued: state.queue.length });
      case 'config:set': await chrome.storage.local.set({ controlPlaneUrl: msg.controlPlaneUrl, deviceLabel: msg.deviceLabel }); await loadConfig(); await fetchPolicy(); await census(); await heartbeat(); return reply({ ok: true });
      case 'census:now': await census(); return reply({ ok: true, census: state.census });
      case 'policy:refresh': await fetchPolicy(); return reply({ ok: true, policy: state.policy });
      default: return reply({ error: 'unknown message' });
    }
  })();
  return true;
});

// ------------------------------------------------------------ lifecycle
chrome.alarms.onAlarm.addListener(a => {
  if (a.name === 'flush') { flush(); }
  if (a.name === 'heartbeat') { heartbeat(); fetchPolicy(); }
  if (a.name === 'census') { census(); }
});

async function boot() {
  await loadConfig();
  await fetchPolicy();
  await refreshProtectedTabs();
  await census();
  await heartbeat();
  const cp = (state.policy && state.policy.controlPlane) || {};
  chrome.alarms.create('flush', { periodInMinutes: Math.max(0.1, (cp.flushSeconds || 10) / 60) });
  chrome.alarms.create('heartbeat', { periodInMinutes: Math.max(0.5, (cp.heartbeatSeconds || 60) / 60) });
  chrome.alarms.create('census', { periodInMinutes: Math.max(1, (cp.censusSeconds || 300) / 60) });
  log('ready as', state.deviceId, 'against', state.cp);
}
state.ready = boot();
chrome.runtime.onInstalled.addListener(() => { state.ready = boot(); });
chrome.runtime.onStartup.addListener(() => { state.ready = boot(); });
