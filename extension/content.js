/*
 * Safeguradrail Sentinel: content script.
 * Runs on every page at document_start; activates only when the page matches
 * a protected finance app in policy. Implements the in-page controls:
 *   Canary Tracer, Field Shield, Action Rail (deny-synthetic / step-up /
 *   dual-control), Injection Scan + neutralisation, Tamper Watch,
 *   Clipboard Guard, and provenance recording.
 */
(function () {
  'use strict';
  if (window.__sgrLoaded) return;
  window.__sgrLoaded = true;

  const SGR = globalThis.SGR;
  const isTop = window.top === window;

  function send(msg) {
    return new Promise(resolve => {
      try { chrome.runtime.sendMessage(msg, r => resolve(chrome.runtime.lastError ? { error: chrome.runtime.lastError.message } : r)); }
      catch (e) { resolve({ error: e.message }); }
    });
  }

  function findApp(policy, url) {
    if (!policy) return null;
    let u; try { u = new URL(url); } catch (e) { return null; }
    return policy.protectedApps.find(a => a.origins.includes(u.origin) && u.pathname.startsWith(a.pathPrefix || '/')) || null;
  }

  async function getPolicy() {
    try {
      const local = await chrome.storage.local.get(['policy']);
      if (local.policy) return local.policy;
    } catch (e) { /* fall through */ }
    const r = await send({ type: 'policy:get' });
    return r && r.policy;
  }

  getPolicy().then(policy => {
    const app = findApp(policy, location.href);
    if (!app) return;
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => activate(policy, app));
    else activate(policy, app);
  });

  // ================================================================ activate
  function activate(policy, app) {
    const rail = policy.rail;
    const state = { presence: [], keys: [], lastTrusted: 0, actions: [], bypass: new Set(), revealTimers: new WeakMap(),
      originals: new WeakMap(), canaryEl: null, canaryToken: null, interacted: false, reportedFields: new Set(), snapshots: new Map() };

    const ui = makeUI();

    function report(code, detail, extra) {
      const event = Object.assign({ code, detail, url: location.href, app: app.id, provenance: provenance() }, extra || {});
      send({ type: 'event', event });
      return event;
    }

    // ------------------------------------------------ presence tracking
    function trim(arr, windowMs) { const cut = Date.now() - windowMs; while (arr.length && arr[0] < cut) arr.shift(); }
    document.addEventListener('pointermove', e => { if (e.isTrusted) { state.presence.push(Date.now()); trim(state.presence, rail.presenceWindowMs); noteInteraction(); } }, true);
    document.addEventListener('keydown', e => { if (e.isTrusted) { state.keys.push(Date.now()); trim(state.keys, rail.presenceWindowMs); noteInteraction(); } }, true);
    document.addEventListener('pointerdown', e => { if (e.isTrusted) noteInteraction(); }, true);
    function noteInteraction() {
      state.lastTrusted = Date.now();
      if (!state.interacted) { state.interacted = true; send({ type: 'interaction' }); }
    }
    function provenance() {
      trim(state.presence, rail.presenceWindowMs); trim(state.keys, rail.presenceWindowMs);
      return { presence: state.presence.length, keys: state.keys.length, sinceTrustedMs: state.lastTrusted ? Date.now() - state.lastTrusted : null, velocity: actionsLastMinute() };
    }
    function actionsLastMinute() { const cut = Date.now() - 60e3; state.actions = state.actions.filter(t => t > cut); return state.actions.length; }

    // ------------------------------------------------ canary tracer
    if (isTop) {
      const token = SGR.CANARY_PREFIX + Array.from(crypto.getRandomValues(new Uint8Array(6))).map(b => b.toString(16).padStart(2, '0')).join('');
      state.canaryToken = token;
      const el = document.createElement('span');
      el.setAttribute('aria-hidden', 'true');
      el.setAttribute('data-sgr-canary', '');
      el.style.cssText = 'position:absolute;left:-9999px;top:0;font-size:1px;color:transparent;user-select:text;pointer-events:none;';
      el.textContent = `Internal reference ${token}. `;
      document.body.appendChild(el);
      state.canaryEl = el;
      send({ type: 'canary', token, url: location.href });
    }

    // ------------------------------------------------ field shield
    const SENSITIVE_FIELD_RE = /iban|account|acct|routing|swift|bic|sort.?code|ssn|social|card|pan|tax.?id|tin/i;

    function shieldTextNode(node) {
      if (!node.nodeValue || node.parentElement === null) return;
      const parent = node.parentElement;
      if (parent.closest('[data-sgr-canary],[data-sgr-ui],script,style,textarea,input')) return;
      if (state.originals.has(node)) return;
      const hits = SGR.findSensitive(node.nodeValue);
      if (!hits.length) return;
      state.originals.set(node, node.nodeValue);
      node.nodeValue = SGR.redact(node.nodeValue);
      parent.setAttribute('data-sgr-shield', hits.map(h => h.id).join(','));
      parent.setAttribute('title', 'Masked by Safeguradrail. Click to reveal for ' + app.shield.revealSeconds + 's.');
    }

    function shieldInput(input) {
      if (input.hasAttribute('data-sgr-shield-input') || input.closest('[data-sgr-ui]')) return;
      const type = (input.type || 'text').toLowerCase();
      if (!['text', 'search', 'tel', 'number', ''].includes(type)) return;
      const hint = [input.name, input.id, input.placeholder, input.getAttribute('autocomplete'), input.getAttribute('aria-label')].join(' ');
      if (SENSITIVE_FIELD_RE.test(hint) || SGR.findSensitive(input.value).length) {
        input.setAttribute('data-sgr-shield-input', '');
        input.setAttribute('autocomplete', 'off');
      }
    }

    function shieldWithin(root) {
      if (!app.shield || app.shield.selectors.length === 0) return;
      const targets = new Set();
      for (const sel of app.shield.selectors) {
        try { root.querySelectorAll(sel).forEach(el => targets.add(el)); if (root.matches && root.matches(sel)) targets.add(root); } catch (e) { /* bad selector */ }
      }
      for (const el of targets) {
        if (el.tagName === 'INPUT') { if (app.shield.maskInputs) shieldInput(el); continue; }
        const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
        const nodes = []; let n; while ((n = walker.nextNode())) nodes.push(n);
        nodes.forEach(shieldTextNode);
        if (app.shield.maskInputs) el.querySelectorAll('input').forEach(shieldInput);
      }
    }

    document.addEventListener('click', e => {
      if (!e.isTrusted) return;
      const el = e.target.closest && e.target.closest('[data-sgr-shield]');
      if (!el || el.hasAttribute('data-sgr-revealed')) return;
      reveal(el);
    }, true);
    document.addEventListener('focusin', e => {
      const el = e.target;
      if (!(el instanceof HTMLInputElement) || !el.hasAttribute('data-sgr-shield-input')) return;
      if (state.lastTrusted && Date.now() - state.lastTrusted < 1500) el.setAttribute('data-sgr-revealed', '');
    }, true);
    document.addEventListener('focusout', e => { if (e.target instanceof HTMLInputElement) e.target.removeAttribute('data-sgr-revealed'); }, true);

    function reveal(el) {
      el.setAttribute('data-sgr-revealed', '');
      const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
      const restored = []; let n;
      while ((n = walker.nextNode())) { if (state.originals.has(n)) { restored.push([n, n.nodeValue]); state.revealing = true; n.nodeValue = state.originals.get(n); } }
      report('SR-V01', `Shielded ${el.getAttribute('data-sgr-shield')} value revealed by a person for ${app.shield.revealSeconds}s`);
      setTimeout(() => {
        for (const [node, masked] of restored) node.nodeValue = masked;
        el.removeAttribute('data-sgr-revealed');
        state.revealing = false;
      }, app.shield.revealSeconds * 1000);
    }

    // ------------------------------------------------ injection scan
    function isHidden(el) {
      const cs = getComputedStyle(el);
      if (cs.display === 'none' || cs.visibility === 'hidden') return 'display:none/visibility:hidden';
      if (parseFloat(cs.fontSize) < 4) return 'font-size ' + cs.fontSize;
      if (parseFloat(cs.opacity) < 0.1) return 'opacity ' + cs.opacity;
      const m = cs.color.match(/rgba?\(([^)]+)\)/);
      if (m) { const parts = m[1].split(',').map(s => parseFloat(s)); if (parts.length === 4 && parts[3] < 0.1) return 'transparent text'; }
      const bg = backgroundOf(el);
      if (bg && cs.color.replace(/\s/g, '') === bg.replace(/\s/g, '')) return 'text colour equals background';
      const r = el.getBoundingClientRect();
      if (r.width > 0 && (r.right < 0 || r.bottom < 0)) return 'positioned off-screen';
      if (cs.clipPath !== 'none' && cs.clipPath.includes('0px')) return 'clipped';
      return null;
    }
    function backgroundOf(el) {
      let p = el.parentElement;
      while (p) { const b = getComputedStyle(p).backgroundColor; if (b && b !== 'rgba(0, 0, 0, 0)' && b !== 'transparent') return b; p = p.parentElement; }
      return 'rgb(255, 255, 255)';
    }

    function scanUntrusted(root) {
      const sels = (app.untrustedContent && app.untrustedContent.selectors) || [];
      const targets = new Set();
      for (const sel of sels) { try { root.querySelectorAll(sel).forEach(el => targets.add(el)); if (root.matches && root.matches(sel)) targets.add(root); } catch (e) { /* ignore */ } }
      for (const el of targets) {
        if (el.hasAttribute('data-sgr-scanned') || el.closest('[data-sgr-ui]')) continue;
        el.setAttribute('data-sgr-scanned', '');
        const findings = [];
        // hidden descendants carrying text
        el.querySelectorAll('*').forEach(child => {
          const txt = (child.textContent || '').trim();
          if (txt.length < 12 || child.children.length) return;
          const why = isHidden(child);
          if (why) findings.push({ code: 'SR-I02', why, node: child, text: txt });
        });
        const visibleText = el.innerText || el.textContent || '';
        const inj = SGR.findInjection(el.textContent || '');
        if (inj.length) findings.push({ code: 'SR-I01', why: inj.map(h => h.label).join(', '), node: null, text: inj.map(h => h.sample).join(' | ') });
        const zw = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]{2,}/.test(el.textContent || '');
        if (findings.length) {
          el.setAttribute('data-sgr-quarantine', '');
          for (const f of findings) {
            if (f.node) {
              // Neutralise: make the hidden text visible and inert so an AI reading the DOM sees the warning, not the instruction.
              f.node.textContent = '[hidden text neutralised by Safeguradrail: "' + f.text.slice(0, 80) + '…"]';
              f.node.className = 'sgr-neutralised';
              f.node.removeAttribute('style');
            }
            report(f.code, `${f.code === 'SR-I02' ? 'Hidden text (' + f.why + ')' : 'AI-directed phrasing (' + f.why + ')'} in ${describe(el)}: "${f.text.slice(0, 160)}"`,
              { data: { visibleSample: visibleText.slice(0, 120), zeroWidth: zw } });
          }
          if (zw) el.textContent = (el.textContent || '').replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g, '');
          ui.toast('warn', 'Untrusted content contained AI-directed instructions and was neutralised.');
        }
      }
    }

    function describe(el) {
      const id = el.id ? '#' + el.id : '';
      const cls = el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\s+/).slice(0, 2).join('.') : '';
      const label = el.getAttribute('data-label') || el.getAttribute('aria-label') || '';
      return el.tagName.toLowerCase() + id + cls + (label ? ' (' + label + ')' : '');
    }

    // ------------------------------------------------ action rail
    function matchAction(e) {
      const target = e.target instanceof Element ? e.target : null;
      if (!target) return null;
      for (const a of app.actions) {
        if ((a.event || 'click') !== e.type) continue;
        try { if (target.closest(a.selector)) return { action: a, el: target.closest(a.selector) }; } catch (err) { /* bad selector */ }
      }
      return null;
    }

    function collectContext(action, el) {
      const ctx = {};
      const scope = el.closest('tr, li, form, article, section, [data-record]') || document;
      for (const [k, sel] of Object.entries(action.context || {})) {
        try {
          const node = scope.querySelector(sel) || document.querySelector(sel);
          if (!node) continue;
          const v = node instanceof HTMLInputElement || node instanceof HTMLSelectElement || node instanceof HTMLTextAreaElement ? node.value : (state.originals.get(node.firstChild) || node.textContent);
          ctx[k] = SGR.redact(String(v || '').trim()).slice(0, 120);
        } catch (err) { /* ignore */ }
      }
      return ctx;
    }

    function syntheticCode(action) {
      if (action.syntheticCode) return action.syntheticCode;
      const id = action.id.toLowerCase();
      if (/export|download|report/.test(id)) return 'SR-X04';
      if (/bank|iban|payee|beneficiary|vendor/.test(id)) return 'SR-A02';
      if (/limit|role|permission|threshold|config/.test(id)) return 'SR-A06';
      if (/dismiss|warning|consent|confirm/.test(id)) return 'SR-A05';
      return 'SR-A01';
    }

    function halt(e) { e.stopImmediatePropagation(); e.stopPropagation(); e.preventDefault(); }

    function onGate(e) {
      const hit = matchAction(e);
      if (!hit) return;
      const { action, el } = hit;
      const key = action.id + '|' + e.type;
      if (state.bypass.has(key)) { state.bypass.delete(key); return; }
      const prov = provenance();
      prov.isTrusted = e.isTrusted;
      const ctx = collectContext(action, el);
      const ctxText = Object.entries(ctx).map(([k, v]) => `${k}=${v}`).join(', ');
      state.actions.push(Date.now());

      if (!e.isTrusted) {
        halt(e);
        report(syntheticCode(action), `Untrusted ${e.type} on ${action.label || action.id} blocked (${ctxText})`, { provenance: prov, data: ctx });
        ui.toast('block', `Blocked: "${action.label || action.id}" was triggered by a script, not a person.`);
        return;
      }
      if (prov.velocity > rail.maxActionsPerMinute) {
        halt(e);
        report('SR-A03', `${prov.velocity} gated actions in the last minute (limit ${rail.maxActionsPerMinute}); ${action.label || action.id} blocked`, { provenance: prov, data: ctx });
        ui.toast('block', 'Blocked: too many high-risk actions per minute for a human operator.');
        return;
      }
      const lowPresence = prov.presence < rail.minPointerSamples && prov.keys === 0;
      if (lowPresence && action.control !== 'observe' && action.control !== 'deny-synthetic') {
        halt(e);
        report('SR-A08', `Trusted ${e.type} on ${action.label || action.id} with ${prov.presence} pointer samples and ${prov.keys} keys in ${rail.presenceWindowMs}ms; held (${ctxText})`, { provenance: prov, data: ctx });
        ui.toast('block', 'Held: no human presence signals before this action. Move the mouse and try again.');
        return;
      }
      if (lowPresence) report('SR-A08', `Trusted ${e.type} on ${action.label || action.id} with no presence signals (allowed by control level)`, { provenance: prov, data: ctx });

      if (action.control === 'observe' || action.control === 'deny-synthetic') {
        report('SR-C02', `Human ${e.type} on ${action.label || action.id} recorded with provenance (${ctxText})`, { provenance: prov, data: ctx, severity: 'info' });
        return;
      }
      halt(e);
      const proceed = () => { state.bypass.add(key); redispatch(e, el); };
      if (action.control === 'step-up') ui.stepUp(action, ctx, proceed, () => report('SR-A07', `Step-up for ${action.label || action.id} abandoned (${ctxText})`, { provenance: prov, data: ctx, severity: 'low' }));
      else if (action.control === 'dual-control') dualControl(action, ctx, prov, proceed);
    }

    function redispatch(e, el) {
      if (e.type === 'submit') { const f = el.tagName === 'FORM' ? el : el.closest('form'); if (f) f.requestSubmit(); return; }
      el.click();
    }

    async function dualControl(action, ctx, prov, proceed) {
      const res = await send({ type: 'approval:request', payload: { app: app.id, actionId: action.id, label: action.label, context: ctx, provenance: prov } });
      if (!res || res.error || !res.id) { ui.toast('block', 'Held: approval service unreachable (' + (res && res.error || 'no response') + ').'); return; }
      report('SR-C02', `Dual-control approval ${res.id} requested for ${action.label || action.id}`, { provenance: prov, data: ctx, severity: 'info' });
      const overlay = ui.hold(action, ctx, res.id);
      const started = Date.now();
      const timer = setInterval(async () => {
        const st = await send({ type: 'approval:poll', id: res.id });
        if (!st || st.error) return;
        if (st.status === 'approved') { clearInterval(timer); overlay.close(); ui.toast('ok', `Approved by ${st.approver}. Proceeding.`); proceed(); }
        else if (st.status === 'denied' || st.status === 'expired') { clearInterval(timer); overlay.close(); ui.toast('block', `${st.status === 'denied' ? 'Denied' : 'Expired'}${st.note ? ': ' + st.note : ''}.`); }
        else if (Date.now() - started > rail.approvalTimeoutSeconds * 1000) { clearInterval(timer); overlay.close(); ui.toast('block', 'Approval timed out.'); }
      }, 2000);
      overlay.onCancel(() => { clearInterval(timer); });
    }

    document.addEventListener('click', onGate, true);
    document.addEventListener('submit', onGate, true);

    // Machine-speed or programmatic value changes in payment-critical fields.
    document.addEventListener('input', e => {
      const el = e.target;
      if (!(el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement)) return;
      const critical = app.actions.some(a => Object.values(a.context || {}).some(sel => { try { return el.matches(sel); } catch (err) { return false; } }));
      if (!critical) return;
      const key = el.name || el.id || describe(el);
      if (!e.isTrusted && !state.reportedFields.has(key)) {
        state.reportedFields.add(key);
        report('SR-A07', `Field "${key}" changed by script (untrusted input event), value ${SGR.redact(el.value).slice(0, 60)}`, { data: { field: key } });
        ui.toast('warn', `Field "${key}" was filled by a script. Re-check it before submitting.`);
      }
    }, true);

    // ------------------------------------------------ clipboard guard
    document.addEventListener('copy', e => {
      const text = String(window.getSelection && window.getSelection());
      const hits = SGR.findSensitive(text);
      if (!hits.length) return;
      const mode = policy.clipboard.mode;
      if (mode === 'redact' && e.clipboardData) { e.preventDefault(); e.clipboardData.setData('text/plain', SGR.redact(text)); }
      report('SR-X03', `${hits.map(h => h.label).join(', ')} copied to clipboard (${mode === 'redact' ? 'redacted' : 'allowed'})`, { data: { types: hits.map(h => h.id).join(',') } });
      if (mode === 'redact') ui.toast('warn', 'Copied text contained bank or ID numbers; they were masked on the clipboard.');
    }, true);
    document.addEventListener('paste', e => {
      const el = e.target;
      if (!(el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement)) return;
      const text = e.clipboardData ? e.clipboardData.getData('text/plain') : '';
      const inj = SGR.findInjection(text);
      const sens = SGR.findSensitive(text);
      if (inj.length || (sens.length && SENSITIVE_FIELD_RE.test(el.name + ' ' + el.id))) {
        report('SR-I04', `Paste into "${el.name || el.id}": ${inj.map(h => h.label).concat(sens.map(s => s.label)).join(', ')}`, { data: { length: text.length } });
        if (inj.length) ui.toast('warn', 'Pasted text looks like instructions for an AI, not data. Check the source.');
      }
    }, true);

    // ------------------------------------------------ tamper watch
    function snapshotCritical() {
      const sels = new Set();
      for (const a of app.actions) for (const s of Object.values(a.context || {})) sels.add(s);
      sels.add('[data-field]');
      for (const s of sels) { try { document.querySelectorAll(s).forEach(el => { if (!(el instanceof HTMLInputElement)) state.snapshots.set(el, el.textContent); }); } catch (e) { /* ignore */ } }
    }

    const observer = new MutationObserver(muts => {
      let needsShield = false;
      for (const m of muts) {
        if (m.type === 'childList') {
          for (const n of m.removedNodes) if (n === state.canaryEl) { document.body.appendChild(state.canaryEl); report('SR-I05', 'Canary marker removed from DOM by page script; re-inserted'); }
          if (m.addedNodes.length) needsShield = true;
        }
        if (m.type === 'characterData') {
          const node = m.target;
          if (state.originals.has(node) && !state.revealing) {
            const raw = SGR.findSensitive(node.nodeValue);
            if (raw.length) { node.nodeValue = SGR.redact(node.nodeValue); report('SR-I05', `Shielded ${raw[0].label} was unmasked by script; re-masked`); }
          }
          const host = node.parentElement && node.parentElement.closest('[data-field]');
          if (host && state.snapshots.has(host) && Date.now() - state.lastTrusted > 1500) {
            const before = state.snapshots.get(host), after = host.textContent;
            if (before !== after) { report('SR-I03', `Displayed value "${host.getAttribute('data-field')}" changed with no user interaction: "${before.trim().slice(0, 40)}" -> "${after.trim().slice(0, 40)}"`); ui.toast('block', 'A displayed financial value changed without you touching it. Reload before acting.'); }
            state.snapshots.set(host, after);
          }
        }
      }
      if (needsShield) schedulePass();
    });

    let passTimer = null;
    function schedulePass() { clearTimeout(passTimer); passTimer = setTimeout(pass, 80); }
    function pass() { shieldWithin(document.body); scanUntrusted(document.body); snapshotCritical(); }

    pass();
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    window.addEventListener('hashchange', schedulePass);
    ui.toast('ok', `Safeguradrail active on ${app.name}`, 2500);

    // ------------------------------------------------ UI (closed shadow root so page scripts cannot restyle it)
    function makeUI() {
      const host = document.createElement('div');
      host.setAttribute('data-sgr-ui', '');
      host.style.cssText = 'all:initial;position:fixed;inset:0;pointer-events:none;z-index:2147483647;';
      const root = host.attachShadow({ mode: 'closed' });
      root.innerHTML = `<style>
        .toasts{position:fixed;right:16px;bottom:16px;display:flex;flex-direction:column;gap:8px;font:13px/1.4 system-ui,sans-serif;pointer-events:none}
        .toast{background:#1c2430;color:#fff;padding:10px 14px;border-radius:8px;max-width:360px;box-shadow:0 6px 24px rgba(0,0,0,.25);border-left:4px solid #6fc3b0}
        .toast.block{border-left-color:#b3121b}.toast.warn{border-left-color:#d9541e}.toast.ok{border-left-color:#1f8a4c}
        .toast b{display:block;font-size:11px;letter-spacing:.06em;text-transform:uppercase;opacity:.7;margin-bottom:2px}
        .veil{position:fixed;inset:0;background:rgba(20,28,40,.55);display:flex;align-items:center;justify-content:center;pointer-events:auto;font:14px/1.45 system-ui,sans-serif}
        .box{background:#fff;color:#1c2430;border-radius:12px;padding:22px 24px;width:min(460px,92vw);box-shadow:0 20px 60px rgba(0,0,0,.35)}
        .box h1{font-size:16px;margin:0 0 6px}.box p{margin:6px 0;color:#5f6b7a}
        .ctx{background:#f4f6f8;border-radius:8px;padding:8px 10px;font-family:ui-monospace,monospace;font-size:12px;margin:10px 0}
        .ctx div{display:flex;justify-content:space-between;gap:12px}.ctx span:first-child{color:#5f6b7a}
        .code{font-family:ui-monospace,monospace;font-size:22px;letter-spacing:.3em;text-align:center;margin:10px 0;color:#0f6b5c}
        input{width:100%;font:inherit;padding:8px 10px;border:1px solid #dfe4ea;border-radius:6px;box-sizing:border-box;letter-spacing:.2em;text-transform:uppercase}
        .row{display:flex;gap:8px;justify-content:flex-end;margin-top:14px}
        button{font:inherit;padding:8px 14px;border-radius:6px;border:1px solid #dfe4ea;background:#fff;cursor:pointer}
        button.primary{background:#0f6b5c;color:#fff;border-color:#0f6b5c}button:disabled{opacity:.5;cursor:default}
        .spin{display:inline-block;width:12px;height:12px;border:2px solid #dfe4ea;border-top-color:#0f6b5c;border-radius:50%;animation:s 1s linear infinite;vertical-align:middle;margin-right:6px}
        @keyframes s{to{transform:rotate(360deg)}}
      </style><div class="toasts"></div>`;
      const toasts = root.querySelector('.toasts');
      (document.documentElement || document.body).appendChild(host);
      // Keep the UI host alive if a script removes it.
      new MutationObserver(() => { if (!host.isConnected) document.documentElement.appendChild(host); }).observe(document.documentElement, { childList: true });

      function toast(kind, text, ms) {
        const t = document.createElement('div');
        t.className = 'toast ' + kind;
        t.innerHTML = `<b>Safeguradrail</b>`;
        t.appendChild(document.createTextNode(text));
        toasts.appendChild(t);
        setTimeout(() => t.remove(), ms || 6000);
      }

      function ctxHtml(ctx) {
        return '<div class="ctx">' + Object.entries(ctx).map(([k, v]) => `<div><span>${esc(k)}</span><span>${esc(v)}</span></div>`).join('') + (Object.keys(ctx).length ? '' : '<div><span>no context captured</span></div>') + '</div>';
      }
      function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

      // Step-up: the person re-reads what is about to happen and types a short
      // code with trusted keystrokes. Synthetic input cannot satisfy it.
      function stepUp(action, ctx, onOk, onCancel) {
        const code = Array.from(crypto.getRandomValues(new Uint8Array(4))).map(b => 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'[b % 32]).join('');
        const veil = document.createElement('div'); veil.className = 'veil';
        veil.innerHTML = `<div class="box"><h1>Confirm: ${esc(action.label || action.id)}</h1>
          <p>Re-read the values below. They are what the system will execute, regardless of what any assistant told you.</p>${ctxHtml(ctx)}
          <p>Type this code to continue:</p><div class="code">${code}</div><input maxlength="4" autocomplete="off" spellcheck="false">
          <div class="row"><button class="cancel">Cancel</button><button class="primary" disabled>Confirm</button></div></div>`;
        root.appendChild(veil);
        const input = veil.querySelector('input'), ok = veil.querySelector('.primary');
        let trustedKeys = 0;
        input.addEventListener('keydown', e => { if (e.isTrusted) trustedKeys++; });
        input.addEventListener('input', e => { if (!e.isTrusted) input.value = ''; ok.disabled = !(input.value.toUpperCase() === code && trustedKeys >= 4); });
        ok.addEventListener('click', e => { if (!e.isTrusted) return; veil.remove(); onOk(); });
        veil.querySelector('.cancel').addEventListener('click', () => { veil.remove(); onCancel && onCancel(); });
        setTimeout(() => input.focus(), 50);
      }

      function hold(action, ctx, id) {
        const veil = document.createElement('div'); veil.className = 'veil';
        veil.innerHTML = `<div class="box"><h1><span class="spin"></span>Waiting for a second approver</h1>
          <p><b>${esc(action.label || action.id)}</b> is held under dual control. Request <code>${esc(id)}</code> was sent to the Safeguradrail console. This page cannot approve it.</p>${ctxHtml(ctx)}
          <div class="row"><button class="cancel">Cancel request</button></div></div>`;
        root.appendChild(veil);
        let cancelCb = null;
        veil.querySelector('.cancel').addEventListener('click', () => { veil.remove(); cancelCb && cancelCb(); });
        return { close: () => veil.remove(), onCancel: cb => { cancelCb = cb; } };
      }

      return { toast, stepUp, hold };
    }
  }
})();
