/*
 * Safeguradrail shared detection library.
 * Loaded as a plain script by the Sentinel extension (content script and
 * service worker) and required as a CommonJS module by the control plane
 * and the test suite. Keep it dependency-free and side-effect-free.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.SGR = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const CANARY_PREFIX = 'SGR-CANARY-';
  const CANARY_RE = /SGR-CANARY-[0-9a-f]{12}/g;

  function luhn(digits) {
    if (!/^\d{13,19}$/.test(digits)) return false;
    let sum = 0, dbl = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = digits.charCodeAt(i) - 48;
      if (dbl) { d *= 2; if (d > 9) d -= 9; }
      sum += d; dbl = !dbl;
    }
    return sum % 10 === 0;
  }

  // Sensitive data classes found in finance tools. Each detector captures the
  // value in group 1 so masking can preserve the surrounding label text.
  const SENSITIVE = [
    {
      id: 'iban', label: 'IBAN',
      re: /\b([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?)\b/g,
      validate: v => { const c = v.replace(/\s/g, ''); return c.length >= 15 && c.length <= 34 && /\d/.test(c.slice(4)); }
    },
    {
      id: 'card', label: 'Card number',
      re: /\b((?:\d[ -]?){13,19})\b/g,
      validate: v => luhn(v.replace(/[ -]/g, ''))
    },
    {
      id: 'ssn', label: 'Social security number',
      re: /\b((?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4})\b/g
    },
    {
      id: 'swift', label: 'SWIFT/BIC',
      re: /\b(?:swift|bic)\b[^A-Z0-9]{0,12}([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b/gi
    },
    {
      id: 'routing', label: 'Routing number',
      re: /\b(?:routing|aba|rtn|sort code)\b[^0-9]{0,20}(\d{6,9})\b/gi
    },
    {
      id: 'account', label: 'Account number',
      re: /\b(?:acct|account|a\/c)(?:\s*(?:no|number|num|#))?\.?\s*[:#]?\s*(\d{6,17})\b/gi
    }
  ];

  // Text that is trying to talk to an AI rather than to a human. Found inside
  // untrusted content rendered by finance tools: vendor memos, invoice notes,
  // remittance emails, attachment previews.
  const INJECTION = [
    { id: 'override', label: 'Instruction override', re: /\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any)\b[^.\n]{0,20}\b(instructions?|rules?|prompts?|guidance)\b/i },
    { id: 'role', label: 'Role assignment', re: /\b(you are|act as|pretend to be|behave as)\b[^.\n]{0,30}\b(an? )?(ai|assistant|agent|bot|model|llm|copilot)\b/i },
    { id: 'ai-address', label: 'Addressed to an AI', re: /\b(ai assistant|ai agent|language model|chatbot|copilot|assistant|agent|model)\b[^.\n]{0,40}\b(must|should|needs? to|please|will now|is required to)\b/i },
    { id: 'payment-redirect', label: 'Payment redirection', re: /\b(update|change|replace|use|send|redirect|remit|switch)\b[^.\n]{0,60}\b(new |updated |following |this |our )?(bank|beneficiary|payee|account|routing|iban|swift|bic)\b/i },
    { id: 'secrecy', label: 'Secrecy request', re: /\b(do not|don't|never|without)\b[^.\n]{0,30}\b(tell|inform|alert|notify|mention|show|flag)\b[^.\n]{0,30}\b(user|human|anyone|approver|finance|team|manager)\b/i },
    { id: 'urgency', label: 'Urgent payment pressure', re: /\b(urgent(ly)?|immediately|right away|asap|today)\b[^.\n]{0,40}\b(wire|transfer|pay|release|approve|remit)\b/i },
    { id: 'markup', label: 'Model control tokens', re: /(<\|im_start\|>|<\|system\|>|\[INST\]|\[\/INST\]|<<SYS>>|###\s*(system|instruction)|^\s*(system|assistant)\s*:)/im },
    { id: 'zero-width', label: 'Zero-width / bidi characters', re: /[\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2064\uFEFF]{2,}/ }
  ];

  const DEFAULT_AI_ENDPOINTS = [
    'api.openai.com', 'chatgpt.com', 'chat.openai.com', 'api.anthropic.com', 'claude.ai',
    'generativelanguage.googleapis.com', 'gemini.google.com', 'aiplatform.googleapis.com',
    'api.cohere.ai', 'api.cohere.com', 'api.mistral.ai', 'openrouter.ai', 'api.perplexity.ai',
    'copilot.microsoft.com', 'api.groq.com', 'api.together.xyz', 'api-inference.huggingface.co',
    'api.x.ai', 'api.deepseek.com', 'api.fireworks.ai', 'api.replicate.com', 'api.writer.com',
    'api.jasper.ai', 'app.grammarly.com', 'api.monica.im', 'api.sider.ai'
  ];

  const AI_KEYWORDS = ['ai', 'gpt', 'chatgpt', 'openai', 'claude', 'gemini', 'copilot', 'assistant',
    'llm', 'summar', 'autofill', 'auto-fill', 'agent', 'writer', 'compose', 'rewrite', 'translate',
    'sidekick', 'sidebar', 'chat', 'bot', 'genai', 'prompt', 'monica', 'sider', 'merlin', 'harpa',
    'jasper', 'grammarly', 'perplexity', 'bard', 'mistral', 'llama'];

  const RISKY_PERMISSIONS = {
    '<all_urls>': 25, '*://*/*': 25, 'http://*/*': 15, 'https://*/*': 15,
    tabs: 8, scripting: 12, activeTab: 4, webRequest: 8, webRequestBlocking: 10,
    clipboardRead: 12, clipboardWrite: 4, debugger: 30, cookies: 12, downloads: 8,
    history: 6, management: 6, nativeMessaging: 10, desktopCapture: 20, tabCapture: 20,
    declarativeNetRequest: 6, webNavigation: 4, storage: 0, alarms: 0, notifications: 0
  };

  function findMatches(text, detectors) {
    const out = [];
    if (!text) return out;
    for (const d of detectors) {
      d.re.lastIndex = 0;
      let m;
      while ((m = d.re.exec(text)) !== null) {
        const value = m[1] !== undefined ? m[1] : m[0];
        if (d.validate && !d.validate(value)) { if (!d.re.global) break; continue; }
        const offset = m[1] !== undefined ? m.index + m[0].indexOf(m[1]) : m.index;
        out.push({ id: d.id, label: d.label, value, index: offset, length: value.length });
        if (!d.re.global) break;
      }
    }
    return out.sort((a, b) => a.index - b.index);
  }

  function findSensitive(text) { return findMatches(text, SENSITIVE); }

  function findInjection(text) {
    const hits = [];
    if (!text) return hits;
    for (const d of INJECTION) {
      d.re.lastIndex = 0;
      const m = d.re.exec(text);
      if (m) hits.push({ id: d.id, label: d.label, sample: m[0].slice(0, 120), index: m.index });
    }
    return hits;
  }

  function mask(value, keep) {
    const k = keep === undefined ? 4 : keep;
    const compact = String(value).replace(/\s/g, '');
    if (compact.length <= k) return '•'.repeat(compact.length);
    return '•'.repeat(Math.min(compact.length - k, 12)) + compact.slice(-k);
  }

  // Replace every sensitive value in a text with its masked form. Used for
  // event payloads so the control plane never stores raw financial identifiers.
  function redact(text) {
    if (!text) return text;
    const hits = findSensitive(text);
    if (!hits.length) return text;
    let out = '', cursor = 0;
    for (const h of hits) {
      if (h.index < cursor) continue;
      out += text.slice(cursor, h.index) + mask(h.value);
      cursor = h.index + h.length;
    }
    return out + text.slice(cursor);
  }

  function findCanaries(text) {
    if (!text) return [];
    CANARY_RE.lastIndex = 0;
    return Array.from(new Set(text.match(CANARY_RE) || []));
  }

  function hostMatches(host, list) {
    if (!host) return false;
    host = host.toLowerCase();
    return (list || []).some(h => host === h || host.endsWith('.' + h));
  }

  function hostOf(url) {
    try { return new URL(url).hostname.toLowerCase(); } catch (e) { return ''; }
  }

  function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  // Classify an installed extension (chrome.management.ExtensionInfo shape).
  function classifyExtension(info, opts) {
    opts = opts || {};
    const keywords = opts.aiKeywords || AI_KEYWORDS;
    const sanctioned = new Set(opts.sanctionedExtensions || []);
    const reasons = [];
    let aiScore = 0, capScore = 0;
    const hay = ((info.name || '') + ' ' + (info.description || '') + ' ' + (info.shortName || '')).toLowerCase();
    for (const k of keywords) {
      const re = new RegExp('(^|[^a-z])' + escapeRe(k) + '([^a-z]|$)');
      if (re.test(hay)) { aiScore += k.length <= 3 ? 10 : 15; reasons.push('name/description mentions "' + k + '"'); }
    }
    const perms = [].concat(info.permissions || [], info.hostPermissions || []);
    for (const p of perms) {
      const w = RISKY_PERMISSIONS[p];
      if (w) { capScore += w; if (w >= 10) reasons.push('permission ' + p); }
    }
    if (info.installType === 'development' || info.installType === 'sideload') {
      capScore += 15; reasons.push('sideloaded / developer-mode install');
    }
    const isAI = aiScore >= 15;
    const broad = perms.some(p => /all_urls|:\/\/\*/.test(p));
    const capabilities = {
      readPages: broad || perms.includes('scripting') || perms.includes('activeTab'),
      network: true,
      synthesizeInput: broad || perms.includes('scripting') || perms.includes('debugger'),
      trustedInput: perms.includes('debugger'),
      screenshot: perms.includes('activeTab') || perms.includes('tabs') || perms.includes('desktopCapture') || perms.includes('tabCapture'),
      clipboard: perms.includes('clipboardRead'),
      session: perms.includes('cookies'),
      files: perms.includes('downloads')
    };
    let category = 'other';
    if (sanctioned.has(info.id)) category = 'sanctioned-ai';
    else if (isAI && capabilities.trustedInput) category = 'unsanctioned-ai-agent';
    else if (isAI) category = 'unsanctioned-ai';
    else if (capScore >= 40) category = 'high-capability';
    const risk = Math.min(100, aiScore + capScore + (category.startsWith('unsanctioned') ? 20 : 0));
    return { id: info.id, name: info.name, version: info.version, enabled: info.enabled !== false,
      installType: info.installType, category, isAI, risk, capabilities, reasons, permissions: perms };
  }

  return {
    CANARY_PREFIX, CANARY_RE, SENSITIVE, INJECTION, DEFAULT_AI_ENDPOINTS, AI_KEYWORDS, RISKY_PERMISSIONS,
    luhn, findSensitive, findInjection, findCanaries, mask, redact, hostMatches, hostOf, classifyExtension
  };
});
