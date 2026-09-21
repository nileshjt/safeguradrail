'use strict';
/*
 * Safeguradrail risk model.
 *
 * Risk is modelled as permutations over five dimensions:
 *   actor      - what kind of AI extension is involved
 *   capability - what the extension can technically do in the browser
 *   asset      - which class of finance data is exposed
 *   operation  - what is being done to the finance tool
 *   vector     - how the harmful behaviour is triggered
 *
 * Each taxonomy code (SR-*) is one concrete, detectable permutation. The
 * Sentinel extension emits events tagged with a code; this module validates
 * the code, assigns severity, and evaluates chains of events per device to
 * find multi-step attacks that no single event reveals.
 */

const DIMENSIONS = {
  actor: {
    A1: 'Sanctioned enterprise AI assistant',
    A2: 'Unsanctioned consumer AI assistant (sidebar / summariser)',
    A3: 'Autonomous browser agent that acts on the user\'s behalf',
    A4: 'Malicious or hijacked extension posing as an AI tool',
    A5: 'Non-AI extension with AI feature creep (grammar, translate, screenshot)'
  },
  capability: {
    C1: 'Read page DOM / text',
    C2: 'Capture screenshots of the visible tab',
    C3: 'Send data to third-party endpoints',
    C4: 'Synthesise input events (click, type, submit)',
    C5: 'Modify what the page displays',
    C6: 'Read the clipboard',
    C7: 'Read cookies, storage, session tokens',
    C8: 'Drive the tab through the debugger protocol (trusted events)',
    C9: 'Read downloaded files (exports, statements)'
  },
  asset: {
    D1: 'Bank account, routing, IBAN, SWIFT',
    D2: 'Card numbers',
    D3: 'Payroll and employee PII',
    D4: 'Unreleased financial results (material non-public information)',
    D5: 'Credentials, session tokens, MFA codes',
    D6: 'Vendor master data',
    D7: 'Ledger and journal entries',
    D8: 'Approval workflows and authority limits'
  },
  operation: {
    O1: 'View', O2: 'Export / bulk read', O3: 'Create', O4: 'Modify',
    O5: 'Approve / release funds', O6: 'Delete / void', O7: 'Change configuration'
  },
  vector: {
    V1: 'Direct user request to the AI',
    V2: 'Indirect prompt injection via content rendered in the finance tool',
    V3: 'Hallucination or misread by a well-intentioned AI',
    V4: 'Background scraping without any user request',
    V5: 'Autonomous multi-step task overreach',
    V6: 'Malicious update, ownership transfer, or backdoor'
  }
};

const SEVERITY_WEIGHT = { info: 0, low: 8, medium: 20, high: 40, critical: 65 };

// One entry per detectable permutation. `detects` names the Sentinel control.
const TAXONOMY = {
  // ---- Exfiltration ------------------------------------------------------
  'SR-X01': { family: 'Exfiltration', severity: 'high', detects: 'Egress Watch + Canary',
    title: 'Finance page content sent to an AI endpoint',
    dims: ['A2', 'C1', 'C3', 'D1', 'D6', 'D7', 'O1', 'V1', 'V4'],
    desc: 'A browser extension read a protected finance page and posted its content to a third-party AI API. Proven when a page canary token appears in the request body.' },
  'SR-X02': { family: 'Exfiltration', severity: 'high', detects: 'Field Shield (mitigation only)',
    title: 'Screenshot of a finance view captured by an extension',
    dims: ['A2', 'A5', 'C2', 'C3', 'D1', 'D4', 'O1', 'V1', 'V4'],
    desc: 'Screenshot capture by other extensions cannot be intercepted from inside the page. Field Shield keeps sensitive values masked so a capture leaks masked values only.' },
  'SR-X03': { family: 'Exfiltration', severity: 'medium', detects: 'Clipboard Guard',
    title: 'Sensitive value copied to the clipboard',
    dims: ['A2', 'C6', 'D1', 'D2', 'D3', 'O1', 'V1'],
    desc: 'An account, card, or ID number was copied where a clipboard-reading extension could harvest it. Policy may redact the copy.' },
  'SR-X04': { family: 'Exfiltration', severity: 'high', detects: 'Action Rail',
    title: 'Bulk export triggered by synthetic input',
    dims: ['A3', 'C4', 'C9', 'D7', 'D3', 'O2', 'V1', 'V5'],
    desc: 'An export or download of ledger, payroll, or vendor data was triggered by a script rather than a person.' },
  'SR-X05': { family: 'Exfiltration', severity: 'medium', detects: 'Egress Watch',
    title: 'Finance content bundled into an unknown third-party request',
    dims: ['A4', 'A5', 'C1', 'C3', 'D1', 'D7', 'O1', 'V4', 'V6'],
    desc: 'A canary or sensitive value left the browser toward a host that is not a known AI endpoint. Typical of telemetry, "context sync", or a backdoored update.' },
  'SR-X06': { family: 'Exfiltration', severity: 'critical', detects: 'Census (posture)',
    title: 'Extension with cookie or session access present on finance origin',
    dims: ['A4', 'C7', 'D5', 'O1', 'V6'],
    desc: 'An extension holding cookies or debugger permission can lift session tokens for the finance tool and replay them outside the browser.' },
  'SR-X07': { family: 'Exfiltration', severity: 'high', detects: 'Field Shield',
    title: 'MFA or one-time code visible to page-reading extensions',
    dims: ['A2', 'C1', 'C2', 'D5', 'O1', 'V4'],
    desc: 'One-time codes rendered in the finance tool are readable by any extension with page access and can be relayed in real time.' },
  'SR-X08': { family: 'Exfiltration', severity: 'high', detects: 'Egress Watch + Canary',
    title: 'Background scraping with no user interaction',
    dims: ['A2', 'A4', 'C1', 'C3', 'D1', 'D7', 'O1', 'V4'],
    desc: 'Content left the page within seconds of load with no click or keypress. The AI tool is harvesting ambient context, not answering a request.' },

  // ---- Unauthorised action ---------------------------------------------
  'SR-A01': { family: 'Unauthorised action', severity: 'critical', detects: 'Action Rail',
    title: 'Synthetic click on a high-risk control',
    dims: ['A3', 'C4', 'D8', 'O5', 'V1', 'V5'],
    desc: 'A script-dispatched (untrusted) event tried to press approve, pay, release, or export.' },
  'SR-A02': { family: 'Unauthorised action', severity: 'critical', detects: 'Action Rail + Injection Scan',
    title: 'Vendor bank details changed by an agent',
    dims: ['A3', 'C4', 'D1', 'D6', 'O4', 'V2', 'V5'],
    desc: 'Beneficiary or bank details were submitted by non-human input. This is the payoff step of business email compromise adapted for AI agents.' },
  'SR-A03': { family: 'Unauthorised action', severity: 'high', detects: 'Action Rail (velocity)',
    title: 'Action velocity exceeds human rate',
    dims: ['A3', 'C4', 'D8', 'O5', 'O4', 'V5'],
    desc: 'More high-risk actions per minute than a person could plausibly perform. Indicates batch automation through the UI.' },
  'SR-A04': { family: 'Unauthorised action', severity: 'critical', detects: 'Dual Control',
    title: 'Segregation of duties collapsed by one agent',
    dims: ['A3', 'C4', 'D8', 'O3', 'O5', 'V5'],
    desc: 'The same automated actor created a record and approved it. Maker and checker must be distinct humans; the rail routes approval out of band.' },
  'SR-A05': { family: 'Unauthorised action', severity: 'medium', detects: 'Action Rail',
    title: 'Consent or warning dialog auto-dismissed',
    dims: ['A3', 'C4', 'D8', 'O7', 'V5'],
    desc: 'A confirmation dialog was dismissed by synthetic input, defeating the tool\'s own safeguard.' },
  'SR-A06': { family: 'Unauthorised action', severity: 'critical', detects: 'Action Rail',
    title: 'Authority limits or roles changed by an agent',
    dims: ['A3', 'A4', 'C4', 'D8', 'O7', 'V5', 'V6'],
    desc: 'Approval thresholds, user roles, or payment limits were modified without a verified human.' },
  'SR-A07': { family: 'Unauthorised action', severity: 'high', detects: 'Step-up confirmation',
    title: 'Amount or payee filled by AI with no human review',
    dims: ['A2', 'A3', 'C4', 'D1', 'D7', 'O3', 'O4', 'V3'],
    desc: 'Large values were pasted or typed at machine speed into amount or payee fields. Hallucinated figures reach the ledger unless a human re-reads them.' },
  'SR-A08': { family: 'Unauthorised action', severity: 'high', detects: 'Action Rail (presence)',
    title: 'Trusted-looking action with no human presence signals',
    dims: ['A3', 'C8', 'D8', 'O5', 'V5'],
    desc: 'Events carried the trusted flag but there was no pointer movement or typing cadence beforehand. Consistent with debugger-driven automation.' },

  // ---- Integrity / injection ---------------------------------------------
  'SR-I01': { family: 'Integrity', severity: 'high', detects: 'Injection Scan',
    title: 'AI-directed instructions found in untrusted finance content',
    dims: ['A2', 'A3', 'C1', 'D6', 'D1', 'O4', 'V2'],
    desc: 'A vendor memo, invoice note, or attachment contains text written for an AI, such as "ignore previous instructions" or "update the bank account to".' },
  'SR-I02': { family: 'Integrity', severity: 'high', detects: 'Injection Scan',
    title: 'Hidden text in finance content',
    dims: ['A2', 'A3', 'C1', 'D6', 'O4', 'V2'],
    desc: 'Text invisible to people (tiny font, transparent colour, off-screen, zero-width characters) but visible to page-reading AI.' },
  'SR-I03': { family: 'Integrity', severity: 'critical', detects: 'Tamper Watch',
    title: 'Displayed financial value altered in the DOM',
    dims: ['A4', 'C5', 'D7', 'D1', 'O1', 'V6'],
    desc: 'A balance, amount, or beneficiary shown to the user was rewritten after render, so the human approves something other than what the system will execute.' },
  'SR-I04': { family: 'Integrity', severity: 'medium', detects: 'Clipboard Guard',
    title: 'Instruction-like text pasted into a finance field',
    dims: ['A2', 'C4', 'C6', 'D6', 'O3', 'V2', 'V3'],
    desc: 'Pasted content carried injection markers or a bank identifier into a form field, likely relayed from an AI chat.' },
  'SR-I05': { family: 'Integrity', severity: 'critical', detects: 'Tamper Watch',
    title: 'Attempt to unmask shielded values or remove canaries',
    dims: ['A4', 'C5', 'D1', 'D3', 'O1', 'V6'],
    desc: 'Something in the page tried to strip Field Shield masks or delete the canary marker. Only a hostile script has reason to.' },

  // ---- Supply chain / posture -------------------------------------------
  'SR-S01': { family: 'Posture', severity: 'medium', detects: 'Census',
    title: 'Unsanctioned AI extension installed',
    dims: ['A2', 'C1', 'C3', 'D1', 'D7', 'O1', 'V1'],
    desc: 'An extension classified as AI-capable is present and not on the sanctioned list.' },
  'SR-S02': { family: 'Posture', severity: 'high', detects: 'Census',
    title: 'Extension gained risky permissions on update',
    dims: ['A4', 'C1', 'C7', 'C8', 'D5', 'O1', 'V6'],
    desc: 'A previously benign extension now requests broad host access, cookies, scripting, or debugger.' },
  'SR-S03': { family: 'Posture', severity: 'high', detects: 'Census',
    title: 'AI agent with debugger capability present',
    dims: ['A3', 'C8', 'D8', 'O5', 'V5'],
    desc: 'The debugger permission lets an extension produce fully trusted input, bypassing isTrusted checks. Requires the strongest rail controls.' },
  'SR-S04': { family: 'Posture', severity: 'medium', detects: 'Census',
    title: 'Sideloaded or developer-mode extension present',
    dims: ['A4', 'C1', 'C3', 'D7', 'O1', 'V6'],
    desc: 'Unpacked extensions bypass store review and can change silently.' },
  'SR-S05': { family: 'Posture', severity: 'critical', detects: 'Heartbeat + Tamper Watch',
    title: 'Sentinel disabled, stale, or degraded',
    dims: ['A4', 'C5', 'D8', 'O7', 'V6'],
    desc: 'The guardrail itself stopped reporting or lost enforcement capability on a device.' },

  // ---- Audit (informational) ---------------------------------------------
  'SR-V01': { family: 'Audit', severity: 'info', detects: 'Field Shield',
    title: 'Shielded value revealed by a person',
    dims: ['A1', 'C1', 'D1', 'D3', 'O1', 'V1'],
    desc: 'A person clicked to reveal a masked value. Recorded for audit; not a risk by itself.' },

  // ---- Compliance ---------------------------------------------------------
  'SR-C01': { family: 'Compliance', severity: 'medium', detects: 'Egress Watch',
    title: 'Regulated data routed to a jurisdiction outside policy',
    dims: ['A1', 'A2', 'C3', 'D3', 'D1', 'O1', 'V1'],
    desc: 'Even a sanctioned AI tool may process finance or payroll data in a region that GDPR, GLBA, or DPDP restrict.' },
  'SR-C02': { family: 'Compliance', severity: 'high', detects: 'Action Rail attribution',
    title: 'Agent action recorded as a human action',
    dims: ['A3', 'C4', 'D8', 'O5', 'V5'],
    desc: 'The finance tool\'s own audit log attributes AI-driven actions to the signed-in user. Sentinel records provenance so SOX-style audits can separate them.' },
  'SR-C03': { family: 'Compliance', severity: 'medium', detects: 'Egress Watch',
    title: 'Financial content retained in a third-party model log',
    dims: ['A2', 'C3', 'D4', 'D7', 'O1', 'V1'],
    desc: 'Consumer AI services retain prompts. Material non-public information sent before an earnings release creates disclosure and insider-trading exposure.' }
};

// Multi-event chains that raise a device to a higher risk level than any
// single event. `within` is milliseconds; `steps` are matched in order.
const CHAINS = [
  { id: 'CH-1', title: 'Scrape then act', level: 'critical', within: 10 * 60e3,
    steps: [['SR-X01', 'SR-X08'], ['SR-A01', 'SR-A02', 'SR-A06', 'SR-A08', 'SR-X04']],
    desc: 'Page content left to an AI, then an automated action hit a high-risk control. The model read the page and is now driving it.' },
  { id: 'CH-2', title: 'Injected payment redirection', level: 'critical', within: 30 * 60e3,
    steps: [['SR-I01', 'SR-I02'], ['SR-A02', 'SR-A07', 'SR-I04']],
    desc: 'Instructions planted in vendor content were followed by a bank-detail or amount change.' },
  { id: 'CH-3', title: 'Silent agent', level: 'high', within: 60 * 60e3,
    steps: [['SR-S01', 'SR-S03', 'SR-S04'], ['SR-A08', 'SR-A03']],
    desc: 'An unsanctioned AI extension is installed and actions are arriving without human presence signals.' },
  { id: 'CH-4', title: 'Bulk harvest', level: 'high', within: 5 * 60e3, repeat: 3,
    steps: [['SR-X01', 'SR-X05', 'SR-X08']],
    desc: 'Repeated exfiltration events in a short window: the extension is sweeping multiple finance views.' },
  { id: 'CH-5', title: 'Rail interference', level: 'critical', within: 24 * 60 * 60e3,
    steps: [['SR-I05', 'SR-S05'], ['SR-A01', 'SR-A02', 'SR-X01', 'SR-X04', 'SR-A08']],
    desc: 'Someone tampered with the guardrail and then risky activity followed.' },
  { id: 'CH-6', title: 'Maker-checker collapse', level: 'critical', within: 15 * 60e3,
    steps: [['SR-A07'], ['SR-A01', 'SR-A08']],
    desc: 'The same automated session filled in a payment and then tried to approve it.' }
];

const LEVELS = ['info', 'low', 'medium', 'high', 'critical'];

function levelOfScore(score) {
  if (score >= 80) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

function normaliseEvent(raw) {
  const code = raw && TAXONOMY[raw.code] ? raw.code : null;
  const tax = code ? TAXONOMY[code] : null;
  const severity = raw.severity && SEVERITY_WEIGHT[raw.severity] !== undefined ? raw.severity : (tax ? tax.severity : 'low');
  return {
    code: code || 'SR-UNK',
    family: tax ? tax.family : 'Unknown',
    title: tax ? tax.title : (raw.title || 'Unclassified event'),
    severity,
    weight: SEVERITY_WEIGHT[severity]
  };
}

function eventTime(e) { return Date.parse(e.ts || e.receivedAt || 0) || 0; }

// Evaluate one device's recent events. Returns score, level, and any matched chains.
function evaluateDevice(events, now) {
  now = now || Date.now();
  const recent = events.filter(e => now - eventTime(e) <= 24 * 60 * 60e3)
    .sort((a, b) => eventTime(a) - eventTime(b));
  let score = 0;
  const bySeverity = {};
  for (const e of recent) {
    const sev = e.severity || 'low';
    bySeverity[sev] = (bySeverity[sev] || 0) + 1;
  }
  // Highest severity sets the floor; additional events add diminishing weight.
  let floor = 0;
  for (const sev of Object.keys(bySeverity)) floor = Math.max(floor, SEVERITY_WEIGHT[sev] || 0);
  score = floor;
  score += Math.min(25, Math.max(0, recent.length - 1) * 3);

  const chains = [];
  for (const chain of CHAINS) {
    const hit = matchChain(chain, recent);
    if (hit) { chains.push(hit); score += chain.level === 'critical' ? 35 : 20; }
  }
  score = Math.min(100, Math.round(score));
  let level = levelOfScore(score);
  for (const c of chains) if (LEVELS.indexOf(c.level) > LEVELS.indexOf(level)) level = c.level;
  return { score, level, chains, eventCount: recent.length, bySeverity };
}

function matchChain(chain, events) {
  if (chain.repeat) {
    const codes = new Set(chain.steps[0]);
    const hits = events.filter(e => codes.has(e.code));
    for (let i = 0; i + chain.repeat - 1 < hits.length; i++) {
      const a = hits[i], b = hits[i + chain.repeat - 1];
      if (eventTime(b) - eventTime(a) <= chain.within) {
        return { id: chain.id, title: chain.title, level: chain.level, desc: chain.desc,
          events: hits.slice(i, i + chain.repeat).map(e => e.id) };
      }
    }
    return null;
  }
  // Ordered steps: find first step, then each next step later but within window.
  for (let i = 0; i < events.length; i++) {
    if (!chain.steps[0].includes(events[i].code)) continue;
    const start = eventTime(events[i]);
    const matched = [events[i]];
    let cursor = i;
    let ok = true;
    for (let s = 1; s < chain.steps.length; s++) {
      const codes = new Set(chain.steps[s]);
      let found = -1;
      for (let j = cursor + 1; j < events.length; j++) {
        if (eventTime(events[j]) - start > chain.within) break;
        if (codes.has(events[j].code)) { found = j; break; }
      }
      if (found < 0) { ok = false; break; }
      matched.push(events[found]); cursor = found;
    }
    if (ok) return { id: chain.id, title: chain.title, level: chain.level, desc: chain.desc, events: matched.map(e => e.id) };
  }
  return null;
}

// Convert a census classification into posture events.
function postureEventsFromCensus(classified, previous) {
  const out = [];
  const prevById = new Map((previous || []).map(x => [x.id, x]));
  for (const ext of classified) {
    if (!ext.enabled) continue;
    if (ext.category === 'unsanctioned-ai' || ext.category === 'unsanctioned-ai-agent') {
      out.push({ code: 'SR-S01', detail: `${ext.name} (${ext.id}) classified as AI: ${ext.reasons.slice(0, 3).join('; ')}` });
    }
    if (ext.category !== 'sanctioned-ai' && ext.capabilities.trustedInput) {
      out.push({ code: 'SR-S03', detail: `${ext.name} holds the debugger permission` });
    }
    if (ext.category !== 'sanctioned-ai' && ext.capabilities.session) {
      out.push({ code: 'SR-X06', detail: `${ext.name} holds the cookies permission` });
    }
    if ((ext.installType === 'development' || ext.installType === 'sideload') && ext.category !== 'sanctioned-ai') {
      out.push({ code: 'SR-S04', detail: `${ext.name} is ${ext.installType}-installed` });
    }
    const prev = prevById.get(ext.id);
    if (prev) {
      const gained = ext.permissions.filter(p => !prev.permissions.includes(p) && (require('../../extension/shared/patterns.js').RISKY_PERMISSIONS[p] || 0) >= 10);
      if (gained.length) out.push({ code: 'SR-S02', detail: `${ext.name} gained ${gained.join(', ')} (v${prev.version} -> v${ext.version})` });
    }
  }
  return out;
}

module.exports = { DIMENSIONS, TAXONOMY, CHAINS, SEVERITY_WEIGHT, LEVELS, normaliseEvent, evaluateDevice, matchChain, levelOfScore, postureEventsFromCensus };
