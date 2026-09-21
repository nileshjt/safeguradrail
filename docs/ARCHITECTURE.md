# Safeguradrail architecture

```
┌──────────────────────────── employee's browser ─────────────────────────────┐
│                                                                              │
│   AI extension(s)          Sentinel (force-installed)         finance tool   │
│   ┌──────────────┐         ┌──────────────────────┐          ┌────────────┐  │
│   │ content      │ reads   │ content script        │ guards   │ Ledgerly / │  │
│   │ script       │────────▶│  Canary Tracer        │◀────────▶│ NetSuite / │  │
│   │              │ clicks  │  Field Shield         │          │ bank portal│  │
│   │ service      │────────▶│  Action Rail          │          └────────────┘  │
│   │ worker ──────┼──┐      │  Injection Scan       │                          │
│   └──────────────┘  │      │  Tamper Watch         │                          │
│                     │      │  Clipboard Guard      │                          │
│                     │      ├──────────────────────┤                          │
│         webRequest  └─────▶│ service worker        │                          │
│         (blocking)         │  Egress Watch         │                          │
│                            │  Extension Census     │                          │
│                            │  Event relay          │                          │
│                            │  Approval broker      │                          │
│                            └──────────┬───────────┘                          │
└───────────────────────────────────────┼──────────────────────────────────────┘
                                        │ HTTPS
                       ┌────────────────▼────────────────┐
                       │ Control plane (server/)          │
                       │  /policy  /events  /census       │
                       │  /heartbeat  /approvals          │
                       │  Risk engine · chains · ledger   │
                       │  Console (dashboard)             │
                       └─────────────────────────────────┘
```

## Components

### Sentinel content script (`extension/content.js`)

Runs at `document_start` on every page but activates only when the URL matches a protected app in policy. Everything it draws lives in a closed shadow root so page scripts cannot restyle or remove it.

| Control | What it does | Codes |
|---|---|---|
| Canary Tracer | Inserts an invisible, unique `SGR-CANARY-…` token into the page. Any request body carrying it proves that page was scraped. | X01, X05, X08 |
| Field Shield | Masks IBANs, account numbers, card PANs, SSNs in text nodes and applies text-security to sensitive inputs. Trusted click reveals for a few seconds and records SR-V01. | X02, X07, V01 |
| Action Rail | Capture-phase listener on policy-defined high-risk controls. Rejects untrusted events, enforces velocity, checks human presence, then applies the control level: `deny-synthetic`, `step-up` (typed code with trusted keystrokes), or `dual-control` (out-of-band approval). Records provenance for audit. | A01–A08, X04, C02 |
| Injection Scan | Scans untrusted-content selectors for AI-directed phrasing and hidden text. Neutralises hidden nodes by rewriting them into a visible warning so an AI reading the DOM sees the warning, not the instruction. | I01, I02 |
| Tamper Watch | MutationObserver: re-masks unmasked values, re-inserts the canary, and flags critical displayed values that change with no recent human interaction. | I03, I05 |
| Clipboard Guard | Rewrites copied text with masked values; reports instruction-like pastes. | X03, I04 |

### Sentinel service worker (`extension/background.js`)

| Function | Detail |
|---|---|
| Policy sync | Fetches `/policy` with ETag; stores locally for the content script; managed storage can pin the control-plane URL. |
| Extension Census | `chrome.management.getAll()` on install/enable/disable events and on a timer; classified locally for the popup and uploaded for posture scoring. |
| Egress Watch | `webRequest.onBeforeRequest` with `requestBody`. Inspects requests initiated by other extensions, and requests to AI hosts from protected tabs. Blocks when policy mode is `block` and the extension is policy-installed; otherwise observes and reports degraded enforcement. |
| Event relay | Batches events; flushes immediately for high-severity codes. Redacts sensitive values before they leave the browser. |
| Approval broker | Proxies dual-control requests and polling so the page never talks to the control plane directly. |
| Heartbeat | Reports enforcement mode, policy version, and protected-tab count; the control plane alerts on silence. |

### Control plane (`server/`)

Zero-dependency Node.js. State is a JSON file with an append-only hash-chained ledger; swap the store for a database by keeping the `Store` interface.

- `lib/risk.js`: taxonomy, dimensions, chain rules, device scoring.
- `lib/policy.js`: validation, defaults, origin matching.
- `lib/ledger.js`: SHA-256 chain with `verify()`.
- `index.js`: HTTP routes, alerting, approvals, census processing, stale-device detection, demo scenarios.
- `public/`: the console.

### Trust boundaries

1. Page scripts and other extensions are untrusted. Sentinel never trusts DOM content or events unless `isTrusted` and presence signals agree, and even then policy may demand a second person.
2. The content script trusts only the policy delivered by its own service worker.
3. The control plane treats event payloads as untrusted input: codes are validated against the taxonomy, strings are clipped and redacted, unknown codes become `SR-UNK`.
4. Approvals are decided only through the console API, never by the requesting browser.

## Data handling

Sentinel redacts bank identifiers, card numbers, and IDs before an event leaves the browser, and the control plane redacts again on ingest. The ledger stores codes, severities, devices, and redacted detail strings, never raw financial data. Canary tokens are random and carry no meaning outside Safeguradrail.

## Deployment

1. Run the control plane behind TLS with an identity-aware proxy. Restrict `/api/*` to security and finance-ops staff; `/policy`, `/events`, `/census`, `/heartbeat`, `/approvals` are the device-facing surface and should require a device token in production.
2. Force-install Sentinel through Chrome Enterprise / Edge policy (`ExtensionInstallForcelist`) and set `controlPlaneUrl` via `ExtensionSettings` managed storage.
3. Put unsanctioned AI extensions discovered by the census onto `ExtensionInstallBlocklist`. Safeguradrail tells you which ones; the browser policy removes them.
4. Add each finance tool as a protected app with its high-risk selectors. Start with `observe` and `deny-synthetic`, then move payment release and beneficiary changes to `dual-control`.
