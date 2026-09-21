# Safeguradrail

[![License: MIT](https://img.shields.io/badge/License-MIT-0f6b5c.svg)](LICENSE)
[![tests](https://github.com/nileshjt/safeguradrail/actions/workflows/tests.yml/badge.svg)](https://github.com/nileshjt/safeguradrail/actions/workflows/tests.yml)

A guardrail platform for organisations whose finance tools are used through browsers that also run AI extensions.

AI sidebars, summarisers, autofill helpers and autonomous browser agents get the same access to your accounts-payable, ERP, payroll and banking portals as the employee who installed them. The finance tool cannot tell them apart, and it logs everything as the employee. Safeguradrail puts a rail between the two.

## What it does

- **Sentinel**, an enterprise-installed browser extension, activates on protected finance origins and enforces in-page controls: canary tracers, field masking, an action rail that rejects synthetic input and routes payment approvals to a second person, prompt-injection scanning with neutralisation, tamper detection, and clipboard protection. Its service worker inventories other extensions and blocks finance content from leaving toward AI endpoints.
- **The control plane** serves policy, ingests events, classifies installed extensions, scores each device against a taxonomy of 30 risk permutations and six attack chains, brokers dual-control approvals, and keeps a hash-chained ledger.
- **The console** shows devices, alerts, approvals, events, the extension census, the risk model and the ledger.
- **A demo finance app and a demo adversary extension** let you see every control fire on your own machine.

Read [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for the risk permutations and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the pieces fit.

## Quick start

Requires Node.js 20 or newer. No npm packages.

```bash
npm start
```

Then:

| Where | URL |
|---|---|
| Console | http://localhost:4173/ |
| Demo finance app (Ledgerly AP) | http://localhost:4173/demo/ |

Press a "Simulate a scenario" button on the console to see scoring, chains and alerts without loading anything into Chrome.

## Full demo with the extension

1. Open `chrome://extensions`, enable Developer mode, click **Load unpacked** and pick the `extension/` folder. A "webRequestBlocking" warning is expected for unpacked installs: blocking only works when the extension is policy-installed, so it runs in observe mode and the console shows the device as degraded. Everything else enforces.
2. Load `demo/rogue-extension/` the same way. It is a stand-in for a consumer AI sidekick: it harvests page text to an AI API on every page load and can drive the UI with synthetic input.
3. Open http://localhost:4173/demo/ and watch the console at http://localhost:4173/.

What you should see:

| Do this in the demo app | Sentinel response | Codes |
|---|---|---|
| Just open the Invoices tab | Hidden white 1px instruction in the INV-1042 memo and attachment preview is neutralised and boxed in orange; IBANs and SWIFTs are masked | SR-I02, SR-I01 |
| Rogue popup: Summarise this page | Request to api.openai.com carrying the page canary is reported (blocked when policy-installed) | SR-X01 / SR-X08 |
| Rogue popup: Auto-approve pending payments | Every synthetic click is blocked with a toast | SR-A01, then chain CH-1 |
| Rogue popup: Act on instructions found in the page (on Vendors tab) | Script-filled IBAN field is flagged, synthetic submit is blocked | SR-A07, SR-A02, chain CH-2 |
| Click Approve & release yourself | Held under dual control; approve or deny it from the console's Approvals tab | approval flow, SR-A04 on deny |
| Submit the bank-details form yourself | Step-up dialog shows the real values and asks for a typed code | step-up |
| Copy an IBAN from the table | Clipboard receives the masked value | SR-X03 |
| Click a masked value | Reveals for 8 seconds and records an audit event | SR-V01 |
| Click Approve without moving the mouse first (use keyboard focus + Enter after sitting still) | Held for lack of presence signals | SR-A08 |

## Layout

```
extension/          Sentinel (Manifest V3)
  shared/patterns.js   detection library shared with the server
server/             control plane + console
  lib/risk.js          taxonomy, dimensions, chains, scoring
  policies/default.json
demo/finance-app/   Ledgerly AP, the protected surface
demo/rogue-extension/  PromptPal, the adversary
docs/               threat model, architecture
test/               node:test suites
```

## Policy

Everything Sentinel does is driven by `server/policies/default.json`. Each protected app declares its origins, the selectors that hold sensitive values, the selectors that render untrusted content, and its high-risk actions with a control level:

| Control | Behaviour |
|---|---|
| `observe` | Record provenance only |
| `deny-synthetic` | Block untrusted events, allow humans |
| `step-up` | Block untrusted events; humans re-read the values and type a code with real keystrokes |
| `dual-control` | Block untrusted events; humans wait for a second person to approve in the console |

The policy file is watched; edits apply within two seconds and reach browsers on their next heartbeat.

## Tests

```bash
npm test
```

## Production notes

Put the control plane behind TLS and an identity-aware proxy, require a device token on the device-facing endpoints, force-install Sentinel through browser policy, and pin `controlPlaneUrl` with managed storage. Use the census output to build the browser's extension blocklist. See the deployment section in the architecture doc.
