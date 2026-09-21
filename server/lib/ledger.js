'use strict';
/*
 * Append-only, hash-chained audit ledger.
 * Every security-relevant fact (event, alert, approval decision, census change)
 * is appended with a SHA-256 over the previous hash and the entry body, so any
 * later edit or deletion is detectable by verify().
 */
const crypto = require('node:crypto');

const GENESIS = '0'.repeat(64);

function digest(prev, body) {
  return crypto.createHash('sha256').update(prev + '\n' + JSON.stringify(body)).digest('hex');
}

class Ledger {
  constructor(entries) {
    this.entries = Array.isArray(entries) ? entries : [];
  }

  get head() {
    return this.entries.length ? this.entries[this.entries.length - 1].hash : GENESIS;
  }

  append(type, data) {
    const body = { seq: this.entries.length + 1, ts: new Date().toISOString(), type, data };
    const prev = this.head;
    const entry = { ...body, prev, hash: digest(prev, body) };
    this.entries.push(entry);
    return entry;
  }

  verify() {
    let prev = GENESIS;
    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i];
      const { hash, prev: p, ...body } = e;
      if (p !== prev) return { ok: false, brokenAt: e.seq, reason: 'previous-hash mismatch' };
      if (body.seq !== i + 1) return { ok: false, brokenAt: e.seq, reason: 'sequence gap' };
      if (digest(prev, body) !== hash) return { ok: false, brokenAt: e.seq, reason: 'entry hash mismatch' };
      prev = hash;
    }
    return { ok: true, length: this.entries.length, head: prev };
  }
}

module.exports = { Ledger, GENESIS, digest };
