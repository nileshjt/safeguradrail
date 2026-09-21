'use strict';
/*
 * Tiny persistent state store: in-memory collections flushed to a JSON file.
 * Good enough for a single control-plane node; swap for Postgres by keeping
 * the same method surface.
 */
const fs = require('node:fs');
const path = require('node:path');
const { Ledger } = require('./ledger');

const MAX_EVENTS = 5000;

class Store {
  constructor(file) {
    this.file = file;
    this.state = { events: [], alerts: [], approvals: [], devices: {}, census: {}, ledger: [] };
    this.load();
    this.ledger = new Ledger(this.state.ledger);
    this._timer = null;
  }

  load() {
    try {
      if (fs.existsSync(this.file)) {
        const parsed = JSON.parse(fs.readFileSync(this.file, 'utf8'));
        this.state = { ...this.state, ...parsed };
      }
    } catch (err) {
      console.error('[store] could not load state, starting fresh:', err.message);
    }
  }

  save() {
    clearTimeout(this._timer);
    this._timer = setTimeout(() => {
      try {
        this.state.ledger = this.ledger.entries;
        fs.mkdirSync(path.dirname(this.file), { recursive: true });
        const tmp = this.file + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(this.state));
        fs.renameSync(tmp, this.file);
      } catch (err) {
        console.error('[store] save failed:', err.message);
      }
    }, 150);
    if (this._timer.unref) this._timer.unref();
  }

  flushSync() {
    clearTimeout(this._timer);
    this.state.ledger = this.ledger.entries;
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    fs.writeFileSync(this.file, JSON.stringify(this.state));
  }

  touchDevice(id, patch) {
    const d = this.state.devices[id] || { id, firstSeen: new Date().toISOString() };
    Object.assign(d, patch || {}, { lastSeen: new Date().toISOString() });
    this.state.devices[id] = d;
    return d;
  }

  addEvent(evt) {
    this.state.events.push(evt);
    if (this.state.events.length > MAX_EVENTS) this.state.events.splice(0, this.state.events.length - MAX_EVENTS);
    this.ledger.append('event', { id: evt.id, device: evt.device, code: evt.code, severity: evt.severity, ts: evt.ts, detail: evt.detail });
    return evt;
  }

  addAlert(alert) {
    this.state.alerts.unshift(alert);
    if (this.state.alerts.length > 1000) this.state.alerts.length = 1000;
    this.ledger.append('alert', { id: alert.id, device: alert.device, level: alert.level, title: alert.title, ts: alert.ts });
    return alert;
  }

  eventsForDevice(device) { return this.state.events.filter(e => e.device === device); }
}

module.exports = { Store };
