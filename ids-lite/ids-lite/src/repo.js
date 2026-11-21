'use strict';
const fs = require('fs');
const path = require('path');

const MAX_EVENTS_IN_MEMORY = 100000;

function atomicWrite(file, text) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, text, { mode: 0o600 });
  fs.renameSync(tmp, file);
}
function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function readJsonl(file) {
  try {
    return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).flatMap((l) => {
      try { return [JSON.parse(l)]; } catch { return []; } // skip a torn last line after a crash
    });
  } catch { return []; }
}

/**
 * Durable repository. Everything lives in memory for speed and is persisted to `dir`:
 *   events.jsonl (append-only), audit.jsonl (append-only), blocks.json + settings.json (atomic rewrite),
 *   backups/settings-v<N>.json (one file per settings change).
 * With dir = null it is purely in-memory (tests). Swap this class for SQL/Postgres in production.
 */
class Repo {
  constructor(dir = null) {
    this.dir = dir;
    this.events = [];
    this.audit = [];
    this.blocks = [];
    this.settings = null;
    if (dir) {
      fs.mkdirSync(path.join(dir, 'backups'), { recursive: true, mode: 0o700 });
      this.events = readJsonl(this._p('events.jsonl'));
      this.audit = readJsonl(this._p('audit.jsonl'));
      this.blocks = readJson(this._p('blocks.json'), []);
      this.settings = readJson(this._p('settings.json'), null);
    }
  }
  _p(name) { return path.join(this.dir, name); }

  addEvents(list) {
    this.events.push(...list);
    if (this.events.length > MAX_EVENTS_IN_MEMORY) this.events.splice(0, this.events.length - MAX_EVENTS_IN_MEMORY);
    if (this.dir) fs.appendFileSync(this._p('events.jsonl'), list.map((e) => JSON.stringify(e)).join('\n') + '\n', { mode: 0o600 });
  }
  addAudit(entry) {
    this.audit.push(entry);
    if (this.dir) fs.appendFileSync(this._p('audit.jsonl'), JSON.stringify(entry) + '\n', { mode: 0o600 });
  }
  saveBlocks() { if (this.dir) atomicWrite(this._p('blocks.json'), JSON.stringify(this.blocks)); }
  saveSettings(s) {
    this.settings = s;
    if (!this.dir) return;
    atomicWrite(this._p('settings.json'), JSON.stringify(s, null, 2));
    atomicWrite(this._p(`backups/settings-v${s.version}.json`), JSON.stringify(s, null, 2));
  }
  /** Drop events older than `cutoff`, and null out raw IPs older than `rawCutoff`. */
  compactEvents(cutoff, rawCutoff) {
    this.events = this.events.filter((e) => e.ts >= cutoff);
    for (const e of this.events) if (e.ip_raw && e.ts < rawCutoff) e.ip_raw = null;
    if (this.dir) atomicWrite(this._p('events.jsonl'), this.events.map((e) => JSON.stringify(e)).join('\n') + (this.events.length ? '\n' : ''));
  }
}

module.exports = { Repo };
