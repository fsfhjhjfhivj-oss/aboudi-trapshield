'use strict';
const crypto = require('crypto');

class EventService {
  constructor(repo, now = Date.now) { this.repo = repo; this.now = now; }

  record(list) {
    const out = list.map((e) => ({
      id: crypto.randomUUID(), ts: this.now(), user_id: null, ip_raw: null, block_id: null, source: 'server', ...e,
    }));
    if (out.length) this.repo.addEvents(out);
    return out;
  }

  query({ from, to, rule_id, severity, ip_hash, limit = 50, cursor = 0 } = {}) {
    const all = [];
    for (let i = this.repo.events.length - 1; i >= 0; i--) { // newest first
      const e = this.repo.events[i];
      if (from && e.ts < from) continue;
      if (to && e.ts > to) continue;
      if (rule_id && e.rule_id !== rule_id) continue;
      if (severity && e.severity !== severity) continue;
      if (ip_hash && e.ip_hash !== ip_hash) continue;
      all.push(e);
    }
    return { items: all.slice(cursor, cursor + limit), next_cursor: cursor + limit < all.length ? String(cursor + limit) : null };
  }

  since(ts) {
    const out = [];
    for (let i = this.repo.events.length - 1; i >= 0 && this.repo.events[i].ts >= ts - 3600000; i--) {
      if (this.repo.events[i].ts >= ts) out.push(this.repo.events[i]);
    }
    return out;
  }

  recentFor(hashes, ts) {
    return this.since(ts).filter((e) => hashes.includes(e.ip_hash) && (e.action === 'warned' || e.action === 'blocked'));
  }
}

module.exports = { EventService };
