'use strict';
const { Repo } = require('./repo');
const { SettingsManager } = require('./settings');
const { CounterStore } = require('./counters');
const { DetectionEngine } = require('./engine');
const { BlockService } = require('./blocks');
const { EventService } = require('./events');
const { hashIp } = require('./crypto');
const { buildEvidence } = require('./redact');

function normalizeKeys(opts) {
  let keys = opts.hmacKeys;
  if (!keys && opts.hmacKey) keys = [{ version: 1, key: opts.hmacKey }];
  if (!Array.isArray(keys) || !keys.length) throw new Error('ids-lite: provide hmacKey or hmacKeys (first = current)');
  for (const k of keys) if (!k.key || String(k.key).length < 16) throw new Error('ids-lite: HMAC keys must be >= 16 chars');
  return keys;
}

/** Block duration doubles for every block the same IP got in the last 24h, capped by settings. */
const escalate = (recent, base, max) => Math.min(base * 2 ** Math.min(recent, 10), max);

class Ids {
  constructor(opts = {}) {
    this.opts = { basePath: '/ids', dataDir: null, now: Date.now, purgeIntervalMs: 3600 * 1000, ...opts };
    this.now = this.opts.now;
    this.keys = normalizeKeys(this.opts);
    this.repo = new Repo(this.opts.dataDir);
    this.settings = new SettingsManager(this.repo, { now: this.now });
    this.counters = new CounterStore(this.now);
    this.engine = new DetectionEngine({ counters: this.counters, getSettings: () => this.settings.get() });
    this.blocks = new BlockService(this.repo, this.now);
    this.events = new EventService(this.repo, this.now);
    this.idem = new Map(); // idempotency_key -> {id, exp}
    this._timers = [];
  }

  hashIp(ip) { const k = this.keys[0]; return { hash: hashIp(ip, k.key), version: k.version }; }
  /** One hash per key version, so blocks created before a key rotation are still matched. */
  hashesFor(ip) { return this.keys.map((k) => hashIp(ip, k.key)); }

  /**
   * Core decision function used by every adapter.
   * ctx: { ip, method, path, query, body, userAgent, isLoginFailure }
   * returns { action: none|logged|warned|blocked, retryAfter?, blockId?, hits: [] }
   */
  inspect(ctx, { only } = {}) {
    const s = this.settings.get();
    const none = { action: 'none', hits: [] };
    if (!s.enabled || !ctx.ip) return none;
    if (this.settings.isAllowlisted(ctx.ip)) return none;

    const all = this.hashesFor(ctx.ip);
    const active = this.blocks.findActive(all);
    if (active && s.mode === 'enforce') {
      this.blocks.hit(active.id);
      return { action: 'blocked', blockId: active.id, retryAfter: Math.max(1, Math.ceil((active.expires_at - this.now()) / 1000)), hits: [] };
    }
    if (this.settings.isExcluded(ctx.path)) return none;

    const { hash, version } = this.hashIp(ctx.ip);
    const res = this.engine.evaluate({ ...ctx, ipHash: hash }, { only });
    if (!res.hits.length) return none;

    let blockId = null;
    let retryAfter;
    if (res.action === 'blocked') {
      const dur = escalate(this.blocks.countRecent(all), s.block_duration_sec, s.max_block_duration_sec);
      const b = this.blocks.create({ ip_hash: hash, key_version: version, reason: res.hits[0].rule_id, duration_sec: dur, created_by: 'system' });
      blockId = b.id;
      retryAfter = dur;
    }
    this.events.record(res.hits.map((h) => ({
      rule_id: h.rule_id, severity: h.severity, score: h.score,
      ip_hash: hash, key_version: version, ip_raw: s.store_raw_ip ? ctx.ip : null,
      method: ctx.method, path: String(ctx.path || '').slice(0, 300),
      evidence: buildEvidence(ctx), action: res.action, block_id: blockId, source: 'server',
    })));
    return { action: res.action, blockId, retryAfter, hits: res.hits.map((h) => h.rule_id) };
  }

  /** Visitor-facing status for the banner. Contains nothing sensitive. */
  statusFor(ip) {
    const s = this.settings.get();
    const base = { level: 'none', message_key: null, block_until: null, poll_after_sec: 60 };
    if (!s.enabled || !s.banner.enabled || !ip) return base;
    const all = this.hashesFor(ip);
    const b = this.blocks.findActive(all);
    if (b && s.mode === 'enforce') return { ...base, level: 'blocked', message_key: 'temporarily_blocked', block_until: new Date(b.expires_at).toISOString(), poll_after_sec: 30 };
    if (s.mode !== 'monitor' && this.events.recentFor(all, this.now() - 10 * 60 * 1000).length) {
      return { ...base, level: 'notice', message_key: 'unusual_activity' };
    }
    return base;
  }

  purge() {
    const s = this.settings.get();
    const cutoff = this.now() - s.retention_days * 86400000;
    this.repo.compactEvents(cutoff, this.now() - 7 * 86400000); // raw IPs live at most 7 days
    this.blocks.purge(cutoff);
    this.blocks.sweepExpired();
    for (const [k, v] of this.idem) if (v.exp <= this.now()) this.idem.delete(k);
  }

  start() {
    const t = setInterval(() => { try { this.purge(); } catch (_) { /* never crash the host app */ } }, this.opts.purgeIntervalMs);
    const f = setInterval(() => { try { this.blocks.sweepExpired(); } catch (_) {} }, 30000);
    t.unref(); f.unref();
    this._timers.push(t, f);
    return this;
  }
  stop() { this._timers.forEach(clearInterval); this._timers = []; this.blocks.sweepExpired(); }
}

module.exports = { Ids };
