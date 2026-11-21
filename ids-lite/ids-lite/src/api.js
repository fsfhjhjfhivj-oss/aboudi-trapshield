'use strict';
const path = require('path');
const crypto = require('crypto');
const { verify, safeEqual } = require('./crypto');

const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const ACTIONS = ['logged', 'warned', 'blocked'];
const HEX64 = /^[0-9a-f]{64}$/;

const err = (res, status, code, message, details) =>
  res.status(status).json({ error: { code, message, ...(details ? { details } : {}) } });

function createRouter(ids) {
  const express = require('express'); // peer dependency
  const router = express.Router();
  const o = ids.opts;

  router.use(express.json({ limit: '64kb', verify: (req, _res, buf) => { req.rawBody = buf.toString('utf8'); } }));
  router.use((req, res, next) => { res.set('Cache-Control', 'no-store'); res.set('X-Content-Type-Options', 'nosniff'); next(); });

  // ---------- auth ----------
  function requireAdmin(req, res, next) {
    let actor = null;
    if (typeof o.adminAuth === 'function') {
      const r = o.adminAuth(req); // return truthy (or an actor id string) to allow; plug in your session + CSRF here
      if (r) actor = typeof r === 'string' ? r : 'admin';
    } else if (o.adminToken) {
      const m = /^Bearer (.+)$/.exec(req.get('authorization') || '');
      if (m && safeEqual(m[1], o.adminToken)) actor = 'admin';
    } else {
      return err(res, 503, 'ADMIN_AUTH_NOT_CONFIGURED', 'Set adminToken or adminAuth');
    }
    if (!actor) return err(res, 401, 'UNAUTHORIZED', 'Admin authentication required');
    req.actor = actor;
    next();
  }

  function requireSigned(req, res, next) {
    if (!o.ingestSecret) return err(res, 503, 'INGEST_NOT_CONFIGURED', 'Set ingestSecret');
    if (req.rawBody === undefined && req.body && Object.keys(req.body).length) {
      return err(res, 500, 'RAW_BODY_MISSING', 'A global body parser consumed the body: use express.json({ verify: rawBodySaver })');
    }
    const ok = verify(req.rawBody || '', req.get('x-ids-timestamp'), req.get('x-ids-signature'), o.ingestSecret, { now: ids.now });
    if (!ok) return err(res, 401, 'BAD_SIGNATURE', 'Invalid or expired signature');
    next();
  }

  const num = (v, d) => { const n = Number(v); return Number.isFinite(n) && n >= 0 ? n : d; };
  const ts = (v) => { if (!v) return undefined; const t = Date.parse(v); return Number.isNaN(t) ? undefined : t; };
  const page = (q) => ({ limit: Math.min(200, Math.max(1, num(q.limit, 50))), cursor: Math.floor(num(q.cursor, 0)) });
  const iso = (e) => ({ ...e, ts: new Date(e.ts).toISOString() });
  const isoBlock = (b) => ({ ...b, created_at: new Date(b.created_at).toISOString(), expires_at: new Date(b.expires_at).toISOString(), lifted_at: b.lifted_at ? new Date(b.lifted_at).toISOString() : null });

  router.get('/v1/health', (_req, res) => res.json({ ok: true }));

  // ---------- events ----------
  router.get('/v1/events', requireAdmin, (req, res) => {
    const q = req.query;
    const r = ids.events.query({ from: ts(q.from), to: ts(q.to), rule_id: q.rule_id, severity: q.severity, ip_hash: q.ip_hash, ...page(q) });
    res.json({ items: r.items.map(iso), next_cursor: r.next_cursor });
  });

  router.post('/v1/events', requireSigned, (req, res) => {
    const b = req.body || {};
    const errors = [];
    if (typeof b.rule_id !== 'string' || !b.rule_id || b.rule_id.length > 64) errors.push('rule_id');
    if (!SEVERITIES.includes(b.severity)) errors.push('severity');
    if (!Number.isInteger(b.score) || b.score < 0 || b.score > 100) errors.push('score');
    if (typeof b.ip_hash !== 'string' || !HEX64.test(b.ip_hash)) errors.push('ip_hash');
    if (typeof b.idempotency_key !== 'string' || !b.idempotency_key || b.idempotency_key.length > 100) errors.push('idempotency_key');
    if (b.action !== undefined && !ACTIONS.includes(b.action)) errors.push('action');
    if (errors.length) return err(res, 422, 'VALIDATION_ERROR', 'Invalid event', errors.map((f) => ({ field: f })));
    const prev = ids.idem.get(b.idempotency_key);
    if (prev && prev.exp > ids.now()) return res.status(409).json({ error: { code: 'DUPLICATE', message: 'Already ingested' }, id: prev.id });
    const [ev] = ids.events.record([{
      rule_id: b.rule_id, severity: b.severity, score: b.score, ip_hash: b.ip_hash, key_version: Number(b.key_version) || ids.keys[0].version,
      method: String(b.method || '').slice(0, 10), path: String(b.path || '').slice(0, 300),
      evidence: { snippet: require('./redact').redactString(b.evidence && b.evidence.snippet), ua: '' },
      action: b.action || 'logged', ts: Number.isFinite(b.ts) ? b.ts : ids.now(), source: 'server',
    }]);
    ids.idem.set(b.idempotency_key, { id: ev.id, exp: ids.now() + 24 * 3600 * 1000 });
    res.status(201).json({ id: ev.id, action: ev.action, block_id: null });
  });

  // Sidecar contract for non-Node adapters (Django, Flask, PHP, ...): send request metadata, enforce the decision.
  router.post('/v1/adapter/evaluate', requireSigned, (req, res) => {
    const b = req.body || {};
    if (typeof b.ip !== 'string' || !b.ip || typeof b.path !== 'string') return err(res, 422, 'VALIDATION_ERROR', 'ip and path are required');
    const only = b.is_login_failure ? ['brute_force'] : undefined;
    const d = ids.inspect({
      ip: b.ip, method: String(b.method || 'GET').slice(0, 10), path: b.path.slice(0, 300),
      query: String(b.query || '').slice(0, 2048), body: String(b.body || '').slice(0, 2048),
      userAgent: String(b.user_agent || '').slice(0, 300), isLoginFailure: !!b.is_login_failure,
    }, { only });
    res.json({ action: d.action, retry_after: d.retryAfter || null, block_id: d.blockId || null, hits: d.hits });
  });

  // ---------- blocks ----------
  router.get('/v1/blocks', requireAdmin, (req, res) => {
    const r = ids.blocks.list({ status: req.query.status, ...page(req.query) });
    res.json({ items: r.items.map(isoBlock), next_cursor: r.next_cursor });
  });

  router.post('/v1/blocks', requireAdmin, (req, res) => {
    const b = req.body || {};
    let hash = b.ip_hash;
    let version = ids.keys[0].version;
    if (!hash && typeof b.ip === 'string' && b.ip) ({ hash, version } = ids.hashIp(b.ip));
    if (typeof hash !== 'string' || !HEX64.test(hash)) return err(res, 422, 'VALIDATION_ERROR', 'ip_hash (64 hex) or ip is required');
    const max = ids.settings.get().max_block_duration_sec;
    const dur = b.duration_sec === undefined ? ids.settings.get().block_duration_sec : b.duration_sec;
    if (!Number.isInteger(dur) || dur < 10 || dur > max) return err(res, 400, 'BAD_DURATION', `duration_sec must be an integer between 10 and ${max}`);
    if (req.ip && ids.hashesFor(req.ip).includes(hash)) return err(res, 400, 'SELF_BLOCK', 'Refusing to block the requesting admin address');
    const blk = ids.blocks.create({ ip_hash: hash, key_version: version, reason: String(b.reason || 'manual').slice(0, 100), duration_sec: dur, created_by: req.actor });
    ids.repo.addAudit({ id: crypto.randomUUID(), ts: ids.now(), actor: req.actor, action: 'block.create', target_type: 'block', target_id: blk.id, diff: { duration_sec: dur, reason: blk.reason } });
    res.status(201).json(isoBlock(blk));
  });

  router.delete('/v1/blocks/:id', requireAdmin, (req, res) => {
    const blk = ids.blocks.lift(req.params.id, req.actor);
    if (!blk) return err(res, 404, 'NOT_FOUND', 'Block not found');
    ids.repo.addAudit({ id: crypto.randomUUID(), ts: ids.now(), actor: req.actor, action: 'block.lift', target_type: 'block', target_id: blk.id, diff: {} });
    res.json(isoBlock(blk));
  });

  // ---------- settings ----------
  router.get('/v1/settings', requireAdmin, (_req, res) => {
    const s = ids.settings.get();
    res.set('ETag', `"v${s.version}"`).json(s);
  });

  router.put('/v1/settings', requireAdmin, (req, res) => {
    const m = /^"?v?(\d+)"?$/.exec(req.get('if-match') || '');
    if (!m) return err(res, 428, 'PRECONDITION_REQUIRED', 'If-Match header with the settings ETag is required');
    const r = ids.settings.update(req.body, { ifVersion: Number(m[1]), actor: req.actor });
    if (!r.ok) return err(res, r.status, r.status === 412 ? 'STALE_VERSION' : 'VALIDATION_ERROR', r.errors[0].message, r.errors);
    res.set('ETag', `"v${r.settings.version}"`).json(r.settings);
  });

  // ---------- audit + dashboard ----------
  router.get('/v1/audit', requireAdmin, (req, res) => {
    const { limit, cursor } = page(req.query);
    const all = ids.repo.audit.slice().reverse();
    res.json({ items: all.slice(cursor, cursor + limit).map(iso), next_cursor: cursor + limit < all.length ? String(cursor + limit) : null });
  });

  router.get('/v1/admin/dashboard', requireAdmin, (req, res) => {
    const ranges = { '24h': [86400000, 3600000], '7d': [7 * 86400000, 86400000], '30d': [30 * 86400000, 86400000] };
    const rangeKey = ranges[req.query.range] ? req.query.range : '24h';
    const [span, bucket] = ranges[rangeKey];
    const now = ids.now();
    const evs = ids.events.since(now - span);
    const by = {}; const series = {}; const ips = {};
    let blocked = 0;
    for (const e of evs) {
      by[e.rule_id] = (by[e.rule_id] || 0) + 1;
      if (e.action === 'blocked') blocked++;
      const bk = Math.floor(e.ts / bucket) * bucket;
      (series[bk] = series[bk] || { events: 0, blocks: 0 }).events++;
      if (e.action === 'blocked') series[bk].blocks++;
      const p = (ips[e.ip_hash] = ips[e.ip_hash] || { events: 0, score: 0 });
      p.events++; p.score += e.score;
    }
    const recent = ids.events.since(now - 15 * 60 * 1000);
    const high = recent.filter((e) => e.severity === 'high' || e.severity === 'critical').length;
    const threat_level = high >= 20 ? 'critical' : recent.length >= 5 ? 'elevated' : 'calm';
    res.json({
      range: rangeKey, threat_level,
      totals: { events: evs.length, blocked, active_blocks: ids.blocks.activeCount() },
      by_rule: Object.entries(by).map(([rule_id, count]) => ({ rule_id, count })).sort((a, b) => b.count - a.count),
      timeseries: Object.keys(series).sort().map((k) => ({ bucket: new Date(Number(k)).toISOString(), ...series[k] })),
      top_ip_hashes: Object.entries(ips).map(([ip_hash, v]) => ({ ip_hash, ...v })).sort((a, b) => b.score - a.score).slice(0, 10),
      settings_version: ids.settings.get().version,
    });
  });

  // ---------- public (banner) ----------
  router.get('/v1/public/status', (req, res) => {
    const { hash } = ids.hashIp(req.ip || '');
    if (ids.counters.incrBy(`pub:${hash}`, 1, 60) > 30) {
      res.set('Retry-After', '60');
      return err(res, 429, 'RATE_LIMITED', 'Too many status checks');
    }
    res.json(ids.statusFor(req.ip));
  });

  router.use('/static', express.static(path.join(__dirname, '..', 'public'), { index: false, maxAge: '1h' }));

  // eslint-disable-next-line no-unused-vars
  router.use((e, _req, res, _next) => {
    if (e && (e.type === 'entity.parse.failed' || e instanceof SyntaxError)) return err(res, 400, 'BAD_JSON', 'Malformed JSON body');
    if (e && e.type === 'entity.too.large') return err(res, 413, 'TOO_LARGE', 'Body too large');
    return err(res, 500, 'INTERNAL', 'Internal error');
  });

  return router;
}

module.exports = { createRouter };
