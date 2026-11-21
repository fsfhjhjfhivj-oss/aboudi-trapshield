'use strict';
const net = require('net');

const RULE_IDS = ['sqli_pattern', 'path_traversal', 'scanner_ua', 'rate_flood', 'brute_force'];
const MODES = ['monitor', 'warn', 'enforce'];
const SENSITIVITIES = ['low', 'medium', 'high'];

const DEFAULTS = Object.freeze({
  enabled: true,
  mode: 'monitor', // safe default: observe first, enforce later
  sensitivity: 'medium',
  block_duration_sec: 900,
  max_block_duration_sec: 86400,
  rules: {
    sqli_pattern: { enabled: true, weight: 40 },
    path_traversal: { enabled: true, weight: 40 },
    scanner_ua: { enabled: true, weight: 25 },
    rate_flood: { enabled: true, weight: 30 },
    brute_force: { enabled: true, weight: 70 },
  },
  allowlist_ips: [],
  exclude_paths: ['/health', '/static/*', '/ids/*'],
  retention_days: 30,
  store_raw_ip: false,
  banner: { enabled: true, position: 'top' },
  fail_mode: 'open',
  version: 1,
  updated_at: null,
  updated_by: null,
});

const clone = (o) => JSON.parse(JSON.stringify(o));
const isInt = (n, min, max) => Number.isInteger(n) && n >= min && n <= max;

function merge(base, input) {
  const out = clone(base);
  for (const k of Object.keys(DEFAULTS)) {
    if (input[k] === undefined) continue;
    if (k === 'rules' && input.rules && typeof input.rules === 'object') {
      for (const id of RULE_IDS) if (input.rules[id]) out.rules[id] = { ...out.rules[id], ...input.rules[id] };
    } else if (k === 'banner' && input.banner && typeof input.banner === 'object') {
      out.banner = { ...out.banner, ...input.banner };
    } else out[k] = input[k];
  }
  return out;
}

function validate(v) {
  const e = [];
  const bad = (field, msg) => e.push({ field, message: msg });
  if (typeof v.enabled !== 'boolean') bad('enabled', 'must be boolean');
  if (!MODES.includes(v.mode)) bad('mode', `one of ${MODES.join('|')}`);
  if (!SENSITIVITIES.includes(v.sensitivity)) bad('sensitivity', `one of ${SENSITIVITIES.join('|')}`);
  if (!isInt(v.block_duration_sec, 10, 7 * 86400)) bad('block_duration_sec', 'integer 10..604800');
  if (!isInt(v.max_block_duration_sec, 10, 30 * 86400)) bad('max_block_duration_sec', 'integer 10..2592000');
  if (v.block_duration_sec > v.max_block_duration_sec) bad('block_duration_sec', 'must be <= max_block_duration_sec');
  if (!isInt(v.retention_days, 1, 365)) bad('retention_days', 'integer 1..365');
  if (typeof v.store_raw_ip !== 'boolean') bad('store_raw_ip', 'must be boolean');
  if (!['open', 'closed'].includes(v.fail_mode)) bad('fail_mode', 'open|closed');
  for (const id of RULE_IDS) {
    const r = v.rules[id];
    if (typeof r.enabled !== 'boolean') bad(`rules.${id}.enabled`, 'must be boolean');
    if (!isInt(r.weight, 0, 100)) bad(`rules.${id}.weight`, 'integer 0..100');
  }
  if (!Array.isArray(v.allowlist_ips) || v.allowlist_ips.length > 500) bad('allowlist_ips', 'array (max 500)');
  else for (const c of v.allowlist_ips) if (!parseCidr(c)) bad('allowlist_ips', `invalid IP/CIDR: ${String(c).slice(0, 50)}`);
  if (!Array.isArray(v.exclude_paths) || v.exclude_paths.some((p) => typeof p !== 'string' || p.length > 200)) bad('exclude_paths', 'array of strings');
  if (typeof v.banner.enabled !== 'boolean') bad('banner.enabled', 'must be boolean');
  return e;
}

function parseCidr(c) {
  if (typeof c !== 'string') return null;
  const [ip, prefix] = c.split('/');
  const fam = net.isIP(ip);
  if (!fam) return null;
  if (prefix === undefined) return { ip, family: fam === 4 ? 'ipv4' : 'ipv6' };
  const p = Number(prefix);
  const max = fam === 4 ? 32 : 128;
  if (!Number.isInteger(p) || p < 0 || p > max) return null;
  return { ip, prefix: p, family: fam === 4 ? 'ipv4' : 'ipv6' };
}

function globToRegex(g) {
  const esc = g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${esc}$`);
}

class SettingsManager {
  constructor(repo, { now = Date.now, onChange } = {}) {
    this.repo = repo;
    this.now = now;
    this.onChange = onChange;
    this.cur = repo.settings ? merge(DEFAULTS, repo.settings) : clone(DEFAULTS);
    this._compile();
  }
  get() { return this.cur; }

  _compile() {
    this.bl = new net.BlockList();
    for (const c of this.cur.allowlist_ips) {
      const p = parseCidr(c);
      if (!p) continue;
      if (p.prefix === undefined) this.bl.addAddress(p.ip, p.family);
      else this.bl.addSubnet(p.ip, p.prefix, p.family);
    }
    this.excludes = this.cur.exclude_paths.map(globToRegex);
  }

  isAllowlisted(ip) {
    if (!ip || !this.cur.allowlist_ips.length) return false;
    const norm = String(ip).replace(/^::ffff:/i, '');
    const fam = net.isIP(norm);
    return fam ? this.bl.check(norm, fam === 4 ? 'ipv4' : 'ipv6') : false;
  }
  isExcluded(p) { return this.excludes.some((r) => r.test(p)); }

  /** Full replace (PUT semantics) with optimistic concurrency. */
  update(input, { ifVersion, actor = 'admin' } = {}) {
    if (input === null || typeof input !== 'object' || Array.isArray(input)) {
      return { ok: false, status: 422, errors: [{ field: '$', message: 'body must be an object' }] };
    }
    if (ifVersion !== this.cur.version) return { ok: false, status: 412, errors: [{ field: 'version', message: 'stale settings version' }] };
    const next = merge(DEFAULTS, input);
    const errors = validate(next);
    if (errors.length) return { ok: false, status: 422, errors };
    next.version = this.cur.version + 1;
    next.updated_at = new Date(this.now()).toISOString();
    next.updated_by = actor;
    const before = this.cur;
    this.cur = next;
    this._compile();
    this.repo.saveSettings(next);
    this.repo.addAudit({ id: require('crypto').randomUUID(), ts: this.now(), actor, action: 'settings.update', target_type: 'settings', target_id: String(next.version), diff: diff(before, next) });
    if (this.onChange) this.onChange(next);
    return { ok: true, settings: next };
  }
}

function diff(a, b) {
  const out = {};
  for (const k of Object.keys(DEFAULTS)) {
    if (['version', 'updated_at', 'updated_by'].includes(k)) continue;
    if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) out[k] = { from: a[k], to: b[k] };
  }
  return out;
}

module.exports = { DEFAULTS, SettingsManager, RULE_IDS, validate, merge };
