'use strict';

/** Thresholds per sensitivity level. blockScore = cumulative score (per IP, 10 min) that triggers a block. */
const SENSITIVITY = Object.freeze({
  low:    { loginFailMax: 10, loginWindowSec: 600, reqRateMax: 300, blockScore: 90 },
  medium: { loginFailMax: 5,  loginWindowSec: 300, reqRateMax: 120, blockScore: 70 },
  high:   { loginFailMax: 3,  loginWindowSec: 300, reqRateMax: 60,  blockScore: 50 },
});

const SQLI = [
  /\bunion\b[\s\S]{0,40}\bselect\b/i,
  /['"]\s*or\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,
  /;\s*drop\s+table\b/i,
  /\bsleep\s*\(\s*\d+\s*\)/i,
  /\bbenchmark\s*\(/i,
  /'\s*--/,
];
const TRAVERSAL = /(\.\.[\/\\]|\/etc\/passwd|\bboot\.ini\b)/i;
const SCANNERS = /(sqlmap|nikto|nmap|masscan|acunetix|nessus|wpscan|dirbuster)/i;

const decodeSafe = (s) => { try { return decodeURIComponent(s); } catch { return s; } };
const decode2 = (s) => decodeSafe(decodeSafe(String(s || '').replace(/\+/g, ' '))); // handles double encoding

/** Baseline rules. This is a lightweight tripwire, not a WAF replacement. */
const RULES = [
  { id: 'sqli_pattern', severity: 'high', weight: 40,
    test: (c) => { const t = `${decode2(c.query)} ${decode2(c.body)}`; return SQLI.some((r) => r.test(t)); } },
  { id: 'path_traversal', severity: 'high', weight: 40,
    test: (c) => TRAVERSAL.test(`${decode2(c.path)} ${decode2(c.query)}`) },
  { id: 'scanner_ua', severity: 'medium', weight: 25,
    test: (c) => SCANNERS.test(c.userAgent || '') },
  { id: 'rate_flood', severity: 'medium', weight: 30,
    test: (c, t, counters) => counters.incrBy(`rate:${c.ipHash}`, 1, 60) > t.reqRateMax },
  { id: 'brute_force', severity: 'high', weight: 70,
    test: (c, t, counters) => c.isLoginFailure && counters.incrBy(`login:${c.ipHash}`, 1, t.loginWindowSec) > t.loginFailMax },
];

class DetectionEngine {
  constructor({ counters, getSettings }) {
    this.counters = counters;
    this.getSettings = getSettings;
  }

  /**
   * ctx: { ipHash, path, method, query, body, userAgent, isLoginFailure }
   * returns { hits:[{rule_id,severity,score}], total, cumulative, action: none|logged|warned|blocked }
   */
  evaluate(ctx, { only } = {}) {
    const s = this.getSettings();
    const t = SENSITIVITY[s.sensitivity];
    const hits = [];
    for (const r of RULES) {
      if (only && !only.includes(r.id)) continue;
      if (s.rules[r.id] && s.rules[r.id].enabled === false) continue;
      if (r.test(ctx, t, this.counters)) {
        hits.push({ rule_id: r.id, severity: r.severity, score: s.rules[r.id] ? s.rules[r.id].weight : r.weight });
      }
    }
    if (!hits.length) return { hits, total: 0, cumulative: 0, action: 'none' };
    const total = hits.reduce((a, h) => a + h.score, 0);
    const cumulative = this.counters.incrBy(`score:${ctx.ipHash}`, total, 600);
    let action = 'logged';
    if (s.mode !== 'monitor') action = 'warned';
    if (s.mode === 'enforce' && cumulative >= t.blockScore) action = 'blocked';
    return { hits, total, cumulative, action };
  }
}

module.exports = { DetectionEngine, SENSITIVITY, RULES };
