'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { DetectionEngine } = require('../src/engine');
const { CounterStore } = require('../src/counters');
const { DEFAULTS } = require('../src/settings');
const { redactString } = require('../src/redact');

const mk = (patch = {}) => {
  const s = { ...JSON.parse(JSON.stringify(DEFAULTS)), ...patch };
  return new DetectionEngine({ counters: new CounterStore(), getSettings: () => s });
};
const ctx = (o = {}) => ({ ipHash: 'h1', path: '/', method: 'GET', query: '', body: '', userAgent: 'Mozilla', ...o });

test('benign requests produce no hits', () => {
  const e = mk();
  for (const q of ['q=hello', 'page=2&sort=asc', 'q=rock+-+roll', 'name=O%27Brien']) assert.equal(e.evaluate(ctx({ query: q })).hits.length, 0, q);
});

test('detects sqli (incl. double encoding), traversal, scanner UA', () => {
  const e = mk();
  assert.equal(e.evaluate(ctx({ ipHash: 'a', query: "q=1' OR 1=1" })).hits[0].rule_id, 'sqli_pattern');
  assert.equal(e.evaluate(ctx({ ipHash: 'b', query: 'q=%2527%2520OR%25201%253D1' })).hits[0].rule_id, 'sqli_pattern');
  assert.equal(e.evaluate(ctx({ ipHash: 'c', query: 'f=../../etc/passwd' })).hits[0].rule_id, 'path_traversal');
  assert.equal(e.evaluate(ctx({ ipHash: 'd', userAgent: 'sqlmap/1.7' })).hits[0].rule_id, 'scanner_ua');
});

test('sensitivity changes the rate_flood threshold', () => {
  const hi = mk({ sensitivity: 'high' }); // 60 req/min
  const lo = mk({ sensitivity: 'low' });  // 300 req/min
  let hiHit = 0; let loHit = 0;
  for (let i = 0; i < 100; i++) {
    if (hi.evaluate(ctx()).hits.some((h) => h.rule_id === 'rate_flood')) hiHit++;
    if (lo.evaluate(ctx()).hits.some((h) => h.rule_id === 'rate_flood')) loHit++;
  }
  assert.equal(hiHit, 40);
  assert.equal(loHit, 0);
});

test('disabled rule never fires; monitor mode never blocks', () => {
  const s = JSON.parse(JSON.stringify(DEFAULTS));
  s.rules.sqli_pattern.enabled = false;
  const e = new DetectionEngine({ counters: new CounterStore(), getSettings: () => s });
  assert.equal(e.evaluate(ctx({ query: "' OR 1=1" })).hits.length, 0);
  const m = mk();
  for (let i = 0; i < 10; i++) assert.notEqual(m.evaluate(ctx({ userAgent: 'nikto', query: "' OR 1=1" })).action, 'blocked');
});

test('redaction hides secrets in evidence', () => {
  const r = redactString('q=1&password=hunter2&token=abc123 {"api_key":"zzz"}');
  assert.ok(!/hunter2|abc123|zzz/.test(r));
  assert.ok(r.includes('[redacted]'));
});
