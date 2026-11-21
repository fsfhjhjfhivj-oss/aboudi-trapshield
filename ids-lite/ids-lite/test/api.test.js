'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer, closeAll, ATTACKER, SQLI } = require('./helpers');

test.after(() => closeAll());

test('monitor mode logs but never blocks or warns', async () => {
  const s = await startServer();
  for (let i = 0; i < 5; i++) { const r = await s.http(SQLI, { ip: ATTACKER }); assert.equal(r.status, 200); assert.equal(r.headers.get('x-ids-level'), null); }
  const ev = await s.adminJson('/ids/v1/events');
  assert.equal(ev.status, 200);
  assert.ok(ev.body.items.length >= 5);
  assert.equal(ev.body.items[0].rule_id, 'sqli_pattern');
  assert.equal(ev.body.items[0].action, 'logged');
  assert.equal(ev.body.items[0].ip_raw, null);               // raw IP is not stored by default
  assert.match(ev.body.items[0].ip_hash, /^[0-9a-f]{64}$/);
  assert.equal((await s.adminJson('/ids/v1/blocks?status=active')).body.items.length, 0);
  await s.close();
});

test('enforce mode: repeated attack gets a temporary block with Retry-After; other IPs unaffected', async () => {
  const s = await startServer();
  s.setSettings({ mode: 'enforce' });
  const r1 = await s.http(SQLI, { ip: ATTACKER });
  assert.equal(r1.status, 200);
  assert.equal(r1.headers.get('x-ids-level'), 'warned');
  const r2 = await s.http(SQLI, { ip: ATTACKER });
  assert.equal(r2.status, 429);
  assert.equal(r2.headers.get('retry-after'), '900');
  assert.equal((await s.http('/', { ip: ATTACKER })).status, 429);
  assert.equal((await s.http('/', { ip: '198.51.100.9' })).status, 200);
  await s.close();
});

test('blocked visitor can still read banner status', async () => {
  const s = await startServer();
  s.setSettings({ mode: 'enforce' });
  await s.http(SQLI, { ip: ATTACKER }); await s.http(SQLI, { ip: ATTACKER });
  const r = await s.http('/ids/v1/public/status', { ip: ATTACKER });
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.deepEqual(Object.keys(j).sort(), ['block_until', 'level', 'message_key', 'poll_after_sec']);
  assert.equal(j.level, 'blocked');
  assert.ok(Date.parse(j.block_until) > s.clock.t);
  assert.equal((await (await s.http('/ids/v1/public/status', { ip: '198.51.100.9' })).json()).level, 'none');
  await s.close();
});

test('warn mode shows a notice to the visitor', async () => {
  const s = await startServer();
  s.setSettings({ mode: 'warn' });
  await s.http(SQLI, { ip: ATTACKER });
  assert.equal((await (await s.http('/ids/v1/public/status', { ip: ATTACKER })).json()).level, 'notice');
  await s.close();
});

test('block expires and the duration escalates on repeat offences', async () => {
  const s = await startServer();
  s.setSettings({ mode: 'enforce' });
  await s.http(SQLI, { ip: ATTACKER }); await s.http(SQLI, { ip: ATTACKER });
  s.clock.t += 901 * 1000;                                       // first block (900s) has expired
  assert.equal((await s.http('/', { ip: ATTACKER })).status, 200);
  await s.http(SQLI, { ip: ATTACKER }); await s.http(SQLI, { ip: ATTACKER });
  const list = (await s.adminJson('/ids/v1/blocks')).body.items;
  assert.equal(list.length, 2);
  const durs = list.map((b) => (Date.parse(b.expires_at) - Date.parse(b.created_at)) / 1000).sort((a, b) => a - b);
  assert.deepEqual(durs, [900, 1800]);
  assert.ok(list.some((b) => b.status === 'expired'));
  await s.close();
});

test('brute force on login triggers a block in enforce mode', async () => {
  const s = await startServer();
  s.setSettings({ mode: 'enforce' });
  for (let i = 0; i < 6; i++) await s.http('/login', { method: 'POST', ip: ATTACKER, body: { u: 'x' } });
  assert.equal((await s.http('/', { ip: ATTACKER })).status, 429);
  await s.close();
});

test('allowlisted IPs bypass detection and blocking', async () => {
  const s = await startServer();
  s.setSettings({ mode: 'enforce', allowlist_ips: ['203.0.113.0/24'] });
  for (let i = 0; i < 5; i++) assert.equal((await s.http(SQLI, { ip: ATTACKER })).status, 200);
  await s.close();
});

test('admin can list, create, lift blocks; cannot block self; duration capped', async () => {
  const s = await startServer();
  s.setSettings({ mode: 'enforce' });
  const hash = s.ids.hashIp('198.51.100.50').hash;
  const c = await s.adminJson('/ids/v1/blocks', { method: 'POST', body: { ip_hash: hash, reason: 'manual', duration_sec: 600 } });
  assert.equal(c.status, 201);
  assert.equal((await s.http('/', { ip: '198.51.100.50' })).status, 429);
  assert.equal((await s.adminJson('/ids/v1/blocks', { method: 'POST', body: { ip: '127.0.0.1' } })).body.error.code, 'SELF_BLOCK');
  assert.equal((await s.adminJson('/ids/v1/blocks', { method: 'POST', body: { ip_hash: hash, duration_sec: 99999999 } })).status, 400);
  assert.equal((await s.adminJson(`/ids/v1/blocks/${c.body.id}`, { method: 'DELETE' })).body.status, 'lifted');
  assert.equal((await s.http('/', { ip: '198.51.100.50' })).status, 200);
  const audit = (await s.adminJson('/ids/v1/audit')).body.items.map((a) => a.action);
  assert.ok(audit.includes('block.create') && audit.includes('block.lift'));
  await s.close();
});

test('admin endpoints require auth', async () => {
  const s = await startServer();
  for (const p of ['/ids/v1/events', '/ids/v1/blocks', '/ids/v1/settings', '/ids/v1/admin/dashboard', '/ids/v1/audit']) {
    assert.equal((await s.http(p)).status, 401, p);
    assert.equal((await s.http(p, { headers: { Authorization: 'Bearer wrong' } })).status, 401, p);
  }
  await s.close();
});

test('settings: ETag concurrency, validation, audit trail', async () => {
  const s = await startServer();
  const g = await s.adminJson('/ids/v1/settings');
  assert.equal(g.res.headers.get('etag'), '"v1"');
  assert.equal(g.body.mode, 'monitor');
  const put = (body, etag) => s.adminJson('/ids/v1/settings', { method: 'PUT', body, headers: etag ? { 'If-Match': etag } : {} });
  assert.equal((await put({ ...g.body, sensitivity: 'high' })).status, 428);
  assert.equal((await put({ ...g.body, sensitivity: 'high' }, '"v9"')).status, 412);
  assert.equal((await put({ ...g.body, mode: 'nope' }, '"v1"')).status, 422);
  const ok = await put({ ...g.body, sensitivity: 'high' }, '"v1"');
  assert.equal(ok.status, 200);
  assert.equal(ok.body.version, 2);
  assert.equal(ok.res.headers.get('etag'), '"v2"');
  assert.equal((await put({ ...g.body, sensitivity: 'low' }, '"v1"')).status, 412);
  assert.equal((await s.adminJson('/ids/v1/audit')).body.items[0].action, 'settings.update');
  await s.close();
});

test('signed ingest: valid, duplicate, bad signature, stale timestamp', async () => {
  const s = await startServer();
  const ev = { rule_id: 'custom', severity: 'low', score: 5, ip_hash: 'a'.repeat(64), idempotency_key: 'k1', method: 'GET', path: '/x' };
  const a = await s.signed('/ids/v1/events', ev);
  assert.equal(a.status, 201);
  const id = (await a.json()).id;
  const dup = await s.signed('/ids/v1/events', ev);
  assert.equal(dup.status, 409);
  assert.equal((await dup.json()).id, id);
  assert.equal((await s.signed('/ids/v1/events', { ...ev, idempotency_key: 'k2' }, { secret: 'wrong-secret' })).status, 401);
  assert.equal((await s.signed('/ids/v1/events', { ...ev, idempotency_key: 'k3' }, { ts: String(s.clock.t - 10 * 60 * 1000) })).status, 401);
  assert.equal((await s.signed('/ids/v1/events', { ...ev, idempotency_key: 'k4', score: 500 })).status, 422);
  assert.equal((await s.http('/ids/v1/events', { method: 'POST', body: ev })).status, 401);
  await s.close();
});

test('adapter/evaluate: sidecar contract for non-Node frameworks', async () => {
  const s = await startServer();
  s.setSettings({ mode: 'enforce' });
  const call = async (extra = {}) => (await s.signed('/ids/v1/adapter/evaluate', { ip: '198.51.100.77', method: 'GET', path: '/search', query: "q=' OR 1=1--", user_agent: 'x', ...extra })).json();
  assert.equal((await call()).action, 'warned');
  const d = await call();
  assert.equal(d.action, 'blocked');
  assert.equal(d.retry_after, 900);
  assert.equal((await s.http('/', { ip: '198.51.100.77' })).status, 429);
  await s.close();
});

test('dashboard aggregates events', async () => {
  const s = await startServer();
  for (let i = 0; i < 6; i++) await s.http(SQLI, { ip: ATTACKER });
  const d = (await s.adminJson('/ids/v1/admin/dashboard?range=24h')).body;
  assert.equal(d.totals.events, 6);
  assert.equal(d.by_rule[0].rule_id, 'sqli_pattern');
  assert.equal(d.threat_level, 'elevated');
  assert.equal(d.top_ip_hashes.length, 1);
  await s.close();
});

test('fail-open by default, fail-closed when configured', async () => {
  const s = await startServer();
  s.ids.inspect = () => { throw new Error('boom'); };
  assert.equal((await s.http('/')).status, 200);
  s.setSettings({ fail_mode: 'closed' });
  assert.equal((await s.http('/')).status, 503);
  await s.close();
});

test('banner script is served', async () => {
  const s = await startServer();
  const r = await s.http('/ids/static/banner.js');
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-type'), /javascript/);
  await s.close();
});

test('malformed JSON returns 400, not a stack trace', async () => {
  const s = await startServer();
  const r = await s.http('/ids/v1/settings', { method: 'PUT', admin: true, body: '{bad', headers: { 'If-Match': '"v1"' } });
  assert.ok([400].includes(r.status) || r.status === 400);
  await s.close();
});
