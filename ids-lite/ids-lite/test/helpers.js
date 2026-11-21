'use strict';
const express = require('express');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { createIds, sign, rawBodySaver } = require('../src');
const opened = [];

const KEY = 'test-hmac-key-0123456789abcdef';
const ADMIN = 'test-admin-token';
const INGEST = 'test-ingest-secret';
const ATTACKER = '203.0.113.7';
const SQLI = "/?q=%27%20OR%201%3D1--";

async function startServer(opts = {}) {
  const clock = { t: 1_800_000_000_000 };
  const ids = createIds({ hmacKey: KEY, adminToken: ADMIN, ingestSecret: INGEST, now: () => clock.t, ...opts });
  const app = express();
  app.set('trust proxy', true); // tests simulate client IPs through X-Forwarded-For
  app.use(express.json({ verify: rawBodySaver }));
  app.use(ids.middleware);
  app.use('/ids', ids.router);
  app.get('/', (_req, res) => res.send('ok'));
  app.post('/login', async (req, res) => { await req.ids.loginFailed(); res.status(401).json({ error: 'nope' }); });
  const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  let closed = false;

  const http = (p, { method = 'GET', ip, admin, body, headers = {} } = {}) => fetch(base + p, {
    method,
    headers: {
      ...(ip ? { 'X-Forwarded-For': ip } : {}),
      ...(admin ? { Authorization: `Bearer ${ADMIN}` } : {}),
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
    body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)),
  });
  const adminJson = async (p, o = {}) => { const r = await http(p, { ...o, admin: true }); return { status: r.status, body: await r.json(), res: r }; };
  const setSettings = (patch) => { const cur = ids.settings.get(); const r = ids.settings.update({ ...cur, ...patch }, { ifVersion: cur.version }); if (!r.ok) throw new Error(JSON.stringify(r.errors)); return r.settings; };
  const signed = (p, payload, { secret = INGEST, ts = String(clock.t) } = {}) => {
    const raw = JSON.stringify(payload);
    return http(p, { method: 'POST', body: raw, headers: { 'X-IDS-Timestamp': ts, 'X-IDS-Signature': sign(raw, ts, secret) } });
  };
  const close = () => { if (closed) return Promise.resolve(); closed = true; ids.stop(); return new Promise((r) => { server.close(r); if (server.closeAllConnections) server.closeAllConnections(); }); };
  const handle = { ids, clock, base, http, adminJson, setSettings, signed, close };
  opened.push(handle);
  return handle;
}

const tmpDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'ids-lite-'));
const closeAll = () => Promise.all(opened.map((h) => h.close()));
module.exports = { closeAll, startServer, tmpDir, KEY, ADMIN, INGEST, ATTACKER, SQLI };
