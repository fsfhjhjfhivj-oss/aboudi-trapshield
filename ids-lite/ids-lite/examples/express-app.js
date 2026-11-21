'use strict';
// Run:  IDS_HMAC_KEY=change-me-please-0123456789 IDS_ADMIN_TOKEN=admin-secret IDS_INGEST_SECRET=ingest-secret npm start
const express = require('express');
const { createIds, rawBodySaver } = require('../src');

const app = express();
app.set('trust proxy', 'loopback'); // IMPORTANT: configure this correctly behind a reverse proxy, or req.ip is wrong/spoofable

const ids = createIds({
  hmacKey: process.env.IDS_HMAC_KEY || 'dev-only-hmac-key-change-me-0123456789',
  adminToken: process.env.IDS_ADMIN_TOKEN || 'dev-admin-token',
  ingestSecret: process.env.IDS_INGEST_SECRET || 'dev-ingest-secret',
  dataDir: process.env.IDS_DATA_DIR || './.ids-data',
  basePath: '/ids',
});

app.use(express.json({ verify: rawBodySaver })); // body parser first (the engine inspects JSON bodies); rawBodySaver lets signed endpoints verify HMAC
app.use(ids.middleware);      // enforcement + detection
app.use('/ids', ids.router);  // REST API + /ids/static/banner.js

app.get('/', (_req, res) => res.send(`<!doctype html><html lang="en"><body>
  <h1>Protected site</h1><p>Try: /?q=1' OR 1=1--</p>
  <script src="/ids/static/banner.js" defer></script></body></html>`));

app.post('/login', async (req, res) => {
  const ok = req.body && req.body.user === 'admin' && req.body.pass === 'secret';
  if (!ok) { await req.ids.loginFailed(); return res.status(401).json({ error: 'invalid credentials' }); }
  res.json({ ok: true });
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => console.log(`demo on http://localhost:${port}  (mode: ${ids.settings.get().mode})`));
