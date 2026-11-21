# ids-lite

Lightweight **intrusion detection and site alert addon** for website owners.
Rule-based detection, adjustable sensitivity, temporary IP blocks, a visitor warning banner, activity log,
durable storage, admin REST API and dashboard data. Zero runtime dependencies (Express is a peer dependency).

> ids-lite is a tripwire, **not a WAF**. It complements input validation, patching and TLS; it does not replace them.

## Features
- **Detection rules:** SQL injection patterns, path traversal, scanner user-agents, request flooding, login brute force
- **Adjustable sensitivity:** `low | medium | high` + per-rule enable/weight
- **Modes:** `monitor` (log only, default) -> `warn` (banner) -> `enforce` (temporary blocks)
- **Temporary blocks** with automatic expiry and escalation for repeat offenders
- **Warning banner:** accessible Web Component (`role=alert/status`, Shadow DOM, throttled polling with backoff)
- **Activity log + audit trail**, durable (JSONL + atomic JSON), per-change settings backups
- **Privacy:** IPs stored as HMAC hashes, redacted evidence, retention, raw-IP scrubbing, key rotation
- **Language-agnostic:** Node/Express middleware, plus a signed sidecar endpoint for Django/Flask/PHP/etc.

## Quick start (Express)
```bash
git clone <your-repo-url> && cd ids-lite && npm install && npm start   # demo app on http://localhost:3000
# once published to npm:  npm install ids-lite express
```
```js
const express = require('express');
const { createIds, rawBodySaver } = require('ids-lite');

const app = express();
app.set('trust proxy', 'loopback');           // configure for YOUR proxy chain

const ids = createIds({
  hmacKey: process.env.IDS_HMAC_KEY,          // >= 16 chars, secret
  adminToken: process.env.IDS_ADMIN_TOKEN,    // or adminAuth: (req) => yourSessionCheck(req)
  ingestSecret: process.env.IDS_INGEST_SECRET,
  dataDir: './.ids-data',
});

app.use(express.json({ verify: rawBodySaver }));  // body parser first
app.use(ids.middleware);                          // detection + enforcement
app.use('/ids', ids.router);                      // REST API + /ids/static/banner.js

app.post('/login', async (req, res) => {
  if (!(await checkCredentials(req.body))) { await req.ids.loginFailed(); return res.sendStatus(401); }
  res.sendStatus(200);
});
```
Add the banner to your layout: `<script src="/ids/static/banner.js" defer></script>`.
Customize/translate messages with `window.IDS_MESSAGES = { unusual_activity: '...', temporarily_blocked: '...' }` before the script.

**Rollout advice:** run in `monitor` for 1-2 weeks, review `GET /ids/v1/events`, tune sensitivity/exclusions, then switch to `warn` and `enforce`
(`PUT /ids/v1/settings` with `If-Match`).

## Other languages (Django / Flask / ...)
Run the Node service (or embed it) and use the signed sidecar endpoint `POST /ids/v1/adapter/evaluate`.
See `examples/python_adapter.py` (stdlib only, fail-open, 250 ms timeout) for Django middleware and a Flask `before_request` hook.

Signature: `X-IDS-Signature: sha256=hex(HMAC_SHA256(ingestSecret, X-IDS-Timestamp + "." + rawBody))`, `X-IDS-Timestamp` = epoch ms (+/-5 min).

## Configuration (`GET/PUT /ids/v1/settings`)
| Key | Default | Notes |
|---|---|---|
| `enabled` | `true` | master switch |
| `mode` | `monitor` | `monitor` / `warn` / `enforce` |
| `sensitivity` | `medium` | low (block score 90) / medium (70) / high (50) |
| `block_duration_sec` | `900` | doubles per repeat block in 24h |
| `max_block_duration_sec` | `86400` | cap |
| `rules.<id>.{enabled,weight}` | all on | `sqli_pattern 40`, `path_traversal 40`, `scanner_ua 25`, `rate_flood 30`, `brute_force 70` |
| `allowlist_ips` | `[]` | IPs/CIDRs that bypass everything |
| `exclude_paths` | `/health`, `/static/*`, `/ids/*` | glob patterns skipped by detection |
| `retention_days` | `30` | events/blocks purge |
| `store_raw_ip` | `false` | if true, scrubbed after 7 days |
| `banner.enabled` | `true` | visitor banner |
| `fail_mode` | `open` | `closed` returns 503 if the addon errors |

Sensitivity thresholds (per IP): login failures `10/5/3` per 10/5/5 min, requests/min `300/120/60`.

## API summary
Full contract: [`openapi.yaml`](openapi.yaml). Admin auth: `Authorization: Bearer <adminToken>` (or your `adminAuth` hook with CSRF protection if you use cookies).

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/ids/v1/events` | admin | list events (filters + cursor) |
| POST | `/ids/v1/events` | HMAC | ingest an event (idempotent) |
| POST | `/ids/v1/adapter/evaluate` | HMAC | decision for non-Node adapters |
| GET / POST | `/ids/v1/blocks` | admin | list / create manual block |
| DELETE | `/ids/v1/blocks/:id` | admin | lift a block |
| GET / PUT | `/ids/v1/settings` | admin | read / replace (ETag + `If-Match`) |
| GET | `/ids/v1/admin/dashboard?range=24h\|7d\|30d` | admin | totals, series, top IP hashes, threat level |
| GET | `/ids/v1/audit` | admin | audit trail |
| GET | `/ids/v1/public/status` | none | banner status for the current visitor |

## Roadmap
- **MVP (this release):** detection, banner, temporary blocks, logging, persistence, admin API, privacy controls
- **Phase 2:** Redis counters + SQL storage, richer analytics UI, custom rules (YAML), webhooks (Slack/email), admin banner
- **Phase 3:** MFA-failure signals, global rate limiting, IP reputation feeds, official Django/Flask packages

## Docs
[Architecture](docs/ARCHITECTURE.md) · [Operations, privacy, key rotation](docs/OPERATIONS.md) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## Development
```bash
npm install
npm test     # node:test, 25 tests (unit, integration, security, persistence)
```
License: MIT
