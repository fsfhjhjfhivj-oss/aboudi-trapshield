# Architecture

```
Visitor browser           Site server (your app + ids-lite)                    Storage
     |  HTTP request            |
     |------------------------->| (1) ids.middleware
     |                          |     inspect(ctx)
     |                          |       - allowlist / excluded paths -> skip
     |                          |       - active block? (enforce) ---> 429 + Retry-After
     |                          |       - rules: sqli, traversal, scanner UA, rate flood, brute force
     |                          |       - cumulative score per IP (10 min) >= threshold -> create Block
     |                          |       - record ThreatEvent(s) -------------------> events.jsonl
     |<-- response / 429 -------|
     |  GET /ids/v1/public/status (throttled, backoff) -> {level, message_key, block_until}
     |  <ids-warning-banner> renders (role=alert / status)

Admin (Bearer token or your session) -> /ids/v1/{events,blocks,settings,admin/dashboard,audit}
Other languages (Django/Flask/PHP) -> POST /ids/v1/adapter/evaluate (HMAC-signed) -> decision {action, retry_after}
```

## Modules
| File | Responsibility |
|---|---|
| `src/engine.js` | Rules, sensitivity thresholds, scoring (pure logic, no I/O) |
| `src/ids.js` | `inspect()` decision function, key handling, retention, banner status |
| `src/blocks.js` | Temporary blocks, escalation, expiry |
| `src/events.js` | ThreatEvent recording and queries |
| `src/settings.js` | Defaults, validation, ETag concurrency, audit diff, per-change backup |
| `src/repo.js` | Durable storage (JSONL + atomic JSON). Replace with SQL for large sites |
| `src/counters.js` | Fixed-window counters (replace with Redis for multi-process) |
| `src/api.js` | REST API + static banner |
| `src/middleware.js` | Express adapter |
| `public/banner.js` | `<ids-warning-banner>` Web Component |

## Decision rules
- Score per rule (weights configurable). Per-IP cumulative score over a 10-minute fixed window.
- `monitor`: log only. `warn`: log + visitor notice. `enforce`: log + notice + block at `blockScore`
  (low 90 / medium 70 / high 50).
- Block duration = `block_duration_sec` x 2^(blocks in last 24h), capped at `max_block_duration_sec`.
- Threat level (dashboard): `critical` = >= 20 high-severity events in 15 min; `elevated` = >= 5 events in 15 min; else `calm`.

## Known limits (MVP)
- Counters are per process (use Redis for clusters). Fixed windows, not sliding.
- Storage keeps up to 100k events in memory; rewrite `Repo` for SQL at larger scale.
- Pattern rules are a baseline tripwire; expect some false negatives and tune via `monitor` mode first.
