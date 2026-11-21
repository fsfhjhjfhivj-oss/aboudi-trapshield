# Operations, privacy and key rotation

## Privacy by default
- IPs are stored only as `HMAC-SHA256(ip, key)`. `store_raw_ip` is `false`; if enabled, raw IPs are scrubbed after 7 days.
- Evidence is a redacted snippet (<= 200 chars): `password`, `token`, `secret`, `api_key`, `session`, `card`... are masked.
- No cookies or fingerprinting. The banner endpoint returns only `{level, message_key, block_until, poll_after_sec}`.
- Events are deleted after `retention_days` (default 30). To erase one person's data, delete events/blocks by `ip_hash`.
- Tell your visitors (privacy policy) that security logs are kept for abuse prevention for N days.

## Key rotation (zero downtime)
1. Generate a new key (32+ random bytes). Add it as the **first** entry: `hmacKeys: [{version: 2, key: NEW}, {version: 1, key: OLD}]`.
2. Deploy. New events/blocks use v2; blocks created under v1 still match until they expire (max `max_block_duration_sec`).
3. After that period, remove v1. Rotate `adminToken` and `ingestSecret` the same way (deploy new value to adapters, then to the service).
4. Rotate immediately if a key leaks; old blocks become unmatchable, which is acceptable (they are temporary).

## Backups and audit
- Every settings change writes `backups/settings-v<N>.json` and an `audit.jsonl` entry (actor, diff).
- Back up `dataDir` nightly (encrypted, restricted permissions; files are created with mode 0600).
- Restore settings: copy a `settings-v<N>.json` over `settings.json` and restart.

## Deployment checklist
- HTTPS everywhere; correct `trust proxy`; secrets from env/secret manager; `dataDir` outside the web root.
- Start in `monitor` for 1-2 weeks, review false positives, then `warn`, then `enforce`.
- Allowlist your office/admin IPs. The API refuses to block the requesting admin's own address.
- Behind multiple instances: share counters (Redis) and storage (SQL) before using `enforce`.
