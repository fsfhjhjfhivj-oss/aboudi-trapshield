# Security Policy

## Reporting a vulnerability
Please do **not** open a public issue. Use GitHub's "Report a vulnerability" (Security tab -> Advisories)
or email the maintainers. We aim to acknowledge within 72 hours.

## Scope and limits
ids-lite is a lightweight tripwire (rule-based detection + temporary blocks). It is **not** a WAF and does not
replace input validation, parameterized queries, patching, TLS or a real WAF/CDN in front of high-risk sites.

## Hardening checklist
- Keep `hmacKey`, `ingestSecret`, `adminToken` in a secret manager / env vars, never in git.
- Configure the proxy chain correctly (`app.set('trust proxy', ...)`): a wrong value lets attackers spoof their IP.
- Start in `monitor`, review events for 1-2 weeks, then move to `warn` and `enforce`.
- Put your own admin IPs in `allowlist_ips`.
- Serve the API only over HTTPS; restrict `/ids/v1/*` (except `public/` and `static/`) at the reverse proxy if possible.
