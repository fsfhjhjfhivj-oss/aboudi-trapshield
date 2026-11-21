# Contributing

1. Fork, create a branch, `npm install`, `npm test` (Node >= 18, no extra tooling).
2. New detection rules go in `src/engine.js` (`RULES`) with: a positive test, a **negative (false-positive) test**, and a weight in `src/settings.js`.
3. Never log or store secrets / raw IPs by default. Redact evidence (`src/redact.js`).
4. Keep the core framework-agnostic: framework code lives in `src/middleware.js` / `examples/`.
5. Open a PR describing behavior changes, config changes and migration notes.
