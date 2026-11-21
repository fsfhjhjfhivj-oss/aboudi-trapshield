'use strict';

function buildCtx(req) {
  const q = req.originalUrl.indexOf('?');
  let body = '';
  if (req.body !== undefined && req.body !== null) {
    body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    body = body.slice(0, 2048);
  }
  return {
    ip: req.ip, method: req.method, path: req.path,
    query: q >= 0 ? req.originalUrl.slice(q + 1, q + 1 + 2048) : '',
    body, userAgent: req.get('user-agent') || '', isLoginFailure: false,
  };
}

function reject(res, retryAfter) {
  res.set('Retry-After', String(retryAfter));
  res.set('Cache-Control', 'no-store');
  res.status(429).json({ error: { code: 'IDS_BLOCKED', message: 'Temporarily blocked', retry_after: retryAfter } });
}

/** Express middleware. Mount AFTER your body parser and BEFORE your routes. */
function createMiddleware(ids) {
  const base = ids.opts.basePath;
  return function idsMiddleware(req, res, next) {
    // The banner must keep working for blocked visitors.
    if (req.path.startsWith(`${base}/v1/public/`) || req.path.startsWith(`${base}/static/`)) return next();
    const ctx = buildCtx(req);
    // Call from your login handler after a failed attempt.
    req.ids = { loginFailed: () => { try { return ids.inspect({ ...ctx, isLoginFailure: true }, { only: ['brute_force'] }); } catch { return null; } } };
    try {
      const d = ids.inspect(ctx);
      if (d.action === 'blocked') return reject(res, d.retryAfter || ids.settings.get().block_duration_sec);
      if (d.action === 'warned') res.set('X-IDS-Level', 'warned'); // not exposed in monitor mode
    } catch (err) {
      if (ids.settings.get().fail_mode === 'closed') return res.status(503).json({ error: { code: 'IDS_UNAVAILABLE', message: 'Security layer unavailable' } });
      // fail-open: never take the site down because the addon failed
    }
    next();
  };
}

module.exports = { createMiddleware, buildCtx };
