'use strict';
const crypto = require('crypto');

/** HMAC-SHA256 of an IP address. Raw IPs are never stored by default. */
function hashIp(ip, key) {
  return crypto.createHmac('sha256', key).update(String(ip)).digest('hex');
}

/** Signature scheme for adapter -> service calls: sha256=hex(HMAC(secret, ts + "." + rawBody)) */
function sign(rawBody, ts, secret) {
  return 'sha256=' + crypto.createHmac('sha256', secret).update(`${ts}.${rawBody}`).digest('hex');
}

function verify(rawBody, ts, signature, secret, { now = Date.now, skewMs = 5 * 60 * 1000 } = {}) {
  if (!signature || !ts || !secret) return false;
  const t = Number(ts);
  if (!Number.isFinite(t) || Math.abs(now() - t) > skewMs) return false;
  const a = Buffer.from(sign(rawBody, ts, secret));
  const b = Buffer.from(String(signature));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/** Constant-time string compare that does not leak length. */
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

module.exports = { hashIp, sign, verify, safeEqual };
