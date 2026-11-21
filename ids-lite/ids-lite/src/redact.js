'use strict';

const KV = /\b(pass(?:word)?|pwd|token|secret|api[_-]?key|authorization|session(?:id)?|card|cvv|ssn)=([^&\s]+)/gi;
const JSON_KV = /("(?:pass(?:word)?|pwd|token|secret|api_?key|authorization|card|cvv|ssn)"\s*:\s*)"[^"]*"/gi;

function redactString(s, max = 200) {
  return String(s == null ? '' : s)
    .replace(KV, '$1=[redacted]')
    .replace(JSON_KV, '$1"[redacted]"')
    .slice(0, max);
}

function buildEvidence(ctx) {
  return {
    snippet: redactString(ctx.query || ctx.body || ''),
    ua: String(ctx.userAgent || '').slice(0, 120),
  };
}

module.exports = { redactString, buildEvidence };
