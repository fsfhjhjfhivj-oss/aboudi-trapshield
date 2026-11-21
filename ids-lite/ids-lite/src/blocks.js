'use strict';
const crypto = require('crypto');

class BlockService {
  constructor(repo, now = Date.now) {
    this.repo = repo;
    this.now = now;
    this.dirty = false;
  }

  /** hashes: all candidate hashes of one IP (one per active key version). */
  findActive(hashes) {
    const t = this.now();
    for (const b of this.repo.blocks) {
      if (b.status === 'active' && b.expires_at > t && hashes.includes(b.ip_hash)) return b;
    }
    return null;
  }

  create({ ip_hash, key_version, reason, duration_sec, created_by }) {
    const t = this.now();
    const b = {
      id: crypto.randomUUID(), ip_hash, key_version, reason,
      created_at: t, expires_at: t + duration_sec * 1000,
      created_by, status: 'active', lifted_by: null, lifted_at: null, hit_count: 0,
    };
    this.repo.blocks.push(b);
    this.repo.saveBlocks();
    return b;
  }

  hit(id) {
    const b = this.repo.blocks.find((x) => x.id === id);
    if (b) { b.hit_count += 1; this.dirty = true; } // flushed periodically, not per request
  }

  countRecent(hashes, windowMs = 24 * 3600 * 1000) {
    const since = this.now() - windowMs;
    return this.repo.blocks.filter((b) => hashes.includes(b.ip_hash) && b.created_at >= since).length;
  }

  lift(id, actor) {
    const b = this.repo.blocks.find((x) => x.id === id);
    if (!b) return null;
    if (b.status === 'active') {
      b.status = 'lifted'; b.lifted_by = actor; b.lifted_at = this.now();
      this.repo.saveBlocks();
    }
    return b;
  }

  sweepExpired() {
    const t = this.now();
    let changed = false;
    for (const b of this.repo.blocks) if (b.status === 'active' && b.expires_at <= t) { b.status = 'expired'; changed = true; }
    if (changed || this.dirty) { this.repo.saveBlocks(); this.dirty = false; }
  }

  list({ status, limit = 50, cursor = 0 } = {}) {
    this.sweepExpired();
    const all = this.repo.blocks.filter((b) => !status || b.status === status).sort((a, b) => b.created_at - a.created_at);
    const items = all.slice(cursor, cursor + limit);
    return { items, next_cursor: cursor + limit < all.length ? String(cursor + limit) : null };
  }

  activeCount() {
    const t = this.now();
    return this.repo.blocks.filter((b) => b.status === 'active' && b.expires_at > t).length;
  }

  purge(cutoff) {
    const before = this.repo.blocks.length;
    this.repo.blocks = this.repo.blocks.filter((b) => b.status === 'active' || b.created_at >= cutoff);
    if (this.repo.blocks.length !== before) this.repo.saveBlocks();
  }
}

module.exports = { BlockService };
