'use strict';

/**
 * Fixed-window counters with TTL (in memory).
 * For multi-process deployments, implement the same interface on Redis (INCRBY + EXPIRE NX).
 */
class CounterStore {
  constructor(now = Date.now) {
    this.now = now;
    this.m = new Map();
    this._ops = 0;
  }

  incrBy(key, n, ttlSec) {
    const t = this.now();
    let e = this.m.get(key);
    if (!e || e.exp <= t) e = { v: 0, exp: t + ttlSec * 1000 };
    e.v += n;
    this.m.set(key, e);
    if ((++this._ops & 1023) === 0) this.sweep();
    return e.v;
  }

  sweep() {
    const t = this.now();
    for (const [k, e] of this.m) if (e.exp <= t) this.m.delete(k);
  }
}

module.exports = { CounterStore };
