'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { Ids } = require('../src/ids');
const { tmpDir, KEY } = require('./helpers');

const mkIds = (dir, extra = {}) => { const clock = extra.clock || { t: 1_800_000_000_000 }; return { clock, ids: new Ids({ hmacKey: KEY, dataDir: dir, now: () => clock.t, ...extra }) }; };

test('blocks, events and settings survive a restart', () => {
  const dir = tmpDir();
  const a = mkIds(dir);
  a.ids.settings.update({ ...a.ids.settings.get(), mode: 'enforce' }, { ifVersion: 1 });
  a.ids.inspect({ ip: '198.51.100.1', method: 'GET', path: '/', query: "' OR 1=1--" });
  a.ids.inspect({ ip: '198.51.100.1', method: 'GET', path: '/', query: "' OR 1=1--" });
  assert.equal(a.ids.blocks.activeCount(), 1);
  const b = mkIds(dir, { clock: a.clock });
  assert.equal(b.ids.settings.get().mode, 'enforce');
  assert.equal(b.ids.blocks.activeCount(), 1);
  assert.equal(b.ids.inspect({ ip: '198.51.100.1', method: 'GET', path: '/' }).action, 'blocked');
  assert.ok(b.ids.repo.events.length >= 2);
  assert.ok(fs.existsSync(path.join(dir, 'backups', 'settings-v2.json')));   // config backup per change
});

test('key rotation: blocks made under the old key still match', () => {
  const dir = tmpDir();
  const a = mkIds(dir);
  a.ids.settings.update({ ...a.ids.settings.get(), mode: 'enforce' }, { ifVersion: 1 });
  for (let i = 0; i < 2; i++) a.ids.inspect({ ip: '198.51.100.2', method: 'GET', path: '/', query: "' OR 1=1--" });
  const b = mkIds(dir, { hmacKey: undefined, hmacKeys: [{ version: 2, key: 'new-rotated-key-0123456789abcd' }, { version: 1, key: KEY }], clock: a.clock });
  assert.equal(b.ids.inspect({ ip: '198.51.100.2', method: 'GET', path: '/' }).action, 'blocked');
  // after the overlap window, drop the old key: the old block no longer matches (and has expired anyway)
  const c = mkIds(dir, { hmacKey: undefined, hmacKeys: [{ version: 2, key: 'new-rotated-key-0123456789abcd' }], clock: a.clock });
  assert.equal(c.ids.inspect({ ip: '198.51.100.2', method: 'GET', path: '/' }).action, 'none');
});

test('retention: old events purged, raw IPs scrubbed after 7 days', () => {
  const dir = tmpDir();
  const a = mkIds(dir);
  a.ids.settings.update({ ...a.ids.settings.get(), store_raw_ip: true, retention_days: 30 }, { ifVersion: 1 });
  a.ids.inspect({ ip: '198.51.100.3', method: 'GET', path: '/', query: "' OR 1=1--" });
  assert.equal(a.ids.repo.events[0].ip_raw, '198.51.100.3');
  a.clock.t += 8 * 86400000; a.ids.purge();
  assert.equal(a.ids.repo.events.length, 1);
  assert.equal(a.ids.repo.events[0].ip_raw, null);
  a.clock.t += 30 * 86400000; a.ids.purge();
  assert.equal(a.ids.repo.events.length, 0);
});

test('constructor rejects weak or missing keys', () => {
  assert.throws(() => new Ids({}));
  assert.throws(() => new Ids({ hmacKey: 'short' }));
});
