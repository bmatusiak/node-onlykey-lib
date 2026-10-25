/*
 * The bucket service (bucket/cli/service.js): a change to this computer's kept bucket is traded once a burst of writes
 * settles; the trade's own write is not traded again (no loop); a change during a trade is traded after it.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { startBucketService } = require('../cli/service');

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

test('a change is traded once its burst settles; the trade\'s own write is not traded again', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'okbucket-svc-'));
  const file = path.join(dir, 'ab.json');
  fs.writeFileSync(file, '{"v":1}');
  let fire = null;
  const watch = (d, cb) => { fire = cb; return { close() {} }; };
  const trades = [];
  const svc = startBucketService({
    dir, watch, debounceMs: 30, intervalMs: 60000,
    tradeOnce: async () => { trades.push(Date.now()); fs.writeFileSync(file, `{"v":"traded ${trades.length}"}`); return { traded: true, taken: {}, gave: {} }; },
  });
  /* a burst of three writes: one trade */
  for (const v of [2, 3, 4]) { fs.writeFileSync(file, `{"v":${v}}`); fire(); }
  await wait(120);
  assert.equal(trades.length, 1);
  /* the trade wrote the file: its own write fires the watcher, and is skipped */
  fire();
  await wait(120);
  assert.equal(trades.length, 1, 'no loop on its own write');
  /* a real change later: traded */
  fs.writeFileSync(file, '{"v":5}');
  fire();
  await wait(120);
  assert.equal(trades.length, 2);
  svc.stop();
});

test('a trade asked while one runs runs once more after it - never two at once', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'okbucket-svc-'));
  let active = 0; let most = 0; let count = 0;
  const svc = startBucketService({
    dir, watch: () => ({ close() {} }), intervalMs: 60000,
    tradeOnce: async () => { active++; most = Math.max(most, active); count++; await wait(40); active--; return { traded: false, why: 'test' }; },
  });
  const first = svc.trade('one');
  svc.trade('two');
  svc.trade('three');
  await first;
  await wait(100);
  assert.equal(most, 1, 'one at a time');
  assert.equal(count, 2, 'the asks during the first trade became one more trade');
  svc.stop();
});
