/*
 * The sync service (bucket/cli/service.js): a change to this computer's kept bucket is traded once a burst of writes
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
  const file = path.join(dir, '0123456789abcdef0123456789abcdef.json');
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

test('the trade\'s own write, seen while the trade still runs, is not traded again (no loop)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'okbucket-svc-'));
  const file = path.join(dir, '0123456789abcdef0123456789abcdef.json');
  fs.writeFileSync(file, '{"v":1}');
  let fire = null;
  const watch = (d, cb) => { fire = cb; return { close() {} }; };
  let count = 0;
  const svc = startBucketService({
    dir, watch, debounceMs: 10, intervalMs: 60000,
    /* a slow trade that writes the folder early and the watcher sees it mid-trade (the box, 2026-10-25) */
    tradeOnce: async () => { count++; fs.writeFileSync(file, `{"v":"traded ${count}"}`); fire(); await wait(80); return { traded: true, taken: {}, gave: {} }; },
  });
  await svc.trade('start');
  await wait(200);
  assert.equal(count, 1, 'one trade, not a loop of them');
  svc.stop();
});

test('one sync service per computer: a second one sees the live holder, does not trade, says who does', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'okbucket-svc-'));
  const lockFile = path.join(dir, '..', `sync-${path.basename(dir)}.json`);
  /* the holder: another live process (a pid the check calls alive) that beat a moment ago */
  fs.writeFileSync(lockFile, JSON.stringify({ pid: 424242, who: 'the desktop app', at: new Date().toISOString(), every: 30000 }));
  const said = [];
  let traded = 0;
  const second = startBucketService({ dir, lockFile, alive: (pid) => pid === 424242, watch: () => ({ close() {} }), intervalMs: 60000, say: (l) => said.push(l), tradeOnce: async () => { traded++; return { traded: true, same: true }; } });
  assert.deepEqual(second.heldBy, { pid: 424242, who: 'the desktop app' });
  await second.trade('asked');
  assert.equal(traded, 0, 'no trade while another holds the lock');
  assert.match(said.join('\n'), /runs in pid 424242 \(the desktop app\)/);
  /* the holder died: the next one takes the lock, trades, and gives it back on stop */
  const third = startBucketService({ dir, lockFile, alive: () => false, watch: () => ({ close() {} }), intervalMs: 60000, tradeOnce: async () => { traded++; return { traded: true, same: true }; } });
  assert.equal(third.heldBy, undefined);
  await third.trade('asked');
  assert.equal(traded, 1);
  assert.equal(JSON.parse(fs.readFileSync(lockFile, 'utf8')).pid, process.pid);
  third.stop();
  assert.equal(fs.existsSync(lockFile), false, 'the lock is given back');
});

test('a lock whose pid answers but whose holder stopped beating is taken (Windows reused the pid)', async () => {
  /*
   * Windows, 2026-10-30: the dead desktop app's pid 149784 had gone to GameInputSvc.exe, which answers EPERM - alive to
   * the pid check - and no sync ran. The lock's time is what tells: hours old here, against a 30 s tick.
   */
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'okbucket-svc-'));
  const lockFile = path.join(dir, '..', `sync-${path.basename(dir)}.json`);
  fs.writeFileSync(lockFile, JSON.stringify({ pid: 149784, who: 'the desktop app', at: new Date(Date.now() - 3 * 3600e3).toISOString(), every: 30000 }));
  let traded = 0;
  const svc = startBucketService({ dir, lockFile, alive: () => true, watch: () => ({ close() {} }), intervalMs: 60000, tradeOnce: async () => { traded++; return { traded: true, same: true }; } });
  assert.equal(svc.heldBy, undefined, 'a stale lock holds nothing');
  await svc.trade('asked');
  assert.equal(traded, 1);
  const j = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
  assert.equal(j.pid, process.pid);
  assert.equal(j.every, 60000, 'the new holder says how often it beats');
  svc.stop();
});
