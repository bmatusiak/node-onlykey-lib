'use strict';

/* onlykey-js edge sync, phase 1: the PC's own copy - read, verify (R27), keep; report, never repair */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { sync, load, store } = require('../cli/copy');
/* one device's copy as the bucket keeps it (the home's copies store, key = device id, 16 hex) */
const kept = (h, deviceId) => store(h).getItem(Buffer.from(deviceId).toString('hex').slice(0, 16));
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

async function keyWith(n) {
  const transport = fakeKey();
  const edge = edgeOver(transport);
  await edge.receipt(0, 0, new Uint8Array(32));
  for (let i = 0; i < n; i++) transport.edgeRecord();
  return { transport, edge };
}
const home = () => fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-sync-'));

test('first sync keeps every link the key holds and verifies; --status then changes nothing', async () => {
  const { edge } = await keyWith(3);
  const h = home();
  const r = await sync(edge, h);
  const k = await edge.head();
  assert.equal(r.verdict.kind, 'verified');
  assert.equal(r.copy.newest, k.seq);
  assert.ok(r.copy.saved);
  const before = kept(h, (await edge.publicKey()).deviceId);
  const s = await sync(edge, h, { status: true });
  assert.equal(s.verdict.kind, 'verified');
  assert.equal(s.copy.saved, false);
  assert.equal(kept(h, (await edge.publicKey()).deviceId), before, '--status wrote the copy');
});

test('a later sync picks up only the new links', async () => {
  const { transport, edge } = await keyWith(2);
  const h = home();
  const first = await sync(edge, h);
  transport.edgeRecord();
  const r = await sync(edge, h);
  assert.equal(r.copy.added, 1);
  assert.equal(r.copy.count, first.copy.count + 1);
  assert.equal(r.verdict.kind, 'verified');
});

test('a copy edited by hand is reported and not saved over - repairs are the phone\'s', async () => {
  const { transport, edge } = await keyWith(3);
  const h = home();
  await sync(edge, h);
  const { deviceId } = await edge.publicKey();
  const key = Buffer.from(deviceId).toString('hex').slice(0, 16);
  const s = JSON.parse(store(h).getItem(key));
  const mid = s.links[1];
  mid.link = mid.link.slice(0, 40) + (mid.link[40] === 'a' ? 'b' : 'a') + mid.link.slice(41); /* one byte of the subject */
  store(h).setItem(key, JSON.stringify(s));
  const edited = store(h).getItem(key);
  transport.edgeRecord();
  const r = await sync(edge, h);
  assert.equal(r.verdict.kind, 'tampered');
  assert.equal(r.copy.saved, false);
  assert.equal(store(h).getItem(key), edited, 'a copy that does not verify was saved');
  assert.equal(load(h, deviceId).links.length, s.links.length);
});
