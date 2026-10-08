'use strict';
/*
 * Checking ANOTHER device's chain (sync.anchorCheck): its links up to its key's SIGNED
 * checkpoint, against what this device already merged of it. The check is the lib's
 * alone - no anchor link on the key since 2026-10-08 (Brad: "pairing and sync is all
 * app stuff, not firmware"); the app runs it before merging a held log.
 */
const test = require('node:test');
const assert = require('node:assert');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');
const syncLib = require('../src/sync');

const someKey = () => p256.getPublicKey(p256.utils.randomSecretKey(), false).slice(1);

/* another device with a few links of its own, and what a computer would read from it */
async function withHistory() {
  const t = fakeKey({ secret: p256.utils.randomSecretKey() });
  const b = edgeOver(t);
  const kb = await b.publicKey();
  for (let i = 0; i < 3; i += 1) t.edgeRecord();
  const h = await b.head();
  const records = await b.pickup(0, h.seq + 1);
  return { kb, records, cp: await b.checkpoint() };
}

test('anchorCheck: the other device\'s chain up to its signed checkpoint verifies', async () => {
  const { kb, records, cp } = await withHistory();
  const r = syncLib.anchorCheck({ records, publicKey: kb.publicKey, checkpoint: cp, anchors: [] });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.verifiedThrough, cp.seq);
});

test('anchorCheck alarms: a rollback, a changed history, a tampered link, a checkpoint not that device\'s', async () => {
  const { kb, records, cp } = await withHistory();
  const check = (o) => syncLib.anchorCheck({ records, publicKey: kb.publicKey, checkpoint: cp, anchors: [], ...o });
  assert.equal(check({ anchors: [{ seq: cp.seq + 2, head: new Uint8Array(32) }] }).alarm, 'rollback');
  assert.equal(check({ anchors: [{ seq: 1, head: new Uint8Array(32).fill(7) }] }).alarm, 'changed');
  assert.equal(check({ anchors: [{ seq: cp.seq, head: new Uint8Array(32).fill(7) }] }).alarm, 'changed');
  assert.equal(check({ anchors: [{ seq: 1, head: records[1].head }] }).ok, true, 'the same head at a seq merged before is fine');
  const flipped = records.map((r, i) => (i === 1 ? { ...r, link: Uint8Array.from(r.link, (x, j) => (j === 50 ? x ^ 1 : x)) } : r));
  assert.equal(check({ records: flipped }).alarm, 'tampered');
  const sig = Uint8Array.from(cp.signature); sig[0] ^= 1;
  assert.equal(check({ checkpoint: { ...cp, signature: sig } }).alarm, 'bad-checkpoint');
  assert.equal(check({ publicKey: someKey() }).alarm, 'bad-checkpoint');
});
