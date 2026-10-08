'use strict';
/*
 * Your devices and the logs they offer (edge/src/devices.js; Brad, 2026-10-08: "if it has
 * the private ecc key to sign the block, then i want the log"; "hold these blocks in the
 * app until approved and merged"; nametags). Every log is kept; this sorts it.
 */
const test = require('node:test');
const assert = require('node:assert');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { devices } = require('../src');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

/* a device: its own chain (a few links), its checkpoint, its statement - as a computer would relay it */
async function device({ nametag = 'hard key', ownerSecret, links = 3 } = {}) {
  const t = fakeKey({ secret: p256.utils.randomSecretKey(), ...(ownerSecret ? { ownerSecret } : {}) });
  const e = edgeOver(t);
  for (let i = 0; i < links; i += 1) t.edgeRecord();
  const { publicKey, deviceId } = await e.publicKey();
  const h = await e.head();
  return { t, e, log: { deviceId, publicKey, records: await e.pickup(0, h.seq + 1), checkpoint: await e.checkpoint(), statement: await e.statement(nametag) } };
}
const myOwner = async () => (await (await device()).e.statement('A13')).ownerKey;

test('a log made with your OnlyKey from a device you know: mine-known, its chain checks, its nametag', async () => {
  const owner = await myOwner();
  const { log } = await device({ nametag: 'Pixel' });
  const known = [{ deviceId: Buffer.from(log.deviceId).toString('hex') }];
  const r = devices.classify({ log, ownerKey: owner, known });
  assert.equal(r.class, 'mine-known');
  assert.equal(r.nametag, 'Pixel');
  assert.equal(r.check.ok, true, JSON.stringify(r.check));
});

test('a log made with your OnlyKey from a device you do NOT know: mine-new (a hard key restored from the backup, or a leak)', async () => {
  const r = devices.classify({ log: (await device()).log, ownerKey: await myOwner(), known: [] });
  assert.equal(r.class, 'mine-new');
  assert.equal(r.nametag, 'hard key');
});

test('a log NOT made with your OnlyKey, or a statement naming another key: forged - never merged, kept as evidence', async () => {
  const owner = await myOwner();
  const stranger = await device({ ownerSecret: p256.utils.randomSecretKey() });
  assert.equal(devices.classify({ log: stranger.log, ownerKey: owner }).class, 'forged', 'another owner key');
  const a = await device();
  const b = await device();
  const swapped = { ...a.log, statement: b.log.statement };
  assert.equal(devices.classify({ log: swapped, ownerKey: owner }).class, 'forged', 'a real statement of ANOTHER device of yours, put on this chain');
});

test('the chain is checked under that device\'s own key: a tampered link is an alarm even on a device of yours', async () => {
  const { log } = await device();
  const records = log.records.map((r, i) => (i === 1 ? { ...r, link: Uint8Array.from(r.link, (x, j) => (j === 50 ? x ^ 1 : x)) } : r));
  const r = devices.classify({ log: { ...log, records }, ownerKey: await myOwner() });
  assert.equal(r.class, 'mine-new', 'the owner signature still says who it is');
  assert.equal(r.check.ok, false);
  assert.equal(r.check.alarm, 'tampered');
});

test('nametags: one fingerprint, many statements - the highest seq names it, the rest are "previously"; a forged one is not counted', async () => {
  const owner = await myOwner();
  const d = await device({ nametag: 'phone' });
  const first = d.log.statement;
  d.t.edgeRecord();
  const later = await d.e.statement('A13');
  const stranger = await device({ ownerSecret: p256.utils.randomSecretKey() });
  const fake = { ...(await stranger.e.statement('evil')), deviceId: first.deviceId, publicKey: first.publicKey, seq: 999 };
  let list = devices.remember([], first, { at: 1 });
  list = devices.remember(list, later, { at: 2 });
  list = devices.remember(list, later, { at: 3 });
  assert.equal(list.length, 1, 'one entry per fingerprint');
  assert.equal(list[0].statements.length, 2, 'the same statement twice is kept once');
  assert.deepEqual(devices.nametagOf([...devices.statementsOf(list[0]), fake], owner), { nametag: 'A13', seq: later.seq, previously: ['phone'] });
});

test('log recovery: a device\'s log with a stretch it accepted as lost (LOSS) still checks and can merge', async () => {
  const d = await device({ links: 4 });
  await d.e.loss({ from: 1, to: 2, timeoutMs: 2000 });
  const h = await d.e.head();
  const all = await d.e.pickup(0, h.seq + 1);
  const records = all.filter((r, i) => i !== 1 && i !== 2); /* the lost stretch is not in this copy */
  const r = devices.classify({ log: { ...d.log, records, checkpoint: await d.e.checkpoint() }, ownerKey: await myOwner() });
  assert.equal(r.check.ok, true, JSON.stringify(r.check));
  const found = devices.classify({ log: { ...d.log, records: all, checkpoint: await d.e.checkpoint() }, ownerKey: await myOwner() });
  assert.equal(found.check.ok, true, 'the lost stretch, found again, welds back in');
});
