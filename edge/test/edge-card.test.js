'use strict';
/*
 * THE LOGIN CARD, certified by the key (edge/src/certify.js; Brad, 2026-10-30: one card per salted device id, certified
 * at a press, kept with the bucket, checked with the owner keys READ from the key). Against the fake key, which signs
 * the way okplugin_edge certify_sign does.
 */
const test = require('node:test');
const assert = require('node:assert');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { chain, certify } = require('../src');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

const hex = (b) => Buffer.from(b).toString('hex');
const cardFor = async (e) => ({
  device: hex((await e.publicKey()).deviceId), identity: hex(new Uint8Array(32).fill(5)), site: 'ok-edge.test',
  derives: ['okedge/bucket/v2/x', 'okedge/bucket-key/v2/x'], signs: { slot: 201, label: hex(new Uint8Array(32).fill(1)), cap: 2 },
});

test('a login card certified at a press: a link on the chain, and the record verifies under the owner keys read from the key', async () => {
  const t = fakeKey({ secret: p256.utils.randomSecretKey() });
  const e = edgeOver(t);
  const before = await e.head();
  const rec = await e.certifyLoginCard(await cardFor(e));
  const after = await e.head();
  assert.equal(after.seq, (before.seq ?? -1) + 1, 'one certify link');
  const [l] = await e.pickup(after.seq, 1);
  assert.deepEqual([...chain.decodeLink(l.link).subject], [...certify.subjectOf('login-card', rec.thing)], 'the link carries the card\'s subject');
  assert.equal(rec.kind, 'login-card');
  assert.equal(await e.verifyRecord(rec), true);
  /* JSON round trip: what the bucket keeps still verifies */
  assert.equal(await e.verifyRecord(JSON.parse(JSON.stringify(rec))), true);
  /* the certify's checkpoint is the card's top (at the certify's own link), not part of the certification */
  assert.equal(rec.certification.checkpoint, undefined);
  assert.equal(rec.top.checkpoint.seq, after.seq);
  assert.deepEqual(rec.top.links, []);
  const kept = JSON.parse(JSON.stringify(rec));
  const { publicKey, deviceId } = await e.publicKey();
  assert.equal(certify.verifyTop(kept.top, { deviceId, publicKey, publicKeyPq: await e.publicKeyPq('checkpoint'), keySeq: after.seq }).ok, true);
  /* a new host warms Edge from the card it found in the bucket */
  const proven = await edgeOver(t).warmUp(kept.top);
  assert.equal(proven.seq, after.seq);
});

test('a changed card, another device\'s card, or another owner\'s - not this owner\'s', async () => {
  const owner = p256.utils.randomSecretKey();
  const t = fakeKey({ secret: p256.utils.randomSecretKey(), ownerSecret: owner });
  const e = edgeOver(t);
  const rec = await e.certifyLoginCard(await cardFor(e));
  assert.equal(await e.verifyRecord({ ...rec, thing: { ...rec.thing, site: 'elsewhere' } }), false, 'a changed card');
  const other = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey(), ownerSecret: owner }));
  const naming = { ...rec, thing: { ...rec.thing, device: hex((await other.publicKey()).deviceId) } };
  assert.equal(await e.verifyRecord(naming), false, 'a card naming another device than the one that certified it');
  const stranger = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey(), ownerSecret: p256.utils.randomSecretKey() }));
  assert.equal(await stranger.verifyRecord(rec), false, 'another owner\'s keys');
});

/* one device's log as an offer brings it: its links up to its key's confirmed checkpoint, its checkpoint keys */
async function logOf(e, extra = {}) {
  const cp = await e.checkpoint();
  const { publicKey, deviceId } = await e.publicKey();
  return { deviceId, publicKey, publicKeyPq: await e.publicKeyPq('checkpoint'), records: await e.pickup(0, cp.seq + 1), checkpoint: cp, ...extra };
}

test('membership: an UNNAMED device with this owner\'s card is yours; no proof at all is unproven; a card for other keys is dropped (unproven)', async () => {
  const { devices } = require('../src');
  const owner = p256.utils.randomSecretKey();
  const mine = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey(), ownerSecret: owner }));
  const card = await mine.certifyLoginCard(await cardFor(mine));
  const me = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey(), ownerSecret: owner }));
  const ownerKey = await me.ownerPublicKey();
  const ownerKeyPq = await me.publicKeyPq('owner');
  const named = devices.classify({ log: await logOf(mine, { card }), ownerKey, ownerKeyPq });
  assert.equal(named.class, 'mine-new', 'a device with this owner\'s card');
  assert.equal(named.nametag, null, 'unnamed: no nametag');
  assert.equal(devices.classify({ log: await logOf(mine), ownerKey, ownerKeyPq }).class, 'unproven', 'no card, no nametag');
  /* the card moved onto another device's log: it names other checkpoint keys */
  const other = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey(), ownerSecret: owner }));
  assert.equal(devices.classify({ log: await logOf(other, { card }), ownerKey, ownerKeyPq }).class, 'unproven', 'a card naming other checkpoint keys is dropped, not a gate');
  /*
   * a statement from before certify (no seq: no CERTIFY link names it) cannot be checked today - unproven, merged, not
   * an alarm (2026-10-31: the web app held live key 1's and the Pixel's old logs apart as forged)
   */
  const plain = await logOf(mine);
  const legacy = { deviceId: plain.deviceId, publicKey: plain.publicKey, publicKeyPq: plain.publicKeyPq, nametag: 'live key 1', signature: new Uint8Array(64).fill(1), signaturePq: new Uint8Array(3309).fill(2) };
  assert.equal(devices.classify({ log: { ...plain, statement: legacy }, ownerKey, ownerKeyPq }).class, 'unproven', 'an old-format statement');
  /* a certified statement (it has its seq) that does not verify: dropped too - only the chain check keeps a log apart */
  assert.equal(devices.classify({ log: { ...plain, statement: { ...legacy, seq: 3 } }, ownerKey, ownerKeyPq }).class, 'unproven', 'a certified statement that does not verify');
});
