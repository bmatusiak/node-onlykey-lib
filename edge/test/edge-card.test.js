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

test('membership: an UNNAMED device with this owner\'s card is yours; no proof at all is unproven; a card for other keys is forged', async () => {
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
  assert.equal(devices.classify({ log: await logOf(other, { card }), ownerKey, ownerKeyPq }).class, 'forged');
});

test('an offer without a nametag: the checkpoint keys travel on their own, with the card; the old statement-only shape still reads', async () => {
  const { sync, request } = require('../src');
  const signer = request.peerSignerFromSecret(p256.utils.randomSecretKey());
  const e = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey() }));
  const card = await e.certifyLoginCard(await cardFor(e));
  const log = await logOf(e);
  const sid = new Uint8Array(8).fill(1);
  const msg = await sync.buildOffer({ signer, deviceId: log.deviceId, sid: Buffer.from(sid).toString('hex'), chain: log.deviceId, linkParts: 0, checkpoint: log.checkpoint, card, keys: log });
  assert.equal(msg.payload.statement, undefined);
  assert.equal(sync.verify(msg).ok, true, 'an offer with keys and a card verifies');
  const st = await e.statement('green');
  const old = await sync.buildOffer({ signer, deviceId: log.deviceId, sid: Buffer.from(sid).toString('hex'), chain: log.deviceId, linkParts: 0, checkpoint: log.checkpoint, statement: st });
  assert.equal(sync.verify(old).ok, true, 'a statement-only offer still verifies');
});
