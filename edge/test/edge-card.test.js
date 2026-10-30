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
