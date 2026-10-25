/*
 * The bucket trade (bucket/src/trade.js, ok-edge plan S3): two devices of one bucket identity prove themselves to
 * each other over fresh nonces, then trade HAVE and GIVE and hold the same bucket; a device of another backup, a
 * replayed hello, an out-of-order message - each gets the same plain refusal, and the peer shows nothing first.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { ed25519, x25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');
const bucketLib = require('../src/bucket');
const bid = require('../src/bucket-identity');
const trade = require('../src/trade');

const rnd = (n) => new Uint8Array(crypto.randomBytes(n));

/* a device of one backup: the bucket identity, bucket key and certificate its key makes (as bucket-identity.test) */
async function device(seed) {
  const secretOf = (identity, keyType) => sha256(new Uint8Array([...new TextEncoder().encode(seed), ...identity, keyType]));
  const key = { agent: {
    publicKey: async (identity, { keyType }) => (keyType === 1 ? ed25519.getPublicKey(secretOf(identity, 1)) : x25519.getPublicKey(secretOf(identity, 4))),
    ecdh: async (identity, peer) => x25519.getSharedSecret(secretOf(identity, 4), peer),
    sign: async (identity, message) => ed25519.sign(message, secretOf(identity, 1)),
  } };
  const { publicKey, id } = await bid.readIdentity(key);
  const bucketKey = await bid.deriveBucketKey(key, publicKey);
  const certificate = await bid.certify(key, publicKey, bucketKey.publicKey);
  return { id, identityPublicKey: publicKey, bucketKey, certificate };
}

let tick = 0;
const kv = (b, store) => bucketLib.kv(b, store, { now: () => new Date(Date.UTC(2026, 9, 25, 1, 0, tick++)).toISOString() });

async function run(computer, peer) {
  const c = trade.computerSide({ bucket: computer.bucket, me: computer.me, randomBytes: rnd });
  const answer = trade.peerSide({ bucket: () => peer.bucket, me: () => peer.me, randomBytes: rnd, seen: peer.seen });
  const a1 = answer(c.hello(), 'desktop');
  const m2 = c.prove(a1);
  if (!m2) return { refusedAt: 'proof', a1 };
  const a2 = answer(m2, 'desktop');
  const g = c.give(a2);
  if (!g) return { refusedAt: 'give', a2 };
  const a3 = answer(g.message, 'desktop');
  return { done: c.finish(a3), a1, a2, a3 };
}

test('two devices of one backup prove themselves and trade: each ends with the other\'s changes', async () => {
  const me = await device('backup-1');
  const desktop = { me: { ...me }, bucket: bucketLib.create({ owner: me.id }) };
  const phone = { me: { ...me }, bucket: bucketLib.create({ owner: me.id }), seen: new Set() };
  kv(phone.bucket, 'guestbook').setItem('myname', 'Pixel Tester');
  kv(desktop.bucket, 'keychain').setItem('list', '{"format":"onlykey-keychain","version":1,"entries":[]}');
  const r = await run(desktop, phone);
  assert.ok(r.done, `refused at ${r.refusedAt}`);
  assert.equal(kv(desktop.bucket, 'guestbook').getItem('myname'), 'Pixel Tester');
  assert.ok(kv(phone.bucket, 'keychain').getItem('list'));
  assert.deepEqual(r.a3.taken, { keychain: 1 });
});

test('a device of another backup is refused at the proof - the peer showed no HAVE, no GIVE', async () => {
  const mine = await device('backup-1');
  const theirs = await device('backup-2');
  const phone = { me: mine, bucket: bucketLib.create({ owner: mine.id }), seen: new Set() };
  kv(phone.bucket, 'guestbook').setItem('myname', 'Pixel Tester');
  /* claims the phone's identity, holds another backup's bucket key */
  const impostor = { me: { ...theirs, id: mine.id }, bucket: bucketLib.create({ owner: mine.id }) };
  const c = trade.computerSide({ bucket: impostor.bucket, me: impostor.me, randomBytes: rnd });
  const answer = trade.peerSide({ bucket: () => phone.bucket, me: () => phone.me, randomBytes: rnd, seen: phone.seen });
  const a1 = answer(c.hello(), 'evil');
  assert.ok(a1.ok && !a1.have && !a1.give, 'hello answers with a proof and a nonce only');
  /* the impostor's own check of the phone passes - the phone is real - but its proof of itself cannot */
  const forged = { type: trade.TYPES.PROVE, v: 1, identity: mine.id, proof: trade.prove(impostor.me, Buffer.from(a1.nonce, 'hex'), 'computer'), have: {} };
  assert.deepEqual(answer(forged, 'evil'), { ok: false, refusal: 'no' });
  assert.deepEqual(answer({ type: trade.TYPES.GIVE, identity: mine.id, give: { guestbook: { myname: { v: 'x', at: '2099-01-01T00:00:00.000Z' } } } }, 'evil'), { ok: false, refusal: 'no' });
  assert.equal(kv(phone.bucket, 'guestbook').getItem('myname'), 'Pixel Tester', 'nothing was taken');
});

test('another identity, a replayed hello, a GIVE out of turn, a closed bucket: the same plain refusal', async () => {
  const me = await device('backup-1');
  const other = await device('backup-2');
  const phone = { me, bucket: bucketLib.create({ owner: me.id }), seen: new Set() };
  const answer = trade.peerSide({ bucket: () => phone.bucket, me: () => phone.me, randomBytes: rnd, seen: phone.seen });
  const c = trade.computerSide({ bucket: bucketLib.create({ owner: other.id }), me: other, randomBytes: rnd });
  assert.deepEqual(answer(c.hello(), 'x'), { ok: false, refusal: 'no' }, 'another identity');
  const same = trade.computerSide({ bucket: bucketLib.create({ owner: me.id }), me, randomBytes: rnd });
  const hello = same.hello();
  assert.ok(answer(hello, 'x').ok);
  assert.deepEqual(answer(hello, 'x'), { ok: false, refusal: 'no' }, 'the same nonce again');
  assert.deepEqual(answer({ type: trade.TYPES.GIVE, identity: me.id, give: {} }, 'y'), { ok: false, refusal: 'no' }, 'no trade started');
  const closed = trade.peerSide({ bucket: () => null, me: () => null, randomBytes: rnd });
  assert.deepEqual(closed(same.hello(), 'x'), { ok: false, refusal: 'no' }, 'bucket not open');
  assert.equal(answer({ type: 'okedge.request' }, 'x'), null, 'not a trade: not answered here');
});
