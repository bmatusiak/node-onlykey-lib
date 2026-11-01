/*
 * Joining the identity's room on the user's server (bucket/src/room.js, ok-edge plan M1): a device of the identity
 * enters with its bucket key's proof over the server's host and nonce; another identity, another room, another
 * server, another nonce, a key without the identity's certificate, a bad device - each gets the same plain refusal.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { ed25519, x25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');
const bid = require('../src/bucket-identity');
const room = require('../src/room');

const rnd = (n) => new Uint8Array(crypto.randomBytes(n));
const HOST = 'ok-edge.example.workers.dev';
const PHONE = { id: 'a1b2c3d4e5f60718', name: 'Pixel', kind: 'android' };

/* a device of one backup: the bucket identity, bucket key and certificate its key makes (as trade.test) */
async function device(seed) {
  const secretOf = (identity, keyType) => sha256(new Uint8Array([...new TextEncoder().encode(seed), ...identity, keyType]));
  const key = { deriveSecret: async (label, { rpId } = {}) => sha256(new TextEncoder().encode(`${seed}|${label}|${rpId}`)), keySite: async () => ({ on: true, site: 'okt.example' }), agent: {
    publicKey: async (identity, { keyType }) => (keyType === 1 ? ed25519.getPublicKey(secretOf(identity, 1)) : x25519.getPublicKey(secretOf(identity, 4))),
    ecdh: async (identity, peer) => x25519.getSharedSecret(secretOf(identity, 4), peer),
    sign: async (identity, message) => ed25519.sign(message, secretOf(identity, 1)),
  } };
  const { publicKey, id } = await bid.readIdentity(key);
  const bucketKey = await bid.deriveBucketKeyAt(key, publicKey, 'okt.example');
  const certificate = await bid.certify(key, publicKey, bucketKey.publicKey);
  return { id, identityPublicKey: publicKey, bucketKey, certificate, key };
}

test('a device of the identity joins its room with a proof over the host and nonce', async () => {
  const me = await device('backup A');
  const { nonce, message } = room.challenge(rnd);
  assert.equal(message.t, 'challenge');
  const msg = room.join(me, { nonce: message.nonce, host: HOST }, PHONE);
  assert.deepEqual(room.checkJoin(me.id, msg, { nonce, host: HOST }), { ok: true, identity: me.id, device: PHONE, login: false });
  /* the host is compared as a host: case does not matter */
  assert.equal(room.checkJoin(me.id, msg, { nonce, host: HOST.toUpperCase() }).ok, true);
});

test('every wrong join is the same plain refusal', async () => {
  const me = await device('backup A');
  const other = await device('backup B');
  const { nonce, message } = room.challenge(rnd);
  const asked = { nonce, host: HOST };
  const good = room.join(me, { nonce: message.nonce, host: HOST }, PHONE);
  const no = { ok: false };
  /* another room: the key does not hash to the identity asked for */
  assert.deepEqual(room.checkJoin(other.id, good, asked), no);
  /* another server: the proof names the host it was made for */
  assert.deepEqual(room.checkJoin(me.id, good, { nonce, host: 'evil.example' }), no);
  /* another connection: a recorded join over an old nonce */
  assert.deepEqual(room.checkJoin(me.id, good, { nonce: rnd(32), host: HOST }), no);
  /* a bucket key the identity never certified (another backup's key and certificate under this identity) */
  const forged = { ...room.join(other, { nonce: message.nonce, host: HOST }, PHONE), identityPublicKey: good.identityPublicKey };
  assert.deepEqual(room.checkJoin(me.id, forged, asked), no);
  /* a trade proof is not a join: the same key signing the same bytes under 'proof' */
  const asProof = { ...good, signature: Buffer.from(bid.sign(me.bucketKey, 'proof', new Uint8Array([...new TextEncoder().encode(`${HOST}|`), ...nonce]))).toString('hex') };
  assert.deepEqual(room.checkJoin(me.id, asProof, asked), no);
  /* a device the room cannot show */
  for (const d of [null, { ...PHONE, id: 'xyz' }, { ...PHONE, name: '' }, { ...PHONE, name: 'n'.repeat(65) }, { ...PHONE, kind: 'toaster' }]) {
    assert.deepEqual(room.checkJoin(me.id, { ...good, device: d }, asked), no);
  }
  /* malformed */
  for (const m of [null, {}, { ...good, t: 'hello' }, { ...good, signature: 'zz' }, { ...good, certificate: good.certificate.slice(2) }]) {
    assert.deepEqual(room.checkJoin(me.id, m, asked), no);
  }
});

/*
 * THE LOGIN PROOF (Brad, 2026-11-01: "the login plan needs to check mcp to challenge the identity"): the identity signs,
 * on the key, the bucket key with THIS server's host and nonce - the key was present at this join. A server that asks
 * for it (requireLogin) refuses a kept certificate, a proof for another nonce or host, and a proof by another identity.
 */
test('a login proof for this challenge enters, and only for this challenge', async () => {
  const me = await device('backup A');
  const { nonce, message } = room.challenge(rnd);
  const asked = { host: HOST, nonce };
  const proof = await bid.signLogin(me.key, me.identityPublicKey, me.bucketKey.publicKey, asked);
  const msg = room.join({ ...me, certificate: proof, login: asked }, { nonce: message.nonce, host: HOST }, PHONE);
  assert.deepEqual(room.checkJoin(me.id, msg, { nonce, host: HOST }, { requireLogin: true }), { ok: true, identity: me.id, device: PHONE, login: true });
  /* the proof is a certificate anyone with the host and nonce checks */
  assert.equal(bid.verifyCertificate({ identityPublicKey: me.identityPublicKey, bucketPublicKey: me.bucketKey.publicKey, certificate: proof, login: asked }), true);
  /* another connection's nonce, another host, the kept certificate where a login is required: refused */
  const other = room.challenge(rnd);
  assert.deepEqual(room.checkJoin(me.id, msg, { nonce: other.nonce, host: HOST }, { requireLogin: true }), { ok: false });
  assert.deepEqual(room.checkJoin(me.id, msg, { nonce, host: 'other.example' }, { requireLogin: true }), { ok: false });
  const kept = room.join(me, { nonce: message.nonce, host: HOST }, PHONE);
  assert.deepEqual(room.checkJoin(me.id, kept, { nonce, host: HOST }, { requireLogin: true }), { ok: false });
  /* a login proof that names this challenge but was signed for another bucket key: refused */
  const stranger = await device('backup B');
  const wrong = await bid.signLogin(me.key, me.identityPublicKey, stranger.bucketKey.publicKey, asked);
  const forged = room.join({ ...me, certificate: wrong, login: asked }, { nonce: message.nonce, host: HOST }, PHONE);
  assert.deepEqual(room.checkJoin(me.id, forged, { nonce, host: HOST }, { requireLogin: true }), { ok: false });
});

/* the desktop's own local MCP: no proof at all - but still this room's identity, a device, a join */
test('an open room takes a join with no proof, only for its own identity and a well-formed device', async () => {
  const me = await device('backup A');
  const { nonce, message } = room.challenge(rnd);
  const bare = room.join({ ...me, certificate: new Uint8Array(0) }, { nonce: message.nonce, host: HOST }, PHONE);
  assert.deepEqual(room.checkJoin(me.id, bare, { nonce, host: HOST }, { open: true }), { ok: true, identity: me.id, device: PHONE, login: false });
  assert.deepEqual(room.checkJoin(me.id, bare, { nonce, host: HOST }), { ok: false }, 'not open: the proof is asked');
  const stranger = await device('backup B');
  assert.deepEqual(room.checkJoin(stranger.id, bare, { nonce, host: HOST }, { open: true }), { ok: false }, 'another room');
  assert.deepEqual(room.checkJoin(me.id, { ...bare, device: { id: 'x', name: '', kind: 'nope' } }, { nonce, host: HOST }, { open: true }), { ok: false });
});
