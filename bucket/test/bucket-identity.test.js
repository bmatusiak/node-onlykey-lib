/*
 * The bucket identity and the bucket key (bucket/src/bucket-identity.js, ok-edge plan S3): keys restored from one
 * backup read the same bucket identity and make the same bucket key and certificate; a key of another backup makes
 * neither; what a bucket key signs checks only with its own purpose, its own certificate and its own identity.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { ed25519, x25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');
const bid = require('../src/bucket-identity');

/* a key's agent, as the firmware derives it: one secret per (seed, identity hash, key type) - the seed is the backup */
function fakeKey(seed) {
  const calls = { ecdh: 0, sign: 0 };
  const secretOf = (identity, keyType) => sha256(new Uint8Array([...new TextEncoder().encode(seed), ...identity, keyType]));
  return {
    calls,
    agent: {
      async publicKey(identity, { keyType, version }) {
        assert.equal(version, 1, 'agent version 1: the same keys on 3.0.4 and 3.1.0');
        return keyType === 1 ? ed25519.getPublicKey(secretOf(identity, 1)) : x25519.getPublicKey(secretOf(identity, 4));
      },
      async ecdh(identity, peer, { keyType }) { calls.ecdh++; assert.equal(keyType, 4); return x25519.getSharedSecret(secretOf(identity, 4), peer); },
      async sign(identity, message, { keyType }) { calls.sign++; assert.equal(keyType, 1); return ed25519.sign(message, secretOf(identity, 1)); },
    },
  };
}

async function setUp(key) {
  const identity = await bid.readIdentity(key);
  const bucketKey = await bid.deriveBucketKey(key, identity.publicKey);
  const certificate = await bid.certify(key, identity.publicKey, bucketKey.publicKey);
  return { identity, bucketKey, certificate };
}

test('the bucket identity is the agent key of the empty label: the same on two keys restored from one backup, its id 32 hex', async () => {
  const phone = await bid.readIdentity(fakeKey('backup-1'));
  const hard = await bid.readIdentity(fakeKey('backup-1'));
  const other = await bid.readIdentity(fakeKey('backup-2'));
  assert.equal(bid.IDENTITY_LABEL, '');
  assert.deepEqual(phone.publicKey, hard.publicKey);
  assert.match(phone.id, /^[0-9a-f]{32}$/);
  assert.notEqual(phone.id, other.id);
});

test('one backup, one bucket key and one certificate; the key is asked twice (ECDH and signature), reading asks nothing', async () => {
  const k1 = fakeKey('backup-1');
  const a = await setUp(k1);
  const b = await setUp(fakeKey('backup-1'));
  assert.deepEqual(a.bucketKey.publicKey, b.bucketKey.publicKey);
  assert.deepEqual(a.certificate, b.certificate, 'Ed25519 is deterministic: every device holds the same certificate');
  assert.deepEqual(k1.calls, { ecdh: 1, sign: 1 });
  assert.equal(bid.verifyCertificate({ identityPublicKey: a.identity.publicKey, bucketPublicKey: a.bucketKey.publicKey, certificate: a.certificate }), true);
});

test('another backup cannot pass for this identity: its bucket key does not check under this identity', async () => {
  const mine = await setUp(fakeKey('backup-1'));
  const theirs = await setUp(fakeKey('backup-2'));
  assert.notDeepEqual(mine.bucketKey.publicKey, theirs.bucketKey.publicKey);
  assert.equal(bid.verifyCertificate({ identityPublicKey: mine.identity.publicKey, bucketPublicKey: theirs.bucketKey.publicKey, certificate: theirs.certificate }), false);
  const challenge = new Uint8Array(32).fill(9);
  const signature = bid.sign(theirs.bucketKey, 'proof', challenge);
  assert.equal(bid.verify({ identityPublicKey: mine.identity.publicKey, bucketPublicKey: theirs.bucketKey.publicKey, certificate: theirs.certificate, purpose: 'proof', bytes: challenge, signature }), false);
});

test('what the bucket key signs checks only for its own purpose and its own bytes', async () => {
  const { identity, bucketKey, certificate } = await setUp(fakeKey('backup-1'));
  const challenge = new Uint8Array(32).fill(7);
  const signature = bid.sign(bucketKey, 'proof', challenge);
  const base = { identityPublicKey: identity.publicKey, bucketPublicKey: bucketKey.publicKey, certificate, bytes: challenge, signature };
  assert.equal(bid.verify({ ...base, purpose: 'proof' }), true);
  assert.equal(bid.verify({ ...base, purpose: 'give' }), false, 'a proof is never a GIVE');
  assert.equal(bid.verify({ ...base, purpose: 'proof', bytes: new Uint8Array(32).fill(8) }), false, 'another challenge');
  assert.throws(() => bid.sign(bucketKey, 'nametag', challenge), /signs proof, give, accept, revoke/);
});
