'use strict';

/*
 * The key's HYBRID signatures for tests (2026-10-10): every checkpoint and owner statement
 * is a P-256 signature AND an ML-DSA-65 one over the same digest, and a verifier needs both.
 * A test that signs as the key takes both halves from here.
 *
 * The ML-DSA-65 seeds follow the firmware (okplugin_edge.cpp mldsa_keypair): the checkpoint
 * key's seed = HKDF(salt = 0x28 . device salt, K132, "onlykey/edge/mldsa/v1"), the owner key's
 * = HKDF(K132, "onlykey/edge/owner-mldsa/v1") with no salt. A test has no K132 or device salt:
 * the P-256 secret stands in for both (salt 0x28 alone). Keygen is cached by seed.
 */
const { chain } = require('../../src');
const { p256 } = require('../../../src/vendor/exports/@noble/curves/nist.js');
const { sha256 } = require('../../../src/vendor/exports/@noble/hashes/sha2.js');
const { hkdf } = require('../../../src/vendor/exports/@noble/hashes/hkdf.js');
const { ml_dsa65 } = require('../../../src/vendor/exports/@noble/post-quantum/ml-dsa.js');

const cache = new Map();
function pqKeys(seed) {
  const id = Buffer.from(seed).toString('hex');
  if (!cache.has(id)) cache.set(id, chain.mlDsaKeys(seed));
  return cache.get(id);
}
const pqCheckpointKeys = (secret) => pqKeys(hkdf(sha256, Uint8Array.from(secret), Uint8Array.of(0x28), Buffer.from('onlykey/edge/mldsa/v1'), 32));
const pqOwnerKeys = (secret) => pqKeys(hkdf(sha256, Uint8Array.from(secret), undefined, Buffer.from('onlykey/edge/owner-mldsa/v1'), 32));

/*
 * ML-DSA-65 signing is hedged (random) by default, so the same seal signed twice gives another
 * block id. Tests sign DETERMINISTICALLY (FIPS 204's deterministic variant, rnd = 32 zero
 * bytes) so a block built again has the same id; verification does not depend on it.
 */
const signPq = (digest, secretKeyPq) => ml_dsa65.sign(digest, secretKeyPq, { extraEntropy: false });

/** An Edge (checkpoint) key from a 32-byte P-256 secret: its two public keys, and checkpoints signed with both. */
function edgeKey(secret) {
  const publicKey = p256.getPublicKey(secret, false).slice(1);
  const pq = pqCheckpointKeys(secret);
  const deviceId = chain.deviceIdOf(publicKey);
  const sign = (fields) => ({ signature: chain.signCheckpoint(fields, secret), signaturePq: signPq(chain.checkpointDigest(fields), pq.secretKey) });
  return {
    secret, publicKey, publicKeyPq: pq.publicKey, secretKeyPq: pq.secretKey, deviceId, sign,
    /* {seq, head} of THIS key's chain -> {seq, head, signature, signaturePq} */
    checkpoint: ({ seq, head }) => ({ seq, head, ...sign({ deviceId, seq, head }) }),
  };
}

/** An owner key from a 32-byte secret: its two public keys, and a digest signed with both. */
function ownerKey(secret) {
  const pq = pqOwnerKeys(secret);
  return {
    publicKey: p256.getPublicKey(secret, false).slice(1), publicKeyPq: pq.publicKey,
    sign: (digest) => ({ signature: p256.sign(digest, secret, { prehash: false, lowS: false }), signaturePq: signPq(digest, pq.secretKey) }),
  };
}

module.exports = { pqCheckpointKeys, pqOwnerKeys, signPq, edgeKey, ownerKey };
