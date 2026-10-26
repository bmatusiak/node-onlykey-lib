'use strict';

/**
 * THE BUCKET IDENTITY AND THE BUCKET KEY (ok-edge plan S3; Brad, 2026-10-25: "derive 2 keys on our key and use both
 * to derive a shared secret, then use that to derive a keypair stored for the bucket, then we sign that keypair
 * pubkey with our identity key ... without anything to do with edge").
 *
 *   BUCKET IDENTITY  the key's agent-derived Ed25519 key of the EMPTY label "" (Brad, 2026-10-25: "\"\" is the
 *                    identity of the key, not tied to edge ... not a salty type and is usable between keys restored
 *                    by same backup"). Its public key names whose bucket it is (id: identityIdOf). Any OnlyKey since
 *                    2.1.0 derives it - Edge or not, v3.0.4 included. Never called "identity" alone: Edge identifies
 *                    itself its own way (a key and a salt), a different thing.
 *   BUCKET KEY       an Ed25519 key pair on the host, made from a secret only the key can make: its ECDH between
 *                    the X25519 keys of IDENTITY_LABEL and KEY_LABEL. The same backup gives the same bucket key on
 *                    every device. It signs, host-side and with no press, what a device of the identity has to
 *                    prove: a fresh challenge, a GIVE, a peer it accepts.
 *   CERTIFICATE      the bucket identity's signature, made on the key, over the bucket key's public key. Ed25519
 *                    is deterministic, so every device of the identity holds the same one; anyone checks it with
 *                    the bucket identity's public key alone.
 *
 * THE SECOND LABEL IS DOMAIN-SEPARATED. The agent derives from a 32-byte hash, and an SSH identity is sha256("host"):
 * a bare sha256("bucket") would BE the ssh key of a host named "bucket" - one key for two jobs. "" is no ssh host
 * (ssh needs one) and no gpg id (those hash "gpg://..."), so the identity's label stays the plain empty one.
 *
 * PRESSES (field 21, derived keys - a press on production firmware, which refuses None there): the ECDH and the
 * certificate's signature, once per device. Reading the bucket identity needs none.
 *
 * Agent version 1 (every release from 2.1.0): version 2 derives DIFFERENT keys, and the bucket identity must be the
 * same on a 3.0.4 key and a 3.1.0 key restored from one backup.
 *
 * Pure: the device is reached only through the okcrypto handed in; no Node built-ins.
 */

const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { hkdf } = require('../../src/vendor/exports/@noble/hashes/hkdf.js');
const { ed25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');
const { toHex } = require('../../src/bytes');

const IDENTITY_LABEL = '';
const KEY_LABEL = 'onlykey-bucket/key';
const AGENT = { version: 1 };
const ED25519 = 1;
const CURVE25519 = 4;

const utf8 = (s) => new TextEncoder().encode(s);
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const H = (domain, ...parts) => sha256(concat(utf8(domain), ...parts.map((p) => Uint8Array.from(p))));
const labelHash = (label) => sha256(utf8(label));

/** Is this a bucket identity id (32 lowercase hex)? */
const isBucketIdentityId = (s) => typeof s === 'string' && /^[0-9a-f]{32}$/.test(s);

/** The id a bucket identity's public key goes by: 32 hex characters (the bucket's owner, its file name). */
function identityIdOf(identityPublicKey) {
  return toHex(H('OKBUCKET-ID-v1', identityPublicKey)).slice(0, 32);
}

/**
 * Read the key's bucket identity - no press.
 * @param {{agent: {publicKey: Function}}} okcrypto
 * @returns {Promise<{publicKey: Uint8Array, id: string}>}
 */
async function readIdentity(okcrypto, opts = {}) {
  const publicKey = Uint8Array.from(await okcrypto.agent.publicKey(labelHash(IDENTITY_LABEL), { ...opts, ...AGENT, keyType: ED25519 }));
  return { publicKey, id: identityIdOf(publicKey) };
}

/**
 * Make the bucket key: the key's ECDH between its two bucket X25519 keys (a press on production), turned into an
 * Ed25519 key pair on the host.
 * @param {{agent: {publicKey: Function, ecdh: Function}}} okcrypto
 * @param {Uint8Array} identityPublicKey the bucket identity (readIdentity) - it names whose bucket key this is
 * @param {object} [opts] passed to the key (confirm, onKeepAlive)
 * @returns {Promise<{secretKey: Uint8Array, publicKey: Uint8Array}>}
 */
async function deriveBucketKey(okcrypto, identityPublicKey, opts = {}) {
  const peer = await okcrypto.agent.publicKey(labelHash(KEY_LABEL), { ...AGENT, keyType: CURVE25519 });
  const shared = Uint8Array.from(await okcrypto.agent.ecdh(labelHash(IDENTITY_LABEL), peer, { ...opts, ...AGENT, keyType: CURVE25519 }));
  try {
    const secretKey = hkdf(sha256, shared, utf8('OKBUCKET-KEY-v1'), Uint8Array.from(identityPublicKey), 32);
    return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
  } finally {
    shared.fill(0);
  }
}

const certDigest = (identityPublicKey, bucketPublicKey) => H('OKBUCKET-CERT-v1', identityPublicKey, bucketPublicKey);

/**
 * The bucket identity signs the bucket key's public key, on the key (a press on production).
 * @returns {Promise<Uint8Array>} the 64-byte certificate signature
 */
async function certify(okcrypto, identityPublicKey, bucketPublicKey, opts = {}) {
  const sig = await okcrypto.agent.sign(labelHash(IDENTITY_LABEL), certDigest(identityPublicKey, bucketPublicKey), { ...opts, ...AGENT, keyType: ED25519 });
  return Uint8Array.from(sig).slice(0, 64);
}

/** Is this bucket key certified by this bucket identity? Never throws: false on anything malformed. */
function verifyCertificate({ identityPublicKey, bucketPublicKey, certificate }) {
  try {
    return ed25519.verify(Uint8Array.from(certificate), certDigest(identityPublicKey, bucketPublicKey), Uint8Array.from(identityPublicKey));
  } catch {
    return false;
  }
}

/*
 * What the bucket key signs, each under its own domain so a signature for one is never one for another:
 * 'proof' (a fresh challenge), 'give' (a GIVE's bytes), 'accept' / 'revoke' (a peer's public key), 'join' (a server's
 * challenge to enter the identity's room, room.js - its own domain, so a server can never turn a device's join into a
 * trade proof for a peer, nor a peer's trade challenge into a join).
 */
const PURPOSES = new Set(['proof', 'give', 'accept', 'revoke', 'join']);
const purposeDigest = (purpose, bytes) => {
  if (!PURPOSES.has(purpose)) throw new Error(`the bucket key signs ${[...PURPOSES].join(', ')} - not ${purpose}`);
  return H(`OKBUCKET-${purpose.toUpperCase()}-v1`, bytes);
};

/** Sign with the bucket key, host-side, no press. */
function sign(bucketKey, purpose, bytes) {
  return ed25519.sign(purposeDigest(purpose, Uint8Array.from(bytes)), bucketKey.secretKey);
}

/**
 * Is this signed by a bucket key of this bucket identity? The certificate and the signature both, or false.
 * @param {{identityPublicKey: Uint8Array, bucketPublicKey: Uint8Array, certificate: Uint8Array, purpose: string, bytes: Uint8Array, signature: Uint8Array}} o
 */
function verify({ identityPublicKey, bucketPublicKey, certificate, purpose, bytes, signature }) {
  try {
    return verifyCertificate({ identityPublicKey, bucketPublicKey, certificate })
      && ed25519.verify(Uint8Array.from(signature), purposeDigest(purpose, Uint8Array.from(bytes)), Uint8Array.from(bucketPublicKey));
  } catch {
    return false;
  }
}

module.exports = { IDENTITY_LABEL, KEY_LABEL, isBucketIdentityId, identityIdOf, readIdentity, deriveBucketKey, certify, verifyCertificate, sign, verify };
