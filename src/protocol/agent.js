/*
 * agent.js - AGENT DERIVATION: SSH and GPG keys the device derives from an
 * identity, never stored and never leaving it. What lib-agent (onlykey-agent,
 * onlykey-gpg) drives, as a pure description: the codes, the identity hash,
 * and the shapes of the replies. plugins/okcrypto's `agent` does the I/O.
 *
 * Read at release 3.1.0 (libraries eb25290 / bm-ok 213e670) and lib-agent
 * master; firmware lines are okcrypto.cpp unless named.
 *
 * ## Two derivations, chosen by the code the host sends
 *
 *   v1  public key 132, sign 200+type, ECDH 200+type
 *       sk = SHA256(K132 || hash)                               (:733-741)
 *   v2  public key 232, sign 220+type, ECDH 220+type
 *       sk = HKDF-SHA256(salt = 0x20 || hash, IKM = K132,
 *                        info = "onlykey/agent/v2", L = 32)     (:763-772)
 *
 * K132 is a random per-device secret that cannot be written (okcore.cpp
 * 3052-3058, 423-426), so there are no cross-device vectors: the same identity
 * gives a different key on every OnlyKey, by design. v1 is every release from
 * 2.1.0 and lib-agent's default; v2 is 3.0.5 on, opt-in in lib-agent
 * (`--skey derived-v2`) - they are DIFFERENT KEYS for the same identity, so a
 * host must keep using whichever one a server already trusts.
 *
 * ## The identity hash
 *
 * lib-agent hashes a string with SHA-256 and sends those 32 bytes:
 *   SSH  "user@host" (just "host" without a user) - no protocol, port or path
 *        (lib-agent libagent/device/onlykey.py:273-278)
 *   GPG  "gpg://" + the user id (gpg/client.py:13-14)
 * lib-agent passes the string through unidecode() first, a transliteration
 * table this library does not carry; an identity with non-ASCII characters is
 * REFUSED here rather than hashed differently, because a different hash is a
 * different key and nothing would say so.
 *
 * ## Replies - one 64-byte report each
 *
 *   public key  P-256 / secp256k1: X||Y (no 04 prefix); Ed25519 / X25519:
 *               32 bytes then 32 zeros                          (:387)
 *   signature   64 bytes, R||S (Ed25519) or r||s (ECDSA)        (:898-900)
 *   ECDH        X25519: 32 bytes then zeros; P-256 / k1: the shared point
 *               X||Y, 64                                        (:967, 1139-1148)
 * Errors come back as "Error ..." text, e.g. "Error invalid derived key slot"
 * for sign with type 4 or ECDH with type 1 (:808-813, 937-941).
 */
'use strict';

const { sha256 } = require('../vendor/exports/@noble/hashes/sha2.js');

const KEY_TYPE = { ED25519: 1, P256R1: 2, P256K1: 3, CURVE25519: 4 };

const VERSIONS = {
  1: { publicKey: 132, base: 200 },
  2: { publicKey: 232, base: 220 },
};

/* Sign has no X25519; ECDH has no Ed25519 - the firmware refuses both. */
const SIGN_TYPES = [KEY_TYPE.ED25519, KEY_TYPE.P256R1, KEY_TYPE.P256K1];
const ECDH_TYPES = [KEY_TYPE.P256R1, KEY_TYPE.P256K1, KEY_TYPE.CURVE25519];

function codesFor(version) {
  const v = VERSIONS[version];
  if (!v) throw new Error(`agent derivation is version 1 or 2, not ${version}`);
  return v;
}

function checkType(keyType, allowed, what) {
  if (!allowed.includes(keyType)) {
    throw new Error(`agent ${what} takes key type ${allowed.join(', ')}; ${keyType} is not one of them`);
  }
}

/** The public-key code (132 or 232). */
function publicKeyCode(version, keyType) {
  checkType(keyType, [...SIGN_TYPES, KEY_TYPE.CURVE25519], 'public key');
  return codesFor(version).publicKey;
}

/** The OKSIGN slot code (201-203 or 221-223). */
function signCode(version, keyType) {
  checkType(keyType, SIGN_TYPES, 'signing');
  return codesFor(version).base + keyType;
}

/** The OKDECRYPT slot code for ECDH (202-204 or 222-224). */
function ecdhCode(version, keyType) {
  checkType(keyType, ECDH_TYPES, 'ECDH');
  return codesFor(version).base + keyType;
}

function ascii(text, what) {
  if (typeof text !== 'string' || !text) throw new Error(`${what} must be a non-empty string`);
  if (!/^[\x20-\x7e]*$/.test(text)) {
    throw new Error(
      `${what} ${JSON.stringify(text)} is not printable ASCII; lib-agent transliterates it with `
      + 'unidecode first, which this library does not carry - it would derive a different key',
    );
  }
  return new TextEncoder().encode(text);
}

/**
 * The 32 bytes a derivation is keyed by.
 *
 * @param {Uint8Array|{ssh: {user?: string, host: string}}|{gpg: string}} identity
 *   a ready hash (32 bytes), or what lib-agent hashes
 */
function identityHash(identity) {
  if (identity instanceof Uint8Array) {
    if (identity.length !== 32) throw new Error(`an identity hash is 32 bytes, not ${identity.length}`);
    return identity;
  }
  if (identity && identity.ssh) {
    const { user, host } = identity.ssh;
    const hostBytes = ascii(host, 'the SSH host');
    return sha256(user ? ascii(`${user}@${host}`, 'the SSH identity') : hostBytes);
  }
  if (identity && typeof identity.gpg === 'string') {
    return sha256(ascii(`gpg://${identity.gpg}`, 'the GPG user id'));
  }
  throw new Error('an agent identity is a 32-byte hash, { ssh: { user, host } } or { gpg: userId }');
}

/** How many bytes of the 64-byte report are the public key. */
function publicKeyLength(keyType) {
  return keyType === KEY_TYPE.P256R1 || keyType === KEY_TYPE.P256K1 ? 64 : 32;
}

/** How many bytes of the 64-byte report are the ECDH result. */
function sharedSecretLength(keyType) {
  return keyType === KEY_TYPE.CURVE25519 ? 32 : 64;
}

module.exports = {
  KEY_TYPE,
  VERSIONS,
  SIGN_TYPES,
  ECDH_TYPES,
  publicKeyCode,
  signCode,
  ecdhCode,
  identityHash,
  publicKeyLength,
  sharedSecretLength,
};
