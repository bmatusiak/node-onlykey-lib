'use strict';

/**
 * IMPORT A PGP PUBLIC KEY BACK INTO KEY CHAIN (owner, 2026-10-03).
 *
 * A device backup carries the PRIVATE keys (ECC1/ECC2 for a PGP pair made in
 * the key), but the certificate - the public keys, the user id and the two
 * self-signatures PGP software imports - lives in the App's list, not on the
 * key. Restoring a phone therefore takes two files: the OnlyKey backup and
 * the PGP public key (.asc). This module is the second half.
 *
 * Re-signing on the new phone would NOT do: the fingerprint covers the
 * creation time, so a fresh certificate is a different PGP key from the one
 * already published (GitHub, keyservers). The old certificate is imported.
 *
 * BEFORE IT LANDS, three checks, in order (owner: "confirm the pubkeys match
 * the privates"):
 *   1. inspect()        the certificate is genuine - its self-signatures
 *                       verify with its own primary key (no device);
 *   2. matchSlots()     its keys are this OnlyKey's - the primary equals what
 *                       a signing slot reports, the encryption subkey what a
 *                       decrypt slot reports. The key COMPUTES those from its
 *                       private keys, so a file cannot fake a match (no press);
 *   3. proveSlots()     the private keys work now - the signing slot signs a
 *                       fresh challenge that verifies with the certificate's
 *                       key; the decrypt slot's ECDH with a throwaway key
 *                       equals the host's ECDH with the certificate's subkey
 *                       (the device's hooks; a press each).
 * Only then entryFor() makes the list entry. Public data only, as list.js
 * insists.
 *
 * openpgp is passed in, as composite and pgp-cert take it: this module stays
 * plain, and Hermes-clean (vendored @noble only).
 */

const { ed25519, x25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');

/* OpenPGP public-key algorithm ids (RFC 9580 9.1) */
const ALG = { RSA: [1, 2, 3], ECDH: 18, ECDSA: 19, EDDSA_LEGACY: 22, X25519: 25, ED25519: 27 };

/* noble's randomBytes, as age_file and pkcs8 use it - not a bare crypto global (bytes.js says why) */
const { randomBytes } = require('../../src/vendor/exports/@noble/ciphers/utils.js');

const eq = (a, b) => a && b && a.length === b.length && a.every((v, i) => v === b[i]);

/*
 * A packet's public key as the DEVICE reports it, and its type: the 25519
 * curves in OpenPGP's "native" form 0x40 || 32 bytes (pgp-cert.js point())
 * -> the 32 bytes; P-256 0x04 || X || Y -> X || Y (the device's 64 bytes);
 * RSA -> the modulus. role: 'sign' or 'ecdh'.
 */
function keyOf(packet) {
  const a = packet.algorithm;
  const p = packet.publicParams || {};
  const curve = p.oid && typeof p.oid.getName === 'function' ? p.oid.getName() : null;
  if (a === ALG.EDDSA_LEGACY && curve === 'ed25519Legacy') return { type: 'ed25519', role: 'sign', bytes: p.Q.slice(1) };
  if (a === ALG.ED25519) return { type: 'ed25519', role: 'sign', bytes: Uint8Array.from(p.A) };
  if (a === ALG.ECDH && curve === 'curve25519Legacy') return { type: 'x25519', role: 'ecdh', bytes: p.Q.slice(1) };
  if (a === ALG.X25519) return { type: 'x25519', role: 'ecdh', bytes: Uint8Array.from(p.A) };
  if ((a === ALG.ECDSA || a === ALG.ECDH) && curve === 'p256') {
    return { type: 'p256', role: a === ALG.ECDSA ? 'sign' : 'ecdh', bytes: p.Q.slice(1) };
  }
  if (ALG.RSA.includes(a)) return { type: 'rsa', role: a === 2 ? 'ecdh' : 'sign', bytes: Uint8Array.from(p.n) };
  return null;
}

/**
 * Check 1: read the armored PUBLIC key and verify its self-signatures.
 * -> {key, userId, fingerprint, primary: {type, bytes}, encryption: {type, bytes} | null}
 * Throws on a private key block, an unreadable file or a self-signature that
 * does not verify.
 */
async function inspect(openpgp, armored) {
  if (typeof armored !== 'string' || !armored.trim()) throw new Error('no PGP key given');
  if (/BEGIN PGP PRIVATE KEY BLOCK/.test(armored)) {
    throw new Error('that is a PRIVATE key block - Key Chain keeps public keys only; import the public key (.asc)');
  }
  let key;
  try {
    key = await openpgp.readKey({ armoredKey: armored });
  } catch (e) {
    throw new Error(`not a PGP public key: ${e.message || e}`);
  }
  if (key.isPrivate()) throw new Error('that is a private key - Key Chain keeps public keys only');
  /* the primary key's self-certification over its user id (and the subkey bindings) */
  try {
    await key.verifyPrimaryKey();
  } catch (e) {
    throw new Error(`the certificate's self-signature does not verify - not genuine, or damaged: ${e.message || e}`);
  }
  const primary = keyOf(key.keyPacket);
  if (!primary) throw new Error(`a primary key of algorithm ${key.keyPacket.algorithm} is not one an OnlyKey holds`);
  let encryption = null;
  for (const sub of key.subkeys || []) {
    const k = keyOf(sub.keyPacket);
    if (!k || k.role !== 'ecdh') continue;
    try {
      await sub.verify(); /* the binding signature, made by the primary */
    } catch (e) {
      throw new Error(`the encryption subkey's binding does not verify: ${e.message || e}`);
    }
    encryption = k;
    break;
  }
  const userId = (key.getUserIDs() || [])[0] || '';
  return { key, userId, fingerprint: key.getFingerprint().toUpperCase(), primary, encryption };
}

/**
 * Check 2: which of this OnlyKey's slots hold the certificate's keys.
 * probes: [{slot, kind, publicKey}] as device.probeKeySlot / Key Chain's
 * readSlots return them. -> {signSlot, ecdhSlot} (null where none matches)
 */
function matchSlots(info, probes) {
  const find = (k) => (k ? (probes || []).find((p) => p.kind === k.type && p.publicKey && eq(Uint8Array.from(p.publicKey), k.bytes)) : null);
  const s = find(info.primary);
  const e = find(info.encryption);
  return { signSlot: s ? s.slot : null, ecdhSlot: e ? e.slot : null };
}

/**
 * Check 3: the slots' private keys work now and are the certificate's.
 * hooks.sign(slot, digest32) -> 64-byte signature (okcrypto.sign);
 * hooks.ecdh(slot, peerPublic) -> 32-byte shared secret (okcrypto.ecdh).
 * Each asks the key, so each is a press. -> {sign: true|null, ecdh: true|null};
 * throws naming the check that failed.
 */
async function proveSlots(info, match, hooks) {
  const out = { sign: null, ecdh: null };
  if (match.signSlot !== null && info.primary.type === 'ed25519') {
    const challenge = randomBytes(32);
    const sig = await hooks.sign(match.signSlot, challenge);
    if (!sig || !ed25519.verify(Uint8Array.from(sig).subarray(0, 64), challenge, info.primary.bytes)) {
      throw new Error('the signing slot\'s test signature does not verify with the certificate\'s key - they are not a pair');
    }
    out.sign = true;
  } else if (match.signSlot !== null && info.primary.type === 'p256') {
    const challenge = randomBytes(32);
    const sig = await hooks.sign(match.signSlot, challenge);
    const pub = Uint8Array.from([4, ...info.primary.bytes]);
    if (!sig || !p256.verify(Uint8Array.from(sig).subarray(0, 64), challenge, pub, { prehash: false })) {
      throw new Error('the signing slot\'s test signature does not verify with the certificate\'s key - they are not a pair');
    }
    out.sign = true;
  }
  if (match.ecdhSlot !== null && info.encryption && info.encryption.type === 'x25519') {
    const eph = randomBytes(32);
    const ephPub = x25519.getPublicKey(eph);
    const fromKey = await hooks.ecdh(match.ecdhSlot, ephPub);
    const expected = x25519.getSharedSecret(eph, info.encryption.bytes);
    eph.fill(0);
    if (!fromKey || !eq(Uint8Array.from(fromKey).subarray(0, 32), expected)) {
      throw new Error('the decrypt slot\'s key exchange does not match the certificate\'s encryption key - they are not a pair');
    }
    out.ecdh = true;
  }
  return out;
}

/**
 * The Key Chain list entry (list.createEntry input), shaped like the one Key
 * Chain makes for a PGP pair made in the key: kind 'external', the slots it
 * is linked to (decrypt first, as the maker writes them), the certificate.
 * Slots only when PROVEN; otherwise someone's key to encrypt to.
 */
function entryFor(info, match, proven) {
  const linked = proven && (proven.sign || proven.ecdh);
  const slots = linked ? [match.ecdhSlot, match.signSlot].filter((s) => s !== null) : undefined;
  return {
    kind: 'external',
    name: info.userId || info.fingerprint,
    ...(slots && slots.length ? { slots } : {}),
    type: info.primary.type,
    publicKey: info.primary.bytes,
    pgp: info.key.armor(),
  };
}

module.exports = { inspect, matchSlots, proveSlots, entryFor, keyOf };
