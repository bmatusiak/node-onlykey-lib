'use strict';

/**
 * Making a key ON THE HOST - Key Chain's second choice.
 *
 * The first choice is the OnlyKey itself (device.generateEccKey /
 * device.generateKey): the private key is born there and no copy exists
 * anywhere. This is for what the device cannot make - RSA, and the composite
 * post-quantum key (crypto/composite_pgp.js) - and for a key the owner wants
 * to use somewhere that is not an OnlyKey. It lives in memory: the caller
 * loads it (device.loadKey with `material`), exports an encrypted copy
 * (keychain.export), or both, and then calls wipe().
 *
 * RSA comes from WebCrypto's generateKey - the platform's own on Node and in
 * a browser; under Hermes the lib's shim, which generates only when the host
 * lent it a generator (webcrypto/subtle install({ rsaGenerate }): Android's,
 * in ok-rn). Sizes 2048, 3072 and 4096 (owner): 1024 is too weak to create
 * now, though a 1024-bit key made elsewhere still loads.
 */

const { ed25519, x25519 } = require('../vendor/exports/@noble/curves/ed25519.js');
const { p256 } = require('../vendor/exports/@noble/curves/nist.js');
const { secp256k1 } = require('../vendor/exports/@noble/curves/secp256k1.js');
const { randomBytes } = require('../vendor/exports/@noble/ciphers/utils.js');
const { fromBase64Url } = require('../bytes');
const keys = require('../device/keys');

const RSA_BITS = Object.freeze([2048, 3072, 4096]);

/* What each ECC type is to the device (keys.KEY_TYPE) and how its public key is made. */
const ECC = {
  ed25519: { keyType: keys.KEY_TYPE.ED25519, pub: (s) => ed25519.getPublicKey(s), secret: () => randomBytes(32) },
  x25519: { keyType: keys.KEY_TYPE.CURVE25519, pub: (s) => x25519.getPublicKey(s), secret: () => x25519.utils.randomSecretKey() },
  p256: { keyType: keys.KEY_TYPE.P256R1, pub: (s) => p256.getPublicKey(s, false).slice(1), secret: () => p256.utils.randomSecretKey() },
  secp256k1: { keyType: keys.KEY_TYPE.P256K1, pub: (s) => secp256k1.getPublicKey(s, false).slice(1), secret: () => secp256k1.utils.randomSecretKey() },
};

/** Left-pad to the prime length the device's slot layout wants (prepareKey). */
function padTo(bytes, length) {
  if (bytes.length > length) throw new Error(`an RSA prime of ${bytes.length} bytes does not fit ${length}`);
  const out = new Uint8Array(length);
  out.set(bytes, length - bytes.length);
  return out;
}

/**
 * Make a key on this host.
 *
 * @param {'ed25519'|'x25519'|'p256'|'secp256k1'|'rsa'} type
 * @param {{bits?: number, subtle?: any}} [opts] bits for RSA; subtle defaults to globalThis.crypto.subtle
 * @returns {Promise<{type: string, publicKey: Uint8Array, keyType: number,
 *   secret?: Uint8Array, p?: Uint8Array, q?: Uint8Array, e?: number, bits?: number,
 *   material: object}>} `material` is what keys.prepareKey / device.loadKey take
 */
async function hostKey(type, { bits = 2048, subtle = globalThis.crypto && globalThis.crypto.subtle } = {}) {
  if (ECC[type]) {
    const spec = ECC[type];
    const secret = spec.secret();
    return {
      type,
      keyType: spec.keyType,
      secret,
      publicKey: spec.pub(secret),
      material: { kind: 'ecc', curve: spec.keyType, scalar: secret },
    };
  }
  if (type === 'rsa') {
    if (!RSA_BITS.includes(bits)) {
      throw new Error(`Key Chain makes RSA keys of ${RSA_BITS.join(', ')} bits; ${bits} is not one`);
    }
    if (!subtle) throw new Error('no WebCrypto here to make an RSA key with (install the shim with an rsaGenerate host hook)');
    const pair = await subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: bits, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' },
      true, ['sign', 'verify'],
    );
    const jwk = await subtle.exportKey('jwk', pair.privateKey);
    const half = bits / 16;
    const p = padTo(fromBase64Url(jwk.p), half);
    const q = padTo(fromBase64Url(jwk.q), half);
    return {
      type: 'rsa',
      bits,
      keyType: bits / 1024,
      p,
      q,
      e: 65537,
      publicKey: fromBase64Url(jwk.n),
      material: { kind: 'rsa', p, q },
    };
  }
  throw new Error(
    `hostKey makes ${Object.keys(ECC).join(', ')} and rsa; for "${type}" use the device `
    + '(ML-KEM, X-Wing) or crypto/composite_pgp (the composite key)',
  );
}

/** Zero every byte array a hostKey() result holds. Call it once the key is loaded or exported. */
function wipe(key) {
  if (!key) return;
  for (const v of [key.secret, key.p, key.q, key.material && key.material.scalar,
    key.material && key.material.p, key.material && key.material.q]) {
    if (v && typeof v.fill === 'function') v.fill(0);
  }
}

module.exports = { RSA_BITS, hostKey, wipe };
