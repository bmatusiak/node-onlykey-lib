/*
 * cose.js - the one COSE_Key shape CTAP2 PIN handling needs: P-256.
 *
 * A clientPin exchange is an ECDH: the platform sends its own public key as a
 * COSE_Key and the authenticator answers with its own. That is the only place
 * a key crosses this wire, so this module encodes and decodes exactly that
 * and refuses everything else, rather than being a general COSE library that
 * would have to guess what an unknown curve means.
 *
 * ## Why the labels are negative, and why that decides the order
 *
 * COSE numbers the common key parameters 1 (kty) and 3 (alg), and the
 * curve-specific ones downwards from -1 (crv, x, y). The firmware parses the
 * map with `CborValidateCanonicalFormat` (ctap_parse.cpp:1437), which is
 * tinycbor's length-first-then-bytewise ordering over the ENCODED key bytes -
 * not over their numeric values. Encoded, those five labels are 0x01, 0x03,
 * 0x20, 0x21, 0x22, so canonical order is 1, 3, -1, -2, -3: the negatives
 * come last, even though they are the smaller numbers. cbor.js already sorts
 * this way (cbor.js:111), so a Map built here comes out right without this
 * module ordering anything itself - but get it wrong and the authenticator
 * rejects the whole request as invalid CBOR, which reads like a transport
 * fault rather than a field-order one.
 *
 * ## What the firmware actually checks
 *
 * parse_cose_key (ctap_parse.cpp:1329-1424) reads kty, crv, x and y, IGNORES
 * alg entirely, and fails only if one of the four is missing or zero. It does
 * not verify that kty is EC2 or that crv is P-256; it just uses the 64 bytes.
 * We send the correct values anyway, because the next authenticator to see
 * these bytes may be someone else's and the spec is what it agrees to.
 */
'use strict';

/** COSE_Key common and EC2 labels (RFC 8152 tables 3 and 5). */
const LABEL = {
  KTY: 1,
  ALG: 3,
  CRV: -1,
  X: -2,
  Y: -3,
};

const KTY_EC2 = 2;
const CRV_P256 = 1;

/**
 * ECDH-ES + HKDF-256, which is what the authenticator says its key agreement
 * key is for (ctap.cpp:2247 passes COSE_ALG_ECDH_ES_HKDF_256). The name is
 * misleading here: PIN protocol 1 does NOT run HKDF. The shared secret is a
 * bare SHA-256 of the ECDH x coordinate - see clientpin.js.
 */
const ALG_ECDH_ES_HKDF_256 = -25;

/** ES256, for reading a credential public key out of an attestation. */
const ALG_ES256 = -7;

const COORD = 32;

function coords(publicKey) {
  const key = Uint8Array.from(publicKey);
  if (key.length === 65) {
    if (key[0] !== 0x04) {
      throw new Error(
        'a 65-byte P-256 public key must start with 0x04 (uncompressed); ' +
          'compressed points have to be decompressed before they get here',
      );
    }
    return [key.subarray(1, 33), key.subarray(33, 65)];
  }
  if (key.length === 64) return [key.subarray(0, 32), key.subarray(32, 64)];
  throw new Error(`a P-256 public key is 64 or 65 bytes, got ${key.length}`);
}

/**
 * A P-256 public key as a COSE_Key map, ready to hand to cbor.encode.
 *
 * @param {Uint8Array} publicKey  65-byte uncompressed (0x04 || x || y) or the
 *                                bare 64-byte x || y
 * @param {number} [alg]          defaults to ECDH-ES+HKDF-256, the only one
 *                                a clientPin key agreement ever uses
 * @returns {Map<number, *>}
 */
function encodeP256(publicKey, alg = ALG_ECDH_ES_HKDF_256) {
  const [x, y] = coords(publicKey);
  return new Map([
    [LABEL.KTY, KTY_EC2],
    [LABEL.ALG, alg],
    [LABEL.CRV, CRV_P256],
    [LABEL.X, Uint8Array.from(x)],
    [LABEL.Y, Uint8Array.from(y)],
  ]);
}

/**
 * Read a P-256 COSE_Key back.
 *
 * @param {Map<number, *>} map  a decoded CBOR map
 * @returns {{x: Uint8Array, y: Uint8Array, uncompressed: Uint8Array,
 *            kty: number, alg: number|undefined, crv: number}}
 *
 * `uncompressed` is the 0x04-prefixed 65-byte form, because that is what
 * every ECDH implementation on this side takes as input.
 *
 * kty and crv ARE checked here, unlike on the firmware side. A key that says
 * it is P-384 and carries 32-byte coordinates is not a key we can do anything
 * useful with, and silently treating it as P-256 would produce a shared
 * secret that simply differs from the peer's with no error anywhere.
 */
function decodeP256(map) {
  if (!(map instanceof Map)) throw new Error('a COSE_Key decodes to a CBOR map');

  const kty = map.get(LABEL.KTY);
  const crv = map.get(LABEL.CRV);
  const x = map.get(LABEL.X);
  const y = map.get(LABEL.Y);

  if (kty !== KTY_EC2) throw new Error(`COSE_Key kty is ${kty}, expected ${KTY_EC2} (EC2)`);
  if (crv !== CRV_P256) throw new Error(`COSE_Key crv is ${crv}, expected ${CRV_P256} (P-256)`);
  if (!(x instanceof Uint8Array) || x.length !== COORD) {
    throw new Error('COSE_Key x is not a 32-byte string');
  }
  if (!(y instanceof Uint8Array) || y.length !== COORD) {
    throw new Error('COSE_Key y is not a 32-byte string');
  }

  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(x, 1);
  uncompressed.set(y, 33);

  return { x, y, uncompressed, kty, alg: map.get(LABEL.ALG), crv };
}

module.exports = {
  LABEL,
  KTY_EC2,
  CRV_P256,
  ALG_ECDH_ES_HKDF_256,
  ALG_ES256,
  encodeP256,
  decodeP256,
};
