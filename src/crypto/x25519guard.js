/**
 * X25519 on the HOST side of the wire: refuse the points and the secrets that
 * mean "no key agreement happened".
 *
 * ## Why the library guards, when firmware 8d28305 already does
 *
 * Release 3.1.0 (libraries 8d28305) refuses an all-zero X25519 shared secret on
 * the device. This library serves every supported firmware line - the
 * compatibility target is v3.0.4, the last signed release, which has no such
 * check - so "the device will catch it" is true for one line and not for the
 * others. And some of what is guarded here never reaches the device at all.
 *
 * ## What goes wrong without it
 *
 * X25519 of any scalar with a LOW-ORDER point (order 1, 2, 4 or 8) lands on
 * the identity, and the output is 32 zero bytes. Nothing fails: tweetnacl's
 * `box.before` runs HSalsa20 over those zeros and returns ONE fixed value
 * (351f86fa..., whatever our secret key), sha256 of it is a perfectly
 * good-looking transit key, and every message sealed under it can be opened by
 * anyone who sent that point - which is exactly the party that should not be
 * able to. Because box.before hides the zeros, the point itself has to be
 * checked, before the ladder, as noble does. The same holds for a secret a
 * device answers with: 32 zero bytes are an ECDH result only for a peer point
 * chosen to produce them.
 *
 * The vendored @noble/curves 2.4.0 already rejects low-order u BEFORE its
 * ladder (abstract/montgomery.js, `lowOrderU`), so session/transit.js,
 * crypto/age_pqc.js and webcrypto/subtle.js are covered by it. These helpers
 * are for the paths noble does not see: tweetnacl's box.before in
 * okconnect.transitKey, peer points the host SENDS to a device to use, and the
 * secrets a device RETURNS (okconnect.sharedSecretFrom, okcrypto.agent.ecdh).
 *
 * ## The list, and why it is bytes
 *
 * Every 32-byte string that decodes (RFC 7748 section 5: mask bit 255, reduce mod
 * p = 2^255 - 19) to a point of order dividing 8. Five values of u -
 * 0, 1, p - 1 and the two order-8 points - which are noble's `lowOrderU` set
 * exactly, plus the two non-canonical encodings that still fit in 255 bits
 * and reduce onto them: p (= 0) and p + 1 (= 1). No other non-canonical form
 * exists, because p + 19 = 2^255 and every other value on the list is above 18.
 * This is the same seven-entry list libsodium keeps (crypto_scalarmult
 * curve25519 `blacklist`) and D. J. Bernstein's "validate" note
 * (https://cr.yp.to/ecdh.html#validate) describes.
 *
 * Byte strings rather than BigInt so this file carries no BigInt at all:
 * nothing else under src/ outside the vendored libraries uses it, and the
 * comparison is a table lookup either way. The test proves the list equal to
 * noble's by decoding each entry with BigInt there.
 */
'use strict';

const { fromHex } = require('../bytes');

/** Little-endian encodings, bit 255 clear. See the note above for each. */
const LOW_ORDER_U = [
  /* 0 - order 4 */
  '0000000000000000000000000000000000000000000000000000000000000000',
  /* 1 - order 1 (the identity's u) */
  '0100000000000000000000000000000000000000000000000000000000000000',
  /* 325606250916557431795983626356110631294008115727848805560023387167927233504 - order 8 */
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
  /* 39382357235489614581723060781553021112529911719440698176882885853963445705823 - order 8 */
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
  /* p - 1 - order 2 */
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  /* p, which reduces to 0 */
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  /* p + 1, which reduces to 1 */
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
].map((hex) => fromHex(hex));

function lowOrderError(message) {
  const err = new Error(message);
  err.code = 'LOW_ORDER_POINT';
  return err;
}

/**
 * Whether a 32-byte X25519 u-coordinate is one of the low-order encodings.
 *
 * Bit 255 is masked first, as RFC 7748 section 5 says a receiver MUST, so 0x80 in
 * the last byte cannot smuggle a listed point past the comparison. Every entry
 * is compared in full, whatever matched first - the answer is about a PUBLIC
 * key, but there is no reason to make the time depend on which one.
 *
 * @param {Uint8Array} u
 * @returns {boolean}
 */
function isLowOrderU(u) {
  if (!u || u.length !== 32) {
    throw new TypeError(`an X25519 public key is 32 bytes; got ${u ? u.length : u}`);
  }
  let found = 0;
  for (const listed of LOW_ORDER_U) {
    let diff = 0;
    for (let i = 0; i < 31; i++) diff |= u[i] ^ listed[i];
    diff |= (u[31] & 0x7f) ^ listed[31];
    found |= diff === 0 ? 1 : 0;
  }
  return found === 1;
}

/**
 * Refuse an X25519 peer point of low order, before it is used or sent.
 *
 * @param {Uint8Array} u      the peer's 32-byte u-coordinate
 * @param {string} [what]     named in the error: whose point it was
 */
function assertPeerNotLowOrder(u, what = 'the peer X25519 public key') {
  if (isLowOrderU(Uint8Array.from(u))) {
    throw lowOrderError(
      `${what} is a LOW-ORDER point, so X25519 with it yields 32 zero bytes - `
      + 'a "shared" secret its sender already knows. Refused rather than used.',
    );
  }
}

/**
 * Refuse an all-zero shared secret - RFC 7748 section 6.1's own check.
 *
 * Applied to every secret a device RETURNS, not only X25519 ones: an all-zero
 * ECDH result is what a low-order peer produces on the 25519 curves, and on
 * P-256 or secp256k1 it is not a value real ECDH produces at all, so it can
 * only mean a zero-filled buffer or a peer chosen to produce it.
 *
 * @param {Uint8Array} secret
 * @param {string} [what]
 */
function assertNonZeroSecret(secret, what = 'the shared secret') {
  let acc = 0;
  for (let i = 0; i < secret.length; i++) acc |= secret[i];
  if (!secret.length || acc === 0) {
    throw lowOrderError(
      `${what} is all zeros - the output of X25519 with a low-order point (RFC `
      + '7748 section 6.1), not a key agreement. Refused rather than used.',
    );
  }
}

module.exports = {
  LOW_ORDER_U,
  isLowOrderU,
  assertPeerNotLowOrder,
  assertNonZeroSecret,
};
