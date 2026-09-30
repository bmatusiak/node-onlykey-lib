/*
 * src/crypto/x25519guard - the host refuses low-order X25519 points and
 * all-zero shared secrets on the paths the vendored noble check does not see
 * (G-12 of the G1 audit).
 *
 * The vectors are the seven low-order encodings (RFC 7748 section 5 decoding;
 * the same list as libsodium's `blacklist` and noble's `lowOrderU` plus its two
 * non-canonical aliases). They are PROVED here rather than trusted: each one
 * is decoded with BigInt into noble's set, noble's x25519 refuses each, and
 * tweetnacl - which okconnect.transitKey uses - computes 32 zero bytes for
 * each, and box.before then returns ONE value for all of them.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('../src/crypto/x25519guard');
const okconnect = require('../src/crypto/okconnect');
const nacl = require('../src/vendor/exports/tweetnacl.js');
const { x25519 } = require('../src/vendor/exports/@noble/curves/ed25519.js');

const P = (1n << 255n) - 19n;
/* noble 2.4.0's lowOrderU for 25519 (abstract/montgomery.js), written out. */
const NOBLE_LOW_ORDER = new Set([
  0n, 1n, P - 1n,
  325606250916557431795983626356110631294008115727848805560023387167927233504n,
  39382357235489614581723060781553021112529911719440698176882885853963445705823n,
]);

/* RFC 7748 section 5 decodeUCoordinate: little-endian, bit 255 masked, mod p. */
function decodeU(bytes) {
  const b = Uint8Array.from(bytes);
  b[31] &= 0x7f;
  let n = 0n;
  for (let i = 31; i >= 0; i--) n = (n << 8n) | BigInt(b[i]);
  return n % P;
}

const SK = Uint8Array.from({ length: 32 }, (_, i) => (i * 13 + 5) & 0xff);
const LOW = guard.LOW_ORDER_U;
const named = { code: 'LOW_ORDER_POINT' };

test('the seven encodings are exactly the low-order points, and noble and tweetnacl agree', () => {
  assert.equal(LOW.length, 7);
  assert.equal(new Set(LOW.map((u) => Buffer.from(u).toString('hex'))).size, 7);
  for (const u of LOW) {
    const hex = Buffer.from(u).toString('hex');
    assert.ok(NOBLE_LOW_ORDER.has(decodeU(u)), `${hex} is not in noble's lowOrderU`);
    assert.throws(() => x25519.getSharedSecret(SK, u), /invalid/, `noble accepted ${hex}`);
    assert.deepEqual(Array.from(nacl.scalarMult(SK, u)), new Array(32).fill(0),
      `tweetnacl did not produce the all-zero secret for ${hex} - the reason for the guard`);
    /* box.before hashes the zeros (HSalsa20), so the zeros never show - one
     * fixed "shared key" for every low-order point, whatever our secret. */
    assert.deepEqual(Array.from(nacl.box.before(u, SK)), Array.from(nacl.box.before(LOW[0], SK.map((b) => b ^ 0xff))));
  }
  /* And every value noble lists has a canonical encoding on the list. */
  const decoded = new Set(LOW.map(decodeU));
  for (const v of NOBLE_LOW_ORDER) assert.ok(decoded.has(v));
});

test('a low-order point is refused with bit 255 set too; a real key is not', () => {
  for (const u of LOW) {
    const high = Uint8Array.from(u);
    high[31] |= 0x80;
    assert.equal(guard.isLowOrderU(u), true);
    assert.equal(guard.isLowOrderU(high), true, 'the masked bit smuggled a listed point through');
    assert.throws(() => guard.assertPeerNotLowOrder(high), named);
  }
  const real = x25519.getPublicKey(SK);
  assert.equal(guard.isLowOrderU(real), false);
  guard.assertPeerNotLowOrder(real);
  assert.throws(() => guard.isLowOrderU(new Uint8Array(31)), /32 bytes/);
});

test('an all-zero secret is refused; any other is not', () => {
  assert.throws(() => guard.assertNonZeroSecret(new Uint8Array(32)), named);
  assert.throws(() => guard.assertNonZeroSecret(new Uint8Array(0)), named);
  const one = new Uint8Array(32);
  one[31] = 1;
  guard.assertNonZeroSecret(one);
});

test('okconnect.transitKey refuses a low-order device key instead of keying from a known value', () => {
  /*
   * tweetnacl's box.before is unchecked: before this, every entry gave
   * sha256(HSalsa20(0^32)) - one transit key, known to whoever sent the point.
   */
  for (const u of LOW) assert.throws(() => okconnect.transitKey(u, SK), named);
  const device = nacl.box.keyPair();
  assert.equal(okconnect.transitKey(device.publicKey, SK).length, 32);
});

test('a low-order peer key is refused before it is framed for the device', () => {
  const transitPublicKey = x25519.getPublicKey(SK);
  for (const keytype of [okconnect.KEYTYPE.CURVE25519, okconnect.KEYTYPE.NACL]) {
    for (const u of LOW) {
      assert.throws(() => okconnect.buildMessage({
        transitPublicKey, label: 'g12', publicKey: u, keytype,
      }), named);
    }
    okconnect.buildMessage({ transitPublicKey, label: 'g12', publicKey: transitPublicKey, keytype });
  }
});

test('an all-zero secret in a device reply is refused, whatever the key type', () => {
  const zeros = new Uint8Array(32);
  const p256 = Uint8Array.from({ length: 65 }, (_, i) => (i === 0 ? 4 : i));
  const c25519 = new Uint8Array(32).fill(9);
  assert.throws(() => okconnect.sharedSecretFrom(
    new Uint8Array([...p256, ...zeros]), okconnect.KEYTYPE.P256R1), named);
  assert.throws(() => okconnect.sharedSecretFrom(
    new Uint8Array([...c25519, ...zeros]), okconnect.KEYTYPE.CURVE25519), named);
  /* X-Wing, both shapes: the split pair's ss_X and the custody secret. */
  assert.throws(() => okconnect.sharedSecretFrom(
    new Uint8Array([...zeros, ...c25519]), okconnect.KEYTYPE.XWING, { xwingCustody: false }), named);
  assert.throws(() => okconnect.sharedSecretFrom(
    zeros, okconnect.KEYTYPE.XWING, { xwingCustody: true }), named);
});
