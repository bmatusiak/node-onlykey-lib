/*
 * The button challenge.
 *
 * Three digits the device never sends, computed from the request. There is no
 * feedback if they are wrong - the window simply closes with "Error incorrect
 * challenge was entered" - so these are checked against an INDEPENDENT sha256
 * (node's own) rather than against a stored vector produced by the same code.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

const { challengeDigits, BUTTONS, DUO_BUTTONS } = require('../src/protocol/challenge');

/** The rule, spelled out again with a different hash implementation. */
function reference(packet, modulus = 6) {
  const h = crypto.createHash('sha256').update(Buffer.from(packet)).digest();
  return [h[0] % modulus + 1, h[15] % modulus + 1, h[31] % modulus + 1];
}

test('the digits match an independent sha256 over the same bytes', () => {
  for (let n = 0; n < 64; n++) {
    const packet = new Uint8Array(n).map((_, i) => (i * 31 + n) & 0xff);
    assert.deepEqual(challengeDigits(packet), reference(packet), `packet of ${n} bytes`);
  }
});

test('keygen primes over the key type and the generate trigger', () => {
  /*
   * ecc_priv_flash() builds its own nine-byte packet: the key type, then the
   * eight 0xFF bytes that mean "generate" rather than "store" (the
   * gen_key == 2040 trigger). Pinned because it is the one packet a caller does
   * NOT assemble itself - hashing the request it sent instead would be wrong
   * here and right everywhere else.
   *
   * Matches onlykey-testing/lib/pqc.js:75-80.
   */
  const KEYTYPE_NACL = 1;
  const packet = new Uint8Array([KEYTYPE_NACL, ...new Array(8).fill(0xff)]);
  assert.deepEqual(challengeDigits(packet), reference(packet));
});

test('every digit is a button that exists', () => {
  for (let n = 1; n < 200; n++) {
    const packet = new Uint8Array([n, n ^ 0x5a, (n * 7) & 0xff]);
    for (const d of challengeDigits(packet)) {
      assert.ok(d >= 1 && d <= BUTTONS, `${d} is not a button`);
    }
  }
});

test('a DUO takes mod 3, because it has three buttons', () => {
  /*
   * Not a detail. Ask for mod 6 digits on a DUO and two thirds of them name
   * buttons the hardware does not have, so the challenge cannot be answered at
   * all - and it presents as the device ignoring presses.
   */
  const packet = new Uint8Array([9, 8, 7, 6]);
  assert.deepEqual(challengeDigits(packet, { duo: true }), reference(packet, DUO_BUTTONS));
  for (const d of challengeDigits(packet, { duo: true })) {
    assert.ok(d >= 1 && d <= DUO_BUTTONS, `${d} is not a DUO button`);
  }
});

test('a different request asks for different buttons', () => {
  // The binding is the point: the press approves THIS request, not the fact
  // that somebody was standing there.
  const a = challengeDigits(new Uint8Array([1, 2, 3]));
  const b = challengeDigits(new Uint8Array([1, 2, 4]));
  assert.notDeepEqual(a, b);
});

test('an empty packet still yields three buttons', () => {
  // sha256 of nothing is a real hash; the firmware would do the same.
  assert.deepEqual(challengeDigits(new Uint8Array(0)), reference(new Uint8Array(0)));
});

test('the packet must be bytes, not a string or a Buffer-alike', () => {
  /*
   * Asked for explicitly because the failure is silent otherwise: hashing the
   * UTF-8 of a hex string produces three perfectly plausible digits that are
   * simply not the ones the device wants.
   */
  assert.throws(() => challengeDigits('0102'), /Uint8Array/);
  assert.throws(() => challengeDigits([1, 2, 3]), /Uint8Array/);
});

test('a Buffer is accepted, since it IS a Uint8Array', () => {
  // Node callers will pass one, and rejecting it would be pedantry.
  const buf = Buffer.from([1, 2, 3]);
  assert.deepEqual(challengeDigits(buf), reference(buf));
});

test('it is exported from the protocol barrel', () => {
  const protocol = require('../src/protocol');
  assert.equal(typeof protocol.challenge.challengeDigits, 'function');
});
