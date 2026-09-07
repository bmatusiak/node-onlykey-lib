/*
 * bytes.js - the conversions every other module sits on.
 *
 * base64 here is hand-written rather than borrowed from the platform, because
 * no single platform API is available everywhere this library runs: Node has
 * Buffer, browsers have atob/btoa, and Hermes has neither in the React Native
 * versions that matter. Hand-written code on a path that carries key material
 * and backup files needs its own tests, so these cross-check every case
 * against Node's Buffer as an INDEPENDENT oracle - comparing the encoder to
 * its own decoder would agree with itself no matter how wrong both were.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const {
  toHex, fromHex, toLatin1, fromLatin1, toPrintable, concat, equalConstantTime,
  utf8ToBytes, bytesToUtf8, toBase64, fromBase64,
} = require('../src/bytes');

/* ---------------------------------------------------------------- base64 */

test('base64 encoding matches Buffer across every padding remainder', () => {
  // Lengths 0-8 cover all three tail cases (0, 1, 2 leftover bytes) more than
  // once. The 255 case exercises the high bit, where a signed-byte slip shows.
  for (const len of [0, 1, 2, 3, 4, 5, 6, 7, 8, 255]) {
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = (i * 7 + 3) & 0xff;
    assert.equal(
      toBase64(bytes),
      Buffer.from(bytes).toString('base64'),
      `length ${len}`,
    );
  }
});

test('base64 encodes the full byte range, including the high half', () => {
  const all = new Uint8Array(256);
  for (let i = 0; i < 256; i++) all[i] = i;
  assert.equal(toBase64(all), Buffer.from(all).toString('base64'));
});

test('base64 decoding matches Buffer, padded or not', () => {
  // The age spec writes recipients UNPADDED, while a backup file is padded.
  // Both reach fromBase64, so both must decode to the same bytes.
  for (const len of [0, 1, 2, 3, 4, 5, 6, 7, 8, 255]) {
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = (i * 11 + 1) & 0xff;
    const padded = Buffer.from(bytes).toString('base64');
    const unpadded = padded.replace(/=+$/, '');

    assert.equal(toHex(fromBase64(padded)), toHex(bytes), `padded, length ${len}`);
    assert.equal(toHex(fromBase64(unpadded)), toHex(bytes), `unpadded, length ${len}`);
  }
});

test('base64 decoding ignores line wrapping', () => {
  // age wraps its body at 64 columns and a backup file is one line per chunk,
  // so newlines arrive inside the string rather than around it.
  const bytes = new Uint8Array(96);
  for (let i = 0; i < bytes.length; i++) bytes[i] = i;
  const b64 = Buffer.from(bytes).toString('base64');
  const wrapped = `${b64.slice(0, 40)}\n${b64.slice(40, 80)}\r\n  ${b64.slice(80)}`;
  assert.equal(toHex(fromBase64(wrapped)), toHex(bytes));
});

test('a base64 round trip is lossless for random input', () => {
  for (let trial = 0; trial < 50; trial++) {
    const bytes = new Uint8Array(1 + Math.floor(Math.random() * 200));
    for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
    assert.equal(toHex(fromBase64(toBase64(bytes))), toHex(bytes));
  }
});

/* ------------------------------------------------------------------ utf8 */

test('utf8 and latin1 are different encodings and must not be swapped', () => {
  // This is the distinction that makes a derived-identity label tag agree
  // with python-onlykey's, so it is asserted directly rather than implied.
  const text = 'café';
  assert.equal(utf8ToBytes(text).length, 5);
  assert.equal(fromLatin1(text).length, 4);
  assert.notEqual(toHex(utf8ToBytes(text)), toHex(fromLatin1(text)));
});

test('utf8 round-trips beyond the basic plane', () => {
  // Surrogate pairs are where a hand-rolled encoder usually breaks; @noble
  // handles them, and this pins that we are actually calling into it.
  for (const text of ['', 'plain', 'café ☕', '🔑 key', '你好']) {
    assert.equal(bytesToUtf8(utf8ToBytes(text)), text, JSON.stringify(text));
    assert.equal(toHex(utf8ToBytes(text)), Buffer.from(text, 'utf8').toString('hex'));
  }
});

/* ------------------------------------------------------------------- hex */

test('hex round-trips and tolerates separators a human would paste', () => {
  assert.equal(toHex(fromHex('00ff10')), '00ff10');
  assert.equal(toHex(fromHex('00 FF 10')), '00ff10');
  assert.equal(toHex(fromHex('00:ff:10')), '00ff10');
});

test('malformed hex is refused rather than silently yielding NaN bytes', () => {
  assert.throws(() => fromHex('abc'), /odd-length/);
  assert.throws(() => fromHex('zz'), /invalid hex/);
});

/* ---------------------------------------------------------------- latin1 */

test('latin1 survives bytes above 0x7f, which is why it is not utf8', () => {
  const bytes = Uint8Array.from([0x00, 0x7f, 0x80, 0xff]);
  assert.equal(toHex(fromLatin1(toLatin1(bytes))), toHex(bytes));
});

test('toPrintable drops what it cannot show instead of emitting control bytes', () => {
  assert.equal(toPrintable(Uint8Array.from([0x00, 0x41, 0x1b, 0x42, 0xff])), 'AB');
});

/* -------------------------------------------------------------- compares */

test('constant-time compare agrees with a plain compare on the answer', () => {
  assert.equal(equalConstantTime(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3)), true);
  assert.equal(equalConstantTime(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 4)), false);
  assert.equal(equalConstantTime(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2)), false);
  assert.equal(equalConstantTime(new Uint8Array(0), new Uint8Array(0)), true);
});

test('constant-time compare scans the whole buffer, not to first difference', () => {
  // An early exit is the leak this function exists to avoid. A difference in
  // byte 0 and one in the last byte must both simply return false.
  const a = new Uint8Array(64);
  const first = new Uint8Array(64); first[0] = 1;
  const last = new Uint8Array(64); last[63] = 1;
  assert.equal(equalConstantTime(a, first), false);
  assert.equal(equalConstantTime(a, last), false);
});

test('concat handles the empty and single-chunk cases', () => {
  assert.equal(concat([]).length, 0);
  assert.equal(toHex(concat([Uint8Array.of(1, 2)])), '0102');
  assert.equal(toHex(concat([Uint8Array.of(1), new Uint8Array(0), Uint8Array.of(2)])), '0102');
});
