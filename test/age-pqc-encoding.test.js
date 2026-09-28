/*
 * The age / X-Wing string encoding, through the PUBLIC surface
 * (node-onlykey-lib/crypto's pqc).
 *
 * bech32Encode, bech32Decode and the prefixes were internal until
 * onlykey-testing moved onto this library: its age-pqc.js carried its own
 * copies, and its tests build and read recipient / identity strings by hand.
 * The expected string below is the KIT'S output for the same input, recorded
 * when it switched (onlykey-testing lib/age-pqc.js, 2026-09-28) - the library's
 * encoder must keep producing it.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { pqc } = require('../src/crypto');

const DATA = new Uint8Array(40).map((_, i) => (i * 29 + 3) & 255);
const KIT_ENCODED =
  'age1onlykey1qvsr6knhjjcua6cgy4p97lyekmflqrf2gajgr84mmr63yt6vdxr28sxalgtng5tw9uwped';

test('bech32 and the prefixes are exported', () => {
  assert.equal(typeof pqc.bech32Encode, 'function');
  assert.equal(typeof pqc.bech32Decode, 'function');
  assert.equal(pqc.RECIPIENT_HRP, 'age1onlykey');
  assert.equal(pqc.IDENTITY_HRP, 'age-plugin-onlykey-');
  assert.equal(pqc.DERIVED_MARKER, 0xff);
});

test('bech32Encode matches what onlykey-testing produced (frozen)', () => {
  assert.equal(pqc.bech32Encode(pqc.RECIPIENT_HRP, DATA), KIT_ENCODED);
});

test('bech32 round-trips, including a whole 1216-byte recipient', () => {
  for (const len of [0, 1, 32, 1216]) {
    const data = new Uint8Array(len).map((_, i) => (i * 7 + 1) & 255);
    const decoded = pqc.bech32Decode(pqc.bech32Encode(pqc.RECIPIENT_HRP, data));
    assert.equal(decoded.hrp, pqc.RECIPIENT_HRP, `hrp at ${len} bytes`);
    assert.deepEqual(Array.from(decoded.data), Array.from(data), `data at ${len} bytes`);
  }
});

test('a recipient string is the bech32 of its key under RECIPIENT_HRP', () => {
  const pk = new Uint8Array(pqc.XWING_PK).map((_, i) => (i * 13) & 255);
  assert.equal(pqc.encodeRecipient(pk), pqc.bech32Encode(pqc.RECIPIENT_HRP, pk));
});
