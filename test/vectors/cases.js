/*
 * The inputs the cross-checks run - one list, shared by the tests and by
 * scripts/freeze-kit-vectors.js, so the recorded outputs and the checks that
 * read them cannot drift onto different inputs.
 *
 * The expected outputs are NOT here: they are in kit-reference.json, produced
 * by onlykey-testing's own implementations at a pinned commit. See that
 * script for why they are frozen rather than computed live.
 */
'use strict';

/** Values chosen to reach every branch of cbor's head() and decodeAt(). */
const CBOR_CASES = [
  ['null', null],
  ['true', true],
  ['false', false],
  ['zero', 0],
  ['a small int', 5],
  ['the 1-byte boundary', 23],
  ['the 2-byte boundary', 24],
  ['a byte-length int', 255],
  ['the 3-byte boundary', 256],
  ['a 16-bit int', 65535],
  ['the 5-byte boundary', 65536],
  ['a 32-bit int', 4294967295],
  ['a negative int', -1],
  ['a larger negative', -1000],
  ['an empty string', ''],
  ['a string', 'onlyagent.app'],
  ['a non-ASCII string', 'café'],
  ['empty bytes', new Uint8Array(0)],
  ['bytes', Uint8Array.from([0x00, 0xff, 0x10])],
  ['an empty array', []],
  ['an array', [1, 2, 3]],
  ['a nested array', [[1], ['two'], [Uint8Array.of(3)]]],
  ['an empty map', new Map()],
  ['an integer-keyed map', new Map([[1, 'a'], [2, Uint8Array.of(9)]])],
  ['a mixed-key map', new Map([[1, 'x'], ['long-key', 2], [10, 3]])],
];

/** CTAPHID framing: payload lengths around the 57/59-byte packet edges. */
const CTAPHID_LENGTHS = [0, 1, 57, 58, 116, 200, 1024];
function ctaphidPayload(len) {
  const payload = new Uint8Array(len);
  for (let i = 0; i < len; i++) payload[i] = (i * 7) & 0xff;
  return payload;
}

/** transit box(): a fixed key over many lengths. */
const BOX_KEY_BYTE = 0x5a;
const BOX_DATA_BYTE = 0xa5;
const BOX_LENGTHS = [0, 1, 15, 16, 17, 64, 228, 512, 3309];

/** transit connectPayload(): a fixed public key and clock. */
const CONNECT_PK_BYTE = 0x11;
const CONNECT_WHEN = 0x68bd1f40 * 1000;

module.exports = {
  CBOR_CASES, CTAPHID_LENGTHS, ctaphidPayload,
  BOX_KEY_BYTE, BOX_DATA_BYTE, BOX_LENGTHS, CONNECT_PK_BYTE, CONNECT_WHEN,
};
