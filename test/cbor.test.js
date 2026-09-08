/*
 * CBOR, cross-checked against the implementation it was ported from.
 *
 * The port is mechanical - Buffer became Uint8Array - so the strongest test
 * available is not a hand-written vector but the original itself, which has run
 * against a physical key. Every case below encodes through both and compares
 * bytes; when onlykey-testing is absent the cross-checks skip and the pinned
 * vectors still run.
 *
 * Canonical ordering is the part worth being careful about: the authenticator
 * hashes some of what it receives, so two encodings of the same map are not
 * interchangeable. A signature verifies against bytes, not meaning.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const cbor = require('../src/protocol/cbor');
const { toHex, fromHex, utf8ToBytes } = require('../src/bytes');

let reference = null;
try {
  reference = require(
    path.resolve(__dirname, '..', '..', 'onlykey-testing', 'lib', 'device', 'cbor.js'),
  );
} catch { /* cross-checks skip themselves */ }

/** Values chosen to reach every branch of head() and decodeAt(). */
const CASES = [
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

for (const [what, value] of CASES) {
  test(`${what} round-trips`, () => {
    const encoded = cbor.encode(value);
    const decoded = cbor.decode(encoded);

    if (value instanceof Uint8Array) {
      assert.equal(toHex(decoded), toHex(value));
    } else if (value instanceof Map) {
      assert.equal(decoded instanceof Map, true, 'a map must not decode to an object');
      assert.equal(decoded.size, value.size);
    } else if (Array.isArray(value)) {
      assert.equal(decoded.length, value.length);
    } else {
      assert.deepEqual(decoded, value);
    }
  });

  test(`${what} encodes identically to onlykey-testing`, { skip: !reference }, () => {
    const mine = cbor.encode(value);
    const theirs = reference.encode(
      value instanceof Uint8Array ? Buffer.from(value) : value,
    );
    assert.equal(toHex(mine), theirs.toString('hex'), `${what} diverged`);
  });
}

/* ------------------------------------------------------------- canonical */

test('map keys sort by encoded LENGTH first, then bytewise', () => {
  /*
   * The rule that is easy to get wrong: a plain bytewise sort would put
   * "b" (2 bytes encoded) before 10 (2 bytes) purely on the first byte, and
   * both before 1 (1 byte). Length wins first.
   */
  const encoded = cbor.encode(new Map([['b', 1], [10, 2], [1, 3]]));
  const decoded = [...cbor.decode(encoded).keys()];
  assert.deepEqual(decoded, [1, 10, 'b']);
});

test('the same map encodes identically whatever order it was built in', () => {
  // Not cosmetic: the authenticator hashes some of what it receives, so a
  // different encoding of the same map is a different message.
  const a = cbor.encode(new Map([[1, 'x'], [2, 'y'], [3, 'z']]));
  const b = cbor.encode(new Map([[3, 'z'], [1, 'x'], [2, 'y']]));
  assert.equal(toHex(a), toHex(b));
});

/* ------------------------------------------------------------- structure */

test('an integer-keyed map does NOT decode to an object', () => {
  // An object would stringify the keys and lose the difference between 1
  // and "1", which is exactly the distinction CTAP2 responses rely on.
  const decoded = cbor.decode(cbor.encode(new Map([[1, 'a']])));
  assert.equal(decoded instanceof Map, true);
  assert.equal(decoded.get(1), 'a');
  assert.equal(decoded.get('1'), undefined);
});

test('byte strings decode as Uint8Array, not as text', () => {
  const decoded = cbor.decode(cbor.encode(Uint8Array.from([1, 2, 3])));
  assert.equal(decoded instanceof Uint8Array, true);
  assert.equal(toHex(decoded), '010203');
});

test('a subarray is decoded from its own offset, not the buffer start', () => {
  /*
   * The one real hazard in the Buffer->Uint8Array port. subarray() shares the
   * underlying allocation, so a DataView built from `.buffer` without the
   * byteOffset reads from the START of the original - silently returning bytes
   * from elsewhere in the message. Multi-byte lengths are where it shows.
   */
  const inner = cbor.encode(65535);
  const padded = new Uint8Array(16);
  padded.set(inner, 7);

  assert.equal(cbor.decode(padded.subarray(7, 7 + inner.length)), 65535);
});

/* -------------------------------------------------------------- decoding */

test('trailing bytes are refused, because they usually mean a wrong slice', () => {
  const encoded = cbor.encode(1);
  const extra = new Uint8Array(encoded.length + 2);
  extra.set(encoded, 0);
  assert.throws(() => cbor.decode(extra), /trailing bytes/);
});

test('decodeFirst reads one item and says where it ended', () => {
  /*
   * CTAP2 puts two CBOR items back to back with no length between them:
   * authData's attested-credential-data ends with a COSE key and an extension
   * map may follow immediately. Decoding is the only way past the key.
   */
  const first = cbor.encode(new Map([[1, 2]]));
  const second = cbor.encode('after');
  const joined = new Uint8Array(first.length + second.length);
  joined.set(first, 0);
  joined.set(second, first.length);

  const one = cbor.decodeFirst(joined);
  assert.equal(one.next, first.length);
  const two = cbor.decodeFirst(joined, one.next);
  assert.equal(two.value, 'after');
});

test('an empty input decodes to undefined rather than throwing', () => {
  assert.equal(cbor.decode(new Uint8Array(0)), undefined);
  assert.equal(cbor.decode(null), undefined);
});

test('a float is refused on encode - CTAP2 has no use for one', () => {
  assert.throws(() => cbor.encode(1.5), /no floats/);
});

/* ------------------------------------------------------------- CTAP2 use */

test('a getAssertion request encodes to the canonical form', () => {
  /*
   * The actual shape this exists for: rpId, clientDataHash and an allowList
   * carrying the OnlyKey keyhandle as a credential id.
   */
  const request = new Map([
    [1, 'onlyagent.app'],
    [2, new Uint8Array(32).fill(0xab)],
    [3, [new Map([['type', 'public-key'], ['id', Uint8Array.from([1, 2, 3, 4])]])]],
  ]);

  const encoded = cbor.encode(request);
  const decoded = cbor.decode(encoded);

  assert.equal(decoded.get(1), 'onlyagent.app');
  assert.equal(decoded.get(2).length, 32);
  assert.equal(toHex(decoded.get(3)[0].get('id')), '01020304');
  // Keys 1,2,3 are one byte each, so they keep their numeric order.
  assert.deepEqual([...decoded.keys()], [1, 2, 3]);
});

test('plain() renders a decoded map readably without lying about bytes', () => {
  const out = cbor.plain(cbor.decode(cbor.encode(new Map([[1, Uint8Array.of(1, 2)]]))));
  assert.deepEqual(out, { 1: '<2 bytes>' });
});

test('a known vector decodes to the expected value', () => {
  // a1 01 63 61 62 63 = {1: "abc"}
  const decoded = cbor.decode(fromHex('a10163616263'));
  assert.equal(decoded.get(1), 'abc');
  assert.equal(toHex(cbor.encode(new Map([[1, 'abc']]))), 'a10163616263');
  assert.equal(toHex(cbor.encode(utf8ToBytes('abc'))), '43616263');
});
