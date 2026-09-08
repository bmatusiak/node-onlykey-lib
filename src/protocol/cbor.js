/*
 * cbor.js - just enough CBOR for CTAP2.
 *
 * Ported from onlykey-testing/lib/device/cbor.js, which is the implementation
 * proven against both a physical key and the emulator. The logic is unchanged;
 * what changed is that every Buffer became a Uint8Array, because Hermes has no
 * Buffer. test/cbor.test.js cross-checks this against the original byte for
 * byte and skips when that checkout is absent.
 *
 * CTAP2 does not use CBOR, it uses a strict subset (the "CTAP2 canonical CBOR
 * encoding form"): definite lengths only, no tags, no indefinite streams, and
 * map keys sorted canonically. That subset is small enough to read in one
 * sitting, which is the argument for having it here rather than taking a
 * dependency on a general CBOR library that would also need porting.
 *
 * Canonical ordering matters and is not cosmetic. The authenticator hashes some
 * of what it receives, so two encodings of the same map are not
 * interchangeable - a signature verifies against the bytes, not the meaning.
 * Keys sort by encoded length first, then bytewise.
 */
'use strict';

const { concat, utf8ToBytes, bytesToUtf8 } = require('../bytes');

/* Major types, in the high three bits of the initial byte. */
const UINT = 0;
const NEGINT = 1;
const BYTES = 2;
const TEXT = 3;
const ARRAY = 4;
const MAP = 5;
const SIMPLE = 7;

/**
 * A DataView over a Uint8Array, honouring its offset.
 *
 * `subarray()` shares the underlying buffer, so a view built from `.buffer`
 * alone would read from the start of the ORIGINAL allocation rather than the
 * slice - silently returning bytes from somewhere else in the message.
 */
function view(bytes) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

/* ---- encoding ------------------------------------------------------------ */

function head(major, value) {
  if (value < 24) return Uint8Array.of((major << 5) | value);
  if (value < 0x100) return Uint8Array.of((major << 5) | 24, value);

  if (value < 0x10000) {
    const b = new Uint8Array(3);
    b[0] = (major << 5) | 25;
    view(b).setUint16(1, value, false);
    return b;
  }
  if (value < 0x100000000) {
    const b = new Uint8Array(5);
    b[0] = (major << 5) | 26;
    view(b).setUint32(1, value, false);
    return b;
  }
  const b = new Uint8Array(9);
  b[0] = (major << 5) | 27;
  view(b).setBigUint64(1, BigInt(value), false);
  return b;
}

/** Bytewise compare, for canonical map ordering. */
function compareBytes(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return a.length - b.length;
}

/**
 * @param {*} value  number | string | Uint8Array | Array | Map | object | boolean | null
 * @returns {Uint8Array}
 */
function encode(value) {
  if (value === null) return Uint8Array.of((SIMPLE << 5) | 22);
  if (value === true) return Uint8Array.of((SIMPLE << 5) | 21);
  if (value === false) return Uint8Array.of((SIMPLE << 5) | 20);

  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new TypeError('CTAP2 CBOR: no floats here');
    return value >= 0 ? head(UINT, value) : head(NEGINT, -value - 1);
  }

  if (typeof value === 'string') {
    const body = utf8ToBytes(value);
    return concat([head(TEXT, body.length), body]);
  }

  if (value instanceof Uint8Array) {
    return concat([head(BYTES, value.length), value]);
  }

  if (Array.isArray(value)) {
    return concat([head(ARRAY, value.length), ...value.map(encode)]);
  }

  /*
   * A Map preserves the caller's key types; a plain object cannot hold the
   * integer keys CTAP2 requests are built from, so both are accepted.
   */
  const entries = value instanceof Map ? [...value.entries()] : Object.entries(value);

  const encoded = entries.map(([k, v]) => [encode(k), encode(v)]);
  encoded.sort((a, b) => (a[0].length - b[0].length) || compareBytes(a[0], b[0]));

  return concat([head(MAP, encoded.length), ...encoded.flat()]);
}

/* ---- decoding ------------------------------------------------------------ */

function readHead(buf, pos) {
  const initial = buf[pos];
  const major = initial >> 5;
  const minor = initial & 0x1f;
  const dv = view(buf);

  if (minor < 24) return { major, value: minor, next: pos + 1 };
  if (minor === 24) return { major, value: buf[pos + 1], next: pos + 2 };
  if (minor === 25) return { major, value: dv.getUint16(pos + 1, false), next: pos + 3 };
  if (minor === 26) return { major, value: dv.getUint32(pos + 1, false), next: pos + 5 };
  if (minor === 27) {
    return { major, value: Number(dv.getBigUint64(pos + 1, false)), next: pos + 9 };
  }
  throw new Error(`CBOR: unsupported length encoding ${minor} at ${pos}`);
}

function decodeAt(buf, pos) {
  const { major, value, next } = readHead(buf, pos);

  switch (major) {
    case UINT:
      return { value, next };
    case NEGINT:
      return { value: -value - 1, next };

    case BYTES:
      return { value: buf.subarray(next, next + value), next: next + value };
    case TEXT:
      return {
        value: bytesToUtf8(buf.subarray(next, next + value)),
        next: next + value,
      };

    case ARRAY: {
      const out = [];
      let at = next;
      for (let i = 0; i < value; i++) {
        const item = decodeAt(buf, at);
        out.push(item.value);
        at = item.next;
      }
      return { value: out, next: at };
    }

    case MAP: {
      /*
       * A Map, not an object: CTAP2 responses are keyed by integer, and an
       * object would stringify those keys and quietly lose the distinction
       * between 1 and "1".
       */
      const out = new Map();
      let at = next;
      for (let i = 0; i < value; i++) {
        const k = decodeAt(buf, at);
        const v = decodeAt(buf, k.next);
        out.set(k.value, v.value);
        at = v.next;
      }
      return { value: out, next: at };
    }

    case SIMPLE: {
      const minor = buf[pos] & 0x1f;
      const dv = view(buf);
      if (minor === 20) return { value: false, next };
      if (minor === 21) return { value: true, next };
      if (minor === 22) return { value: null, next };
      if (minor === 23) return { value: undefined, next };
      if (minor === 26) return { value: dv.getFloat32(pos + 1, false), next: pos + 5 };
      if (minor === 27) return { value: dv.getFloat64(pos + 1, false), next: pos + 9 };
      throw new Error(`CBOR: unsupported simple value ${minor} at ${pos}`);
    }

    default:
      throw new Error(`CBOR: unsupported major type ${major} at ${pos}`);
  }
}

/**
 * @param {Uint8Array} buf
 * @returns {*} Maps stay Maps, byte strings stay Uint8Arrays
 */
function decode(buf) {
  if (!buf || !buf.length) return undefined;
  const bytes = buf instanceof Uint8Array ? buf : Uint8Array.from(buf);
  const { value, next } = decodeAt(bytes, 0);
  if (next !== bytes.length) {
    throw new Error(`CBOR: ${bytes.length - next} trailing bytes after the top-level item`);
  }
  return value;
}

/**
 * Decode ONE item and say where it ended.
 *
 * decode() insists the buffer holds exactly one item, which is the right
 * default - a trailing byte usually means the wrong slice was passed. But CTAP2
 * puts two CBOR items back to back with no length between them and expects the
 * reader to know: authData's attested-credential-data ends with a COSE key, and
 * an extension map may follow it immediately. The only way past the key is to
 * decode it and be told the offset.
 *
 * @param {Uint8Array} buf
 * @param {number} [pos]
 * @returns {{value: *, next: number}} next is the offset just past the item
 */
function decodeFirst(buf, pos = 0) {
  if (!buf || pos >= buf.length) return { value: undefined, next: pos };
  const bytes = buf instanceof Uint8Array ? buf : Uint8Array.from(buf);
  return decodeAt(bytes, pos);
}

/** Maps to plain objects, for readable assertion messages. Lossy on purpose. */
function plain(value) {
  if (value instanceof Map) {
    const out = {};
    for (const [k, v] of value) out[String(k)] = plain(v);
    return out;
  }
  if (Array.isArray(value)) return value.map(plain);
  if (value instanceof Uint8Array) return `<${value.length} bytes>`;
  return value;
}

module.exports = { encode, decode, decodeFirst, plain };
