/**
 * `TextEncoder` and `TextDecoder` for a runtime that has neither.
 *
 * Hermes has no TextDecoder. OpenPGP.js reaches for one the moment it reads
 * armour - `decodeUTF8` at openpgp.js's `read()` - so a key that GENERATES
 * perfectly still cannot be parsed back. This project has been bitten by the
 * same absence before: `src/crypto/vault.js` used `new TextDecoder().decode()`,
 * passed twenty-one Node tests, and threw on the phone.
 *
 * The codecs themselves are `utf8ToBytes`/`bytesToUtf8` from `../bytes`, which
 * are already used everywhere else here and are checked against Node's Buffer
 * for astral characters as well as ASCII. This file is only the class shape
 * that a caller written against the Web API expects.
 *
 * ## What is deliberately not implemented
 *
 * Encodings other than UTF-8. `new TextDecoder('shift-jis')` throws a
 * RangeError naming the encoding, which is what the Web API does for an
 * unsupported label and what a caller can act on. Silently decoding as UTF-8
 * would produce plausible mojibake instead.
 *
 * Streaming (`{stream: true}`) is accepted and ignored, because a decoder that
 * held state across calls would be a different and much larger thing. Nothing
 * in openpgp's armour path uses it; a caller that needs it should not be given
 * a shim that pretends.
 */
'use strict';

const { utf8ToBytes, bytesToUtf8 } = require('../bytes');

/** Labels the Web API treats as UTF-8. */
const UTF8_LABELS = new Set(['utf-8', 'utf8', 'unicode-1-1-utf-8']);

class ShimTextEncoder {
  get encoding() {
    return 'utf-8';
  }

  /** @param {string} [input] @returns {Uint8Array} */
  encode(input = '') {
    return utf8ToBytes(String(input));
  }

  /**
   * The Web API's encodeInto, which writes in place and reports how far it got.
   *
   * Implemented by encoding then copying rather than incrementally, so a
   * destination too small to hold the whole string truncates at a byte
   * boundary rather than splitting a character - which is what the spec
   * requires and what a naive byte-wise copy gets wrong.
   */
  encodeInto(source, destination) {
    const bytes = utf8ToBytes(String(source));
    const room = Math.min(bytes.length, destination.length);

    // Back off to a boundary: a continuation byte is 10xxxxxx.
    let written = room;
    while (written > 0 && written < bytes.length && (bytes[written] & 0xc0) === 0x80) {
      written--;
    }
    destination.set(bytes.subarray(0, written));

    // `read` counts UTF-16 code units consumed, not bytes written.
    const text = bytesToUtf8(bytes.subarray(0, written));
    return { read: text.length, written };
  }
}

class ShimTextDecoder {
  constructor(label = 'utf-8', options = {}) {
    const normalized = String(label).toLowerCase();
    if (!UTF8_LABELS.has(normalized)) {
      throw new RangeError(
        `TextDecoder: node-onlykey-lib's shim only implements utf-8, not "${label}"`,
      );
    }
    this._fatal = Boolean(options.fatal);
    this._ignoreBOM = Boolean(options.ignoreBOM);
  }

  get encoding() { return 'utf-8'; }
  get fatal() { return this._fatal; }
  get ignoreBOM() { return this._ignoreBOM; }

  /** @param {BufferSource} [input] @returns {string} */
  decode(input) {
    if (input === undefined) return '';
    let bytes;
    if (input instanceof Uint8Array) bytes = input;
    else if (ArrayBuffer.isView(input)) {
      bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
    } else if (input instanceof ArrayBuffer) bytes = new Uint8Array(input);
    else throw new TypeError('TextDecoder.decode expects a BufferSource');

    // A leading BOM is dropped unless the caller asked to keep it.
    if (!this._ignoreBOM && bytes.length >= 3
        && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
      bytes = bytes.subarray(3);
    }
    return bytesToUtf8(bytes);
  }
}

/**
 * Put both on the global, if they are not already there.
 *
 * Never replaces a platform implementation: a real one handles every encoding
 * and streams, and this one does neither.
 *
 * @returns {{installed: string[], reason: string}}
 */
function installTextCodecs() {
  const g = globalThis;
  const installed = [];

  if (typeof g.TextEncoder !== 'function') {
    g.TextEncoder = ShimTextEncoder;
    installed.push('TextEncoder');
  }
  if (typeof g.TextDecoder !== 'function') {
    g.TextDecoder = ShimTextDecoder;
    installed.push('TextDecoder');
  }

  return {
    installed,
    reason: installed.length ? 'the platform had none' : 'the platform already has them',
  };
}

module.exports = { installTextCodecs, ShimTextEncoder, ShimTextDecoder };
