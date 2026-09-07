/*
 * bytes.js - byte handling that works in every runtime this library targets.
 *
 * Uint8Array, never Buffer. React Native's Hermes engine has no Buffer, and
 * neither does a browser; adding a polyfill would put a 30 kB shim under a
 * library whose whole job is moving 64-byte reports around. Every reference
 * implementation this is ported from is Buffer-based, so the conversions here
 * are the seam where that changes.
 *
 * Nothing in this file allocates more than it needs to: these run once per HID
 * report, and on a busy vendor interface that is hundreds of times a second.
 */
'use strict';

const HEX = '0123456789abcdef';

/** @param {Uint8Array|number[]} bytes */
function toHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const v = bytes[i] & 0xff;
    out += HEX[v >>> 4] + HEX[v & 0x0f];
  }
  return out;
}

/**
 * Accepts separators, because hex that a human typed or a log printed is worth
 * being able to paste straight back in.
 * @param {string} hex
 */
function fromHex(hex) {
  const clean = String(hex).replace(/[\s:_-]/g, '');
  if (clean.length % 2 !== 0) {
    throw new Error(`fromHex: odd-length hex string (${clean.length} chars)`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = digit(clean.charCodeAt(i * 2));
    const lo = digit(clean.charCodeAt(i * 2 + 1));
    if (hi < 0 || lo < 0) {
      throw new Error(`fromHex: invalid hex at offset ${i * 2}`);
    }
    out[i] = (hi << 4) | lo;
  }
  return out;
}

function digit(code) {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;        // 0-9
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;   // a-f
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10;   // A-F
  return -1;
}

/** `01 ff 00 aa` - for logs and assertion messages. */
function formatHex(bytes) {
  const hex = typeof bytes === 'string' ? bytes : toHex(bytes);
  return (hex.match(/.{1,2}/g) || []).join(' ');
}

/**
 * latin1, not UTF-8.
 *
 * The firmware's strings are single bytes and its binary payloads must survive
 * a round trip unchanged; UTF-8 would mangle anything above 0x7f. This matches
 * okmsg.text()'s `toString('latin1')` upstream.
 * @param {Uint8Array} bytes
 */
function toLatin1(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i] & 0xff);
  return out;
}

/** @param {string} text */
function fromLatin1(text) {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

/**
 * Printable ASCII only, for showing a report that may be text or may be
 * binary. Unlike toLatin1 this drops what it cannot show rather than emitting
 * control characters into a log.
 * @param {Uint8Array} bytes
 */
function toPrintable(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b >= 0x20 && b <= 0x7e) out += String.fromCharCode(b);
  }
  return out;
}

/** @param {Array<Uint8Array>} chunks */
function concat(chunks) {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

/**
 * Constant-time comparison.
 *
 * Present because this library compares MACs and derived keys, and the
 * obvious `===` on a hex string leaks through early exit. Length is not
 * secret, so returning early on it is fine.
 */
function equalConstantTime(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/*
 * UTF-8, distinct from latin1 above and not interchangeable with it.
 *
 * The device's own strings are latin1 - single bytes, and binary payloads that
 * must survive a round trip. But a derived-identity LABEL is UTF-8, and that
 * choice is load-bearing: the label tag is SHA-256 over these bytes, and
 * python-onlykey derives the same tag from the same label. Encoding a
 * non-ASCII label as latin1 would produce a different tag, a different
 * recipient, and a decryption that fails much later with "no identity
 * matched" rather than anything about encodings.
 *
 * Delegated to @noble, which is already a dependency and handles surrogate
 * pairs correctly.
 */
const { utf8ToBytes, bytesToUtf8 } = require('@noble/ciphers/utils.js');

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * base64, implemented rather than taken from the platform.
 *
 * Node has Buffer, browsers have btoa, and React Native has neither reliably -
 * atob/btoa only landed in recent versions and Hermes has no Buffer at all.
 * Twenty lines is cheaper than a polyfill dependency or a runtime branch.
 */
function toBase64(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += B64[a >> 2];
    out += B64[((a & 3) << 4) | (b >> 4)];
    out += i + 1 < bytes.length ? B64[((b & 15) << 2) | (c >> 6)] : '=';
    out += i + 2 < bytes.length ? B64[c & 63] : '=';
  }
  return out;
}

function fromBase64(text) {
  const clean = String(text).replace(/[^A-Za-z0-9+/]/g, '');
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let at = 0;
  let acc = 0;
  let bits = 0;
  for (const ch of clean) {
    const v = B64.indexOf(ch);
    if (v === -1) throw new Error(`invalid base64 character "${ch}"`);
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[at++] = (acc >> bits) & 0xff;
    }
  }
  return out.subarray(0, at);
}

module.exports = {
  utf8ToBytes,
  bytesToUtf8,
  toBase64,
  fromBase64,
  toHex,
  fromHex,
  formatHex,
  toLatin1,
  fromLatin1,
  toPrintable,
  concat,
  equalConstantTime,
};
