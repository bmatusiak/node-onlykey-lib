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

module.exports = {
  toHex,
  fromHex,
  formatHex,
  toLatin1,
  fromLatin1,
  toPrintable,
  concat,
  equalConstantTime,
};
