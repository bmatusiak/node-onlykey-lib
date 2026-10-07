'use strict';

/**
 * The hashing Edge needs: SHA-256 and HMAC-SHA256 through the crypto provider
 * (pure JS by default, OpenSSL on the phone - src/crypto/provider.js), ASCII tags
 * without TextEncoder, integers as
 * little-endian bytes. Nothing here touches a global, so it runs the same
 * under Hermes (no Buffer, no TextEncoder, no crypto.subtle) as under Node.
 */
const crypto = require('../crypto/provider');
const { concat, equalConstantTime } = require('../bytes');

/** ASCII only (the domain tags); anything else is a programming error. */
function ascii(text) {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c > 0x7e || c < 0x20) throw new TypeError(`edge: tag is not printable ASCII: ${JSON.stringify(text)}`);
    out[i] = c;
  }
  return out;
}

function u32le(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new RangeError(`edge: not a u32: ${n}`);
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}

function u8(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xff) throw new RangeError(`edge: not a byte: ${n}`);
  return new Uint8Array([n]);
}

/** SHA-256 over the parts in order (Uint8Array, or a string = an ASCII tag). */
function H(...parts) {
  return crypto.sha256(concat(parts.map((p) => (typeof p === 'string' ? ascii(p) : p))));
}

function hmacSha256(key, msg) {
  return crypto.hmacSha256(key, msg);
}

function bytes32(b, what) {
  if (!(b instanceof Uint8Array) || b.length !== 32) throw new TypeError(`edge: ${what} must be 32 bytes`);
  return b;
}

/* hashes and MACs from a mirror are attacker-supplied: compare in constant time */
const same = (a, b) => a instanceof Uint8Array && b instanceof Uint8Array && equalConstantTime(a, b);

module.exports = { H, hmacSha256, ascii, u32le, u8, bytes32, same };
