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
 * WRITTEN OUT, not delegated. These used to come from @noble/ciphers/utils,
 * which uses TextEncoder and TextDecoder - and Hermes has NEITHER. It crashed
 * the first time CBOR decoded a text string on the phone:
 *
 *     ReferenceError: Property 'TextDecoder' doesn't exist
 *         at bytesToUtf8 ... at decodeAt ... at decode
 *
 * which is every authenticatorGetInfo, since its versions are text. The same
 * class of mistake as reaching for crypto.getRandomValues: a global that is
 * ordinary everywhere except the one platform this library was written for.
 */

/** @param {string} text */
function utf8ToBytes(text) {
  const str = String(text);
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i);

    // A surrogate pair is one code point in two units; combine before encoding
    // or every emoji becomes two replacement characters.
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
      const low = str.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
        i++;
      }
    }

    if (code < 0x80) {
      out.push(code);
    } else if (code < 0x800) {
      out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0x10000) {
      out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      out.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f),
      );
    }
  }
  return Uint8Array.from(out);
}

/** @param {Uint8Array} bytes */
function bytesToUtf8(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; ) {
    const b = bytes[i];
    let code;
    let size;

    if (b < 0x80) { code = b; size = 1; }
    else if ((b & 0xe0) === 0xc0) { code = b & 0x1f; size = 2; }
    else if ((b & 0xf0) === 0xe0) { code = b & 0x0f; size = 3; }
    else if ((b & 0xf8) === 0xf0) { code = b & 0x07; size = 4; }
    else { out += '�'; i += 1; continue; }

    if (i + size > bytes.length) { out += '�'; break; }

    for (let k = 1; k < size; k++) {
      const cont = bytes[i + k];
      if ((cont & 0xc0) !== 0x80) { code = -1; break; }
      code = (code << 6) | (cont & 0x3f);
    }
    i += size;

    if (code < 0) { out += '�'; continue; }

    if (code > 0xffff) {
      // Back to a surrogate pair, which is how JS holds anything above the BMP.
      code -= 0x10000;
      out += String.fromCharCode(0xd800 + (code >> 10), 0xdc00 + (code & 0x3ff));
    } else {
      out += String.fromCharCode(code);
    }
  }
  return out;
}

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

/**
 * base64url, unpadded - which is what a JWK `k` member is.
 *
 * This is not a formatting preference. The web app turns a derived secret into
 * a password by importing the raw bytes as an AES-GCM key and exporting the
 * JWK, then taking `k` (build_AESGCM, onlykey-3rd-party.js:95):
 *
 *     crypto.subtle.importKey('raw', secret, {name:'AES-GCM'}, true, ...)
 *     crypto.subtle.exportKey('jwk', key).then(({k}) => k)
 *
 * RFC 7517 says a JWK octet key is base64url with the padding removed, so `k`
 * is exactly this function's output over the same 32 bytes. Rendering the
 * secret as hex instead gives a different password for the same site, which is
 * a silent incompatibility rather than an error - the user simply cannot log
 * in with the one this app shows.
 *
 * It matters twice over: the vault feeds the UTF-8 of this string into HKDF as
 * its key material, so getting the encoding wrong changes the vault key too.
 */
function toBase64Url(bytes) {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** The inverse, tolerant of missing padding. */
function fromBase64Url(text) {
  return fromBase64(String(text).replace(/-/g, '+').replace(/_/g, '/'));
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
  toBase64Url,
  fromBase64Url,
  toHex,
  fromHex,
  formatHex,
  toLatin1,
  fromLatin1,
  toPrintable,
  concat,
  equalConstantTime,
};
