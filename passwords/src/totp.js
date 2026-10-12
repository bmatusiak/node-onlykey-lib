'use strict';

/**
 * AUTHENTICATOR CODES (onlykey-edge features/PASSWORD-MANAGER-SPEC.md, the entry's `totp` field;
 * Brad, 2026-10-11: "we can do authenticator topt for github in passwords").
 *
 * HOTP (RFC 4226) and TOTP (RFC 6238) with HMAC-SHA1/256/512, and Steam Guard's 5-character
 * codes. The secret is the base32 setup key the site shows (or the `secret` of its otpauth://
 * link); it is kept inside the entry, so it is sealed with the rest of the store and never
 * stored in the clear. The codes are computed here, on the phone - the OnlyKey's own TOTP slots
 * are a different feature.
 */

const { hmac } = require('../../src/vendor/exports/@noble/hashes/hmac.js');
const { sha1 } = require('../../src/vendor/exports/@noble/hashes/legacy.js');
const { sha256, sha512 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { base32ToBytes } = require('../../src/device/encoders');

const ALGOS = { SHA1: sha1, SHA256: sha256, SHA512: sha512 };
/* Steam Guard's alphabet: 26 characters, no look-alikes */
const STEAM = '23456789BCDFGHJKMNPQRTVWXY';

/** The 8-byte big-endian counter HOTP signs. */
function counterBytes(counter) {
  if (!Number.isSafeInteger(counter) || counter < 0) throw new TypeError('passwords: the counter is a whole number from 0');
  const b = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i -= 1) {
    b[i] = c % 256;
    c = Math.floor(c / 256);
  }
  return b;
}

/** One HOTP code. key: the secret's bytes. */
function hotp(key, counter, { digits = 6, algo = 'SHA1', encoder = null } = {}) {
  const hash = ALGOS[algo];
  if (!hash) throw new TypeError(`passwords: algo is one of ${Object.keys(ALGOS).join(', ')}`);
  const mac = hmac(hash, key, counterBytes(counter));
  const o = mac[mac.length - 1] & 0x0f;
  const bin = (((mac[o] & 0x7f) << 24) | (mac[o + 1] << 16) | (mac[o + 2] << 8) | mac[o + 3]) >>> 0;
  if (encoder === 'steam') {
    let code = bin;
    let out = '';
    for (let i = 0; i < 5; i += 1) {
      out += STEAM[code % STEAM.length];
      code = Math.floor(code / STEAM.length);
    }
    return out;
  }
  return String(bin % 10 ** digits).padStart(digits, '0');
}

/** The code for an entry's totp field at `nowMs`. -> {code, remaining (s, TOTP only), counter} */
function codeOf(t, nowMs = Date.now()) {
  const s = shapeTotp(t);
  const key = base32ToBytes(s.secret);
  if (s.type === 'hotp') return { code: hotp(key, s.counter, s), remaining: null, counter: s.counter };
  const counter = Math.floor(nowMs / 1000 / s.period);
  const remaining = s.period - (Math.floor(nowMs / 1000) % s.period);
  return { code: hotp(key, counter, s), remaining, counter };
}

const num = (v, d) => (v === undefined || v === null || v === '' ? d : Number(v));

/** A totp field as stored, checked. Unknown fields are dropped. */
function shapeTotp(t) {
  if (!t || typeof t !== 'object') throw new TypeError('passwords: an authenticator is an object');
  const type = t.type === 'hotp' ? 'hotp' : 'totp';
  const secret = String(t.secret || '').toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (!secret) throw new TypeError('passwords: an authenticator needs its setup key');
  let key;
  try {
    key = base32ToBytes(secret);
  } catch (e) {
    throw new TypeError(`passwords: the setup key is not base32 (${e.message})`);
  }
  if (key.length < 10) throw new TypeError('passwords: the setup key is too short (under 80 bits)');
  const encoder = t.encoder === 'steam' ? 'steam' : null;
  const digits = encoder === 'steam' ? 5 : num(t.digits, 6);
  if (!encoder && ![6, 7, 8].includes(digits)) throw new TypeError('passwords: digits is 6, 7 or 8');
  const algo = encoder === 'steam' ? 'SHA1' : String(t.algo || 'SHA1').toUpperCase().replace('-', '');
  if (!ALGOS[algo]) throw new TypeError(`passwords: algo is one of ${Object.keys(ALGOS).join(', ')}`);
  const out = { type, secret, digits, algo };
  if (encoder) out.encoder = encoder;
  if (type === 'totp') {
    out.period = num(t.period, 30);
    if (!Number.isInteger(out.period) || out.period < 10 || out.period > 300) throw new TypeError('passwords: period is 10 to 300 seconds');
  } else {
    out.counter = num(t.counter, 0);
    if (!Number.isSafeInteger(out.counter) || out.counter < 0) throw new TypeError('passwords: the counter is a whole number from 0');
  }
  if (typeof t.issuer === 'string' && t.issuer.trim()) out.issuer = t.issuer.trim().slice(0, 128);
  return out;
}

/**
 * An otpauth:// link (the QR code's text), -> {totp, account, issuer}. Steam's links say
 * issuer=Steam (or encoder=steam); they get Steam's codes.
 */
function parseOtpauth(uri) {
  const m = /^otpauth:\/\/(totp|hotp)\/([^?]*)\??(.*)$/i.exec(String(uri).trim());
  if (!m) throw new TypeError('passwords: not an otpauth:// link');
  const params = {};
  for (const part of m[3].split('&')) {
    if (!part) continue;
    const [k, ...v] = part.split('=');
    params[decodeURIComponent(k).toLowerCase()] = decodeURIComponent(v.join('=').replace(/\+/g, ' '));
  }
  const label = decodeURIComponent(m[2]);
  const colon = label.indexOf(':');
  const labelIssuer = colon >= 0 ? label.slice(0, colon).trim() : '';
  const account = (colon >= 0 ? label.slice(colon + 1) : label).trim();
  const issuer = params.issuer || labelIssuer || '';
  const steam = /^steam$/i.test(issuer) || params.encoder === 'steam';
  const totp = shapeTotp({
    type: m[1].toLowerCase(),
    secret: params.secret,
    digits: params.digits,
    period: params.period,
    counter: params.counter,
    algo: params.algorithm,
    issuer,
    encoder: steam ? 'steam' : null,
  });
  return { totp, account, issuer };
}

module.exports = { ALGOS, hotp, codeOf, shapeTotp, parseOtpauth };
