/*
 * encoders.js - slot field encodings.
 *
 * Two of these are corrected rather than ported. The originals are in
 * OnlyKeyWizard.js (base32tohex:1529, the Yubikey encoder:1038) and
 * OnlyKeyComm.js (a second, divergent Yubikey encoder:1687); each divergence
 * is noted where it matters.
 */
'use strict';

const { toHex, fromHex } = require('../bytes');

/* ------------------------------------------------------------- base32 / TOTP */

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Decode a base32 TOTP secret to bytes.
 *
 * Two defects fixed relative to OnlyKeyWizard.js:1529-1544.
 *
 * PADDING. The original does not strip '=', so indexOf returns -1, and
 * (-1).toString(2) is the string "-1", which its zero-pad turns into "000-1".
 * That corrupts the entire bit string from that point on - and '=' is present
 * on most real secrets, so this is not an edge case.
 *
 * TRUNCATION. The original emits hex nibbles and the caller does
 * .match(/.{2}/g), which silently drops a trailing odd nibble. A 26-character
 * secret is 130 bits, which is exactly where that bites.
 *
 * Whitespace is stripped because authenticator apps present secrets in groups
 * of four and people paste them that way.
 */
function base32ToBytes(secret) {
  const clean = String(secret).toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (!clean.length) return new Uint8Array(0);

  let bits = 0;
  let value = 0;
  const out = [];

  for (const ch of clean) {
    const index = BASE32_ALPHABET.indexOf(ch);
    if (index === -1) {
      throw new Error(`invalid base32 character "${ch}" in TOTP secret`);
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
    }
  }
  // Anything under 8 bits left is padding, not data - dropping it is correct.
  return Uint8Array.from(out);
}

/** The device wants the TOTP secret as bytes; this is the hex spelling of them. */
function base32ToHex(secret) {
  return toHex(base32ToBytes(secret));
}

/* ------------------------------------------------------------------- modhex */

const HEX_ALPHABET = '0123456789abcdef';
const MODHEX_ALPHABET = 'cbdefghijklnrtuv';

/**
 * modhex to hex.
 *
 * Yubico encodes its public id in modhex - an alphabet chosen so the string
 * survives any keyboard layout. The original helper is named hexToModhex but
 * both call sites pass reverse=true, which makes it convert the other way; the
 * name is simply wrong. Named for what it does here.
 */
function modhexToHex(modhex) {
  const clean = String(modhex).toLowerCase();
  let out = '';
  for (const ch of clean) {
    const index = MODHEX_ALPHABET.indexOf(ch);
    if (index === -1) {
      throw new Error(`invalid modhex character "${ch}"`);
    }
    out += HEX_ALPHABET[index];
  }
  return out;
}

function hexToModhex(hex) {
  const clean = String(hex).toLowerCase();
  let out = '';
  for (const ch of clean) {
    const index = HEX_ALPHABET.indexOf(ch);
    if (index === -1) throw new Error(`invalid hex character "${ch}"`);
    out += MODHEX_ALPHABET[index];
  }
  return out;
}

/* ------------------------------------------------------------------ Yubikey */

/**
 * Yubico OTP field limits, in hex characters.
 *
 * There are two encoders in OnlyKey-App and they disagree. This one follows
 * OnlyKeyWizard.js:1038-1067, which is spec-correct: Yubico defines the public
 * id as 1-16 bytes, the private id as exactly 6, and the AES key as exactly
 * 16.
 *
 * OnlyKeyComm.js:1687 uses maxPublicIdLength = 12, which silently truncates
 * any public id longer than 6 bytes - fine for the common Yubico-issued
 * prefix, wrong for anything else - and its "// 64 bytes" comment on the
 * secret is simply incorrect (32 hex chars is 16 bytes).
 *
 * One encoder, two entry points: writing a slot, and writing the device-global
 * validator identity.
 */
const YUBI = {
  PUBLIC_ID_HEX: 32,   // 16 bytes
  PRIVATE_ID_HEX: 12,  // 6 bytes
  SECRET_HEX: 32,      // 16 bytes
};

/**
 * Encode a Yubico OTP credential for the YUBIAUTH field.
 *
 * @param {object} spec
 * @param {string} spec.publicId   modhex, as Yubico presents it
 * @param {string} spec.privateId  hex, 6 bytes
 * @param {string} spec.secretKey  hex, 16 bytes
 * @returns {Uint8Array}
 */
function yubiCredential({ publicId, privateId, secretKey }) {
  const pub = modhexToHex(String(publicId).slice(0, YUBI.PUBLIC_ID_HEX));
  const priv = String(privateId).toLowerCase().slice(0, YUBI.PRIVATE_ID_HEX);
  const secret = String(secretKey).toLowerCase().slice(0, YUBI.SECRET_HEX);

  /*
   * Length is checked rather than assumed. The originals slice and move on, so
   * a short private id shifts the secret and produces a credential that is
   * accepted by the device and simply never authenticates - which is a very
   * expensive thing to debug from the far side.
   */
  if (priv.length !== YUBI.PRIVATE_ID_HEX) {
    throw new Error(`Yubikey private id must be ${YUBI.PRIVATE_ID_HEX} hex chars (6 bytes), got ${priv.length}`);
  }
  if (secret.length !== YUBI.SECRET_HEX) {
    throw new Error(`Yubikey secret must be ${YUBI.SECRET_HEX} hex chars (16 bytes), got ${secret.length}`);
  }
  if (!pub.length || pub.length % 2 !== 0) {
    throw new Error(`Yubikey public id must be a whole number of bytes, got ${pub.length} hex chars`);
  }

  return fromHex(pub + priv + secret);
}

/* ------------------------------------------------------------------- TFATYPE */

/**
 * The two-factor mode, sent as a LITERAL ASCII STRING.
 *
 * Not a numeric code. The device compares the text, and the values come
 * straight from the radio buttons in the original UI. Turning these into an
 * enum on the wire would be a silent protocol change.
 */
const TFA_TYPE = {
  GOOGLE_AUTH: 'googleAuthOtp',
  YUBIKEY: 'YubikeyOtp',
};

module.exports = {
  BASE32_ALPHABET,
  MODHEX_ALPHABET,
  YUBI,
  TFA_TYPE,
  base32ToBytes,
  base32ToHex,
  modhexToHex,
  hexToModhex,
  yubiCredential,
};
