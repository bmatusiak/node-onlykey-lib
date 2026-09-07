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
 * OnlyKey-App has two Yubikey encoders with different constants, and the
 * obvious reading - that one is a stale copy of the other - is wrong. They are
 * two different device features, and libraries/onlykey/okcore.cpp:5772-5825
 * settles it:
 *
 *   SLOT 0, the deprecated EEPROM path behind setYubiAuth():
 *     memcpy(pubID, temp, 6);   // "Old Yubikey method only supports default
 *                               //  6 len pubkey"
 *   exactly 6 bytes, no more and no less.
 *
 *   SLOTS 1-24, the per-slot flash path the wizard writes:
 *     uint8_t publen = 16;                       // Max public size
 *     for (int i = 37; i > 1; i--) { ... }       // Public ID 2-16 bytes
 *   variable, 2 to 16 bytes, recovered by trimming trailing zeros.
 *
 * So collapsing them into one encoder breaks whichever path loses. They also
 * differ in what they take: the per-slot form is given MODHEX, as Yubico
 * prints it, and converts; the slot-0 form is given hex and concatenates it
 * unchanged. Two entry points over one assembler.
 *
 * Neither bound is discoverable from any client - both hardcode a single
 * number and neither matches both paths - so this is written up in
 * FINDING-yubikey-public-id-bounds.md.
 */
const YUBI = {
  /** Per-slot public id: 2-16 bytes. */
  PUBLIC_ID_MIN_HEX: 4,
  PUBLIC_ID_MAX_HEX: 32,
  /** Slot 0 public id: exactly 6 bytes. */
  PUBLIC_ID_GLOBAL_HEX: 12,
  PRIVATE_ID_HEX: 12,  // 6 bytes
  SECRET_HEX: 32,      // 16 bytes
};

/**
 * The common tail: private id and secret, which are the same on both paths.
 *
 * Lengths are checked rather than sliced. The originals slice and move on, so
 * a short private id shifts the secret and produces a credential the device
 * accepts and which then never authenticates - a very expensive thing to
 * diagnose from the far side of a one-way OTP.
 */
function yubiTail(privateId, secretKey) {
  const priv = String(privateId).trim().toLowerCase();
  const secret = String(secretKey).trim().toLowerCase();

  if (priv.length !== YUBI.PRIVATE_ID_HEX) {
    throw new Error(
      `Yubikey private id must be ${YUBI.PRIVATE_ID_HEX} hex chars (6 bytes), got ${priv.length}`,
    );
  }
  if (secret.length !== YUBI.SECRET_HEX) {
    throw new Error(
      `Yubikey secret must be ${YUBI.SECRET_HEX} hex chars (16 bytes), got ${secret.length}`,
    );
  }
  return priv + secret;
}

/**
 * Encode a Yubico OTP credential for a SLOT (1-24).
 *
 * The public id arrives as modhex, the way a Yubikey prints it, and is
 * converted here. Length is variable: the firmware recovers it by trimming
 * trailing zeros, so anything from 2 to 16 bytes round-trips.
 *
 * @param {object} spec
 * @param {string} spec.publicId   modhex, 2-16 bytes
 * @param {string} spec.privateId  hex, 6 bytes
 * @param {string} spec.secretKey  hex, 16 bytes
 * @returns {Uint8Array}
 */
function yubiCredential({ publicId, privateId, secretKey }) {
  const pub = modhexToHex(String(publicId).trim());

  if (pub.length % 2 !== 0) {
    throw new Error(`Yubikey public id must be a whole number of bytes, got ${pub.length} hex chars`);
  }
  /*
   * Refused rather than truncated. The original slices to its limit, so an
   * over-long public id is silently shortened and the credential authenticates
   * against nothing.
   */
  if (pub.length < YUBI.PUBLIC_ID_MIN_HEX || pub.length > YUBI.PUBLIC_ID_MAX_HEX) {
    throw new Error(
      `Yubikey public id must be ${YUBI.PUBLIC_ID_MIN_HEX}-${YUBI.PUBLIC_ID_MAX_HEX} ` +
      `hex chars (2-16 bytes), got ${pub.length}`,
    );
  }

  return fromHex(pub + yubiTail(privateId, secretKey));
}

/**
 * Encode the device-global Yubico credential, for slot 0.
 *
 * Different in three ways from the per-slot form, none of them cosmetic: the
 * public id must be EXACTLY 6 bytes because the firmware memcpys that many, it
 * is supplied as hex rather than modhex because setYubiAuth concatenates it
 * unchanged, and it lands on the device-global pseudo-slot.
 *
 * @param {object} spec
 * @param {string} spec.publicId   hex, exactly 6 bytes
 * @param {string} spec.privateId  hex, 6 bytes
 * @param {string} spec.secretKey  hex, 16 bytes
 * @returns {Uint8Array}
 */
function yubiGlobalCredential({ publicId, privateId, secretKey }) {
  const pub = String(publicId).trim().toLowerCase();

  if (pub.length !== YUBI.PUBLIC_ID_GLOBAL_HEX) {
    throw new Error(
      `slot 0 Yubikey public id must be exactly ${YUBI.PUBLIC_ID_GLOBAL_HEX} hex chars ` +
      `(6 bytes) - the firmware copies 6 and ignores the rest - got ${pub.length}`,
    );
  }

  return fromHex(pub + yubiTail(privateId, secretKey));
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
  yubiGlobalCredential,
};
