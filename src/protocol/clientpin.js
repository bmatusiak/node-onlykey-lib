/*
 * clientpin.js - CTAP2 authenticatorClientPIN, protocol 1, as a pile of pure
 * functions. Nothing here performs I/O; a caller pairs these with CtapHid.
 *
 * This is what lets a phone SET the key's FIDO2 PIN, change it, ask how many
 * attempts are left, and get the pinToken that credential management needs.
 * The library could already tunnel a vendor request through a WebAuthn
 * ceremony (ctap.js) and nothing else.
 *
 * ## Protocol 1, and it is not a choice
 *
 * The spec has two PIN protocols and the newer one is better in every way:
 * HKDF instead of a bare hash, an explicit IV, HMAC over a longer context.
 * This firmware refuses it outright - `if (CP.pinProtocol != 1 ...) return
 * CTAP1_ERR_OTHER` (ctap.cpp:2217) - so everything below is protocol 1:
 *
 *   sharedSecret = SHA-256(ECDH_P256(platformPriv, authenticatorPub).x)
 *   newPinEnc    = AES-256-CBC(sharedSecret, IV=0) over the PIN, zero-padded
 *                  to exactly 64 bytes
 *   pinHashEnc   = AES-256-CBC(sharedSecret, IV=0) over SHA-256(PIN)[0..16]
 *   pinAuth      = HMAC-SHA-256(sharedSecret, ...)[0..16]
 *
 * The IV is zero on every call, not carried between them: OnlyKey replaced
 * Solo's running CBC context with `okcore_aes_cbc_encrypt(state, key, len)`,
 * which allocates `uint8_t iv[16] = {0}` each time (okcore.cpp:7958-7976).
 * The same is true in the other direction, which is why pinHashEnc decrypts
 * correctly even though the firmware decrypts newPinEnc first: two separate
 * calls, two zero IVs. A client that chained the IV would agree with Solo and
 * not with this key.
 *
 * ## Every wrong attempt costs two things, so the bytes are tested first
 *
 * A failed PIN decrements a counter that locks FIDO2 PERMANENTLY at eight
 * (PIN_LOCKOUT_ATTEMPTS, ctap.h:170) and locks it until a replug at three
 * (PIN_BOOT_ATTEMPTS, ctap.h:171). A bug in any byte below is therefore not
 * a failed request, it is one of eight lives spent. Hence: unit tests pin the
 * exact wire bytes, and the e2e path reaches a real key only after they pass.
 *
 * And the FIRST thing a failure does is throw the authenticator's key
 * agreement key away (`ctap_reset_key_agreement()`, ctap.cpp:2120 and 2170),
 * BEFORE the counter moves. So a client that caches the authenticator public
 * key and retries with it computes a shared secret nobody else has, and burns
 * a SECOND attempt proving it. getKeyAgreement is re-issued for every single
 * attempt; see `keyAgreementParams`.
 */
'use strict';

const { p256 } = require('@noble/curves/nist.js');
const { cbc } = require('@noble/ciphers/aes.js');
const { sha256 } = require('@noble/hashes/sha2.js');
const { hmac } = require('@noble/hashes/hmac.js');

const cose = require('./cose');
const { utf8ToBytes, concat } = require('../bytes');

/** The only protocol this firmware accepts (ctap.cpp:2217). */
const PIN_PROTOCOL = 1;

/** Request map keys (ctap.h:65-77). */
const PARAM = {
  PIN_PROTOCOL: 0x01,
  SUB_COMMAND: 0x02,
  KEY_AGREEMENT: 0x03,
  PIN_AUTH: 0x04,
  NEW_PIN_ENC: 0x05,
  PIN_HASH_ENC: 0x06,
  GET_KEY_AGREEMENT: 0x07,
  GET_RETRIES: 0x08,
};

/** Subcommands (ctap.h:67-71). */
const SUB = {
  GET_RETRIES: 0x01,
  GET_KEY_AGREEMENT: 0x02,
  SET_PIN: 0x03,
  CHANGE_PIN: 0x04,
  GET_PIN_TOKEN: 0x05,
};

/** Response map keys (ctap.h:110-112). */
const RESP = {
  KEY_AGREEMENT: 0x01,
  PIN_TOKEN: 0x02,
  RETRIES: 0x03,
};

/**
 * The padded plaintext is exactly this long, always.
 *
 * The firmware recovers the PIN LENGTH by counting zero bytes backwards from
 * index 63 (`trailing_zeros(pinEnc, NEW_PIN_ENC_MIN_SIZE - 1)`,
 * ctap.cpp:2082), so the padding is not decoration - it is the length field.
 * Sending 32 bytes of ciphertext would make the firmware read whatever lies
 * at offsets 32..63 of its own buffer as part of the PIN.
 */
const PIN_BLOCK = 64;

/** ctap.h:156-157, read through the `ret < MIN || ret >= MAX` test. */
const PIN_MIN_BYTES = 4;
const PIN_MAX_BYTES = 63;

/** ctap.h:436. Sixteen, not thirty-two: one AES block. */
const PIN_TOKEN_SIZE = 16;

const ZERO_IV = new Uint8Array(16);

/**
 * AES-256-CBC with a zero IV and NO padding.
 *
 * `disablePadding` is required, not tidiness. noble applies PKCS#7 by
 * default, which would turn a 64-byte plaintext into 80 bytes of ciphertext;
 * the firmware rounds the length up to a block boundary and decrypts in
 * place, so those extra 16 bytes would be decrypted as PIN material and the
 * length count would find no trailing zeros at all.
 */
function encryptCbc(key, data) {
  return cbc(key, ZERO_IV, { disablePadding: true }).encrypt(data);
}

function decryptCbc(key, data) {
  return cbc(key, ZERO_IV, { disablePadding: true }).decrypt(data);
}

/**
 * A fresh platform key pair for one exchange.
 *
 * Fresh per exchange because it is free and because reusing one gives an
 * observer of the bus a long-lived handle to correlate; the authenticator
 * treats its own side as ephemeral too.
 */
function newPlatformKey() {
  const secretKey = p256.utils.randomSecretKey();
  const publicKey = p256.getPublicKey(secretKey, false);
  return { secretKey, publicKey, coseKey: cose.encodeP256(publicKey) };
}

/**
 * SHA-256 of the ECDH x coordinate - the whole key derivation for protocol 1.
 *
 * @param {Uint8Array} secretKey            the platform private key
 * @param {Map|Uint8Array} authenticatorKey the decoded COSE_Key from
 *                                          getKeyAgreement, or a raw 65-byte
 *                                          uncompressed point
 *
 * noble returns the shared point COMPRESSED - 33 bytes, a sign prefix and
 * then x - so the prefix is dropped. Hashing all 33 would produce a secret
 * that differs from the device's for half of all key pairs at random, which
 * is the kind of bug that looks like flaky hardware.
 */
function sharedSecret(secretKey, authenticatorKey) {
  const peer = authenticatorKey instanceof Uint8Array
    ? authenticatorKey
    : cose.decodeP256(authenticatorKey).uncompressed;
  const point = p256.getSharedSecret(secretKey, peer, true);
  return sha256(point.subarray(1));
}

/** The PIN as the firmware wants it: UTF-8, zero-padded to 64 bytes. */
function padPin(pin) {
  const bytes = utf8ToBytes(String(pin));
  if (bytes.length < PIN_MIN_BYTES || bytes.length > PIN_MAX_BYTES) {
    throw new Error(
      `a FIDO2 PIN is ${PIN_MIN_BYTES}..${PIN_MAX_BYTES} bytes of UTF-8; ` +
        `this one is ${bytes.length}`,
    );
  }
  if (bytes.includes(0)) {
    throw new Error('a FIDO2 PIN cannot contain a zero byte: it is the length marker');
  }
  const out = new Uint8Array(PIN_BLOCK);
  out.set(bytes);
  return out;
}

/** AES(sharedSecret, PIN padded to 64). */
function newPinEnc(secret, pin) {
  return encryptCbc(secret, padPin(pin));
}

/** AES(sharedSecret, SHA-256(PIN) truncated to 16) - one block. */
function pinHashEnc(secret, pin) {
  return encryptCbc(secret, sha256(utf8ToBytes(String(pin))).subarray(0, 16));
}

/** HMAC-SHA-256 under the shared secret, truncated to 16 bytes. */
function pinAuth(secret, ...parts) {
  return hmac(sha256, secret, concat(parts)).subarray(0, 16);
}

/**
 * The same truncated HMAC, but keyed by the PIN TOKEN rather than the shared
 * secret: this is what makeCredential, getAssertion and credential management
 * put in their own pinAuth field.
 */
function pinTokenAuth(pinToken, message) {
  return hmac(sha256, pinToken, message).subarray(0, 16);
}

/** Accept either the pair from newPlatformKey() or an already-built map. */
function coseOf(platformKey) {
  if (platformKey instanceof Map) return platformKey;
  if (platformKey && platformKey.coseKey) return platformKey.coseKey;
  return cose.encodeP256(platformKey);
}

/** Ask how many attempts are left. Costs nothing and takes no PIN. */
function retriesParams() {
  return new Map([
    [PARAM.PIN_PROTOCOL, PIN_PROTOCOL],
    [PARAM.SUB_COMMAND, SUB.GET_RETRIES],
  ]);
}

/**
 * Ask for the authenticator's key agreement key.
 *
 * ONCE PER ATTEMPT. The device regenerates this pair on every PIN failure
 * (ctap.cpp:2120), so a cached copy is worth exactly one more wasted retry.
 */
function keyAgreementParams() {
  return new Map([
    [PARAM.PIN_PROTOCOL, PIN_PROTOCOL],
    [PARAM.SUB_COMMAND, SUB.GET_KEY_AGREEMENT],
  ]);
}

/**
 * Set a PIN on a key that has none.
 *
 * The firmware answers CTAP2_ERR_NOT_ALLOWED if one is already set
 * (ctap.cpp:2255), so a caller decides between this and `changePinParams`
 * from getInfo's `clientPin` option rather than by trying one and catching.
 */
function setPinParams({ secret, platformKey, newPin }) {
  const enc = newPinEnc(secret, newPin);
  return new Map([
    [PARAM.PIN_PROTOCOL, PIN_PROTOCOL],
    [PARAM.SUB_COMMAND, SUB.SET_PIN],
    [PARAM.KEY_AGREEMENT, coseOf(platformKey)],
    [PARAM.PIN_AUTH, pinAuth(secret, enc)],
    [PARAM.NEW_PIN_ENC, enc],
  ]);
}

/**
 * Change a PIN, proving the current one.
 *
 * pinAuth covers newPinEnc FOLLOWED BY pinHashEnc, in that order and with
 * nothing between them (ctap.cpp:2050-2056). Swapping them produces a valid
 * HMAC of the wrong message, which the firmware reports as
 * CTAP2_ERR_PIN_AUTH_INVALID - and unlike a wrong PIN that one does NOT cost
 * an attempt, because the check happens before the counter can move.
 */
function changePinParams({ secret, platformKey, currentPin, newPin }) {
  const enc = newPinEnc(secret, newPin);
  const hash = pinHashEnc(secret, currentPin);
  return new Map([
    [PARAM.PIN_PROTOCOL, PIN_PROTOCOL],
    [PARAM.SUB_COMMAND, SUB.CHANGE_PIN],
    [PARAM.KEY_AGREEMENT, coseOf(platformKey)],
    [PARAM.PIN_AUTH, pinAuth(secret, enc, hash)],
    [PARAM.NEW_PIN_ENC, enc],
    [PARAM.PIN_HASH_ENC, hash],
  ]);
}

/** Exchange the PIN for a token. No pinAuth: the hash is the proof. */
function pinTokenParams({ secret, platformKey, pin }) {
  return new Map([
    [PARAM.PIN_PROTOCOL, PIN_PROTOCOL],
    [PARAM.SUB_COMMAND, SUB.GET_PIN_TOKEN],
    [PARAM.KEY_AGREEMENT, coseOf(platformKey)],
    [PARAM.PIN_HASH_ENC, pinHashEnc(secret, pin)],
  ]);
}

/* ---- reading the answers ------------------------------------------------ */

/** The authenticator's key agreement key, decoded. */
function readKeyAgreement(response) {
  const key = response && response.get(RESP.KEY_AGREEMENT);
  if (!key) throw new Error('clientPin getKeyAgreement returned no key');
  return cose.decodeP256(key);
}

/** Attempts left before FIDO2 locks for good. */
function readRetries(response) {
  const n = response && response.get(RESP.RETRIES);
  if (typeof n !== 'number') throw new Error('clientPin getRetries returned no count');
  return n;
}

/**
 * The pinToken, decrypted.
 *
 * Sixteen bytes in and sixteen out: PIN_TOKEN_SIZE is one AES block, so
 * there is exactly one block to decrypt and no padding to strip.
 */
function readPinToken(response, secret) {
  const enc = response && response.get(RESP.PIN_TOKEN);
  if (!(enc instanceof Uint8Array) || enc.length !== PIN_TOKEN_SIZE) {
    throw new Error(
      `clientPin getPinToken returned ${enc ? enc.length : 'no'} bytes, ` +
        `expected ${PIN_TOKEN_SIZE}`,
    );
  }
  return decryptCbc(secret, enc);
}

module.exports = {
  PIN_PROTOCOL,
  PARAM,
  SUB,
  RESP,
  PIN_BLOCK,
  PIN_MIN_BYTES,
  PIN_MAX_BYTES,
  PIN_TOKEN_SIZE,

  newPlatformKey,
  sharedSecret,
  padPin,
  newPinEnc,
  pinHashEnc,
  pinAuth,
  pinTokenAuth,

  retriesParams,
  keyAgreementParams,
  setPinParams,
  changePinParams,
  pinTokenParams,

  readKeyAgreement,
  readRetries,
  readPinToken,
};
