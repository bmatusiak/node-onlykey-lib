/*
 * ctap.js - the WebAuthn tunnel: keyhandle encoding and assertion decoding.
 *
 * Browsers will not hand raw HID to a FIDO device, so the web app reaches the
 * OnlyKey by smuggling a vendor request through a WebAuthn ceremony: the
 * request is encoded as a credential ID, and the response comes back inside
 * the signature. This module is the encode/decode half of that; the I/O half
 * belongs to whatever transport is in use.
 *
 * Nothing here performs I/O. `encodeRequest` is pure bytes and
 * `decodeAssertion` takes an already-decoded CTAP2 getAssertion response.
 */
'use strict';

const { toLatin1 } = require('../bytes');

/** What is_extension_request() looks for at offset 4. */
const MAGIC = [0x8c, 0x27, 0x90, 0xf6];
const HEADER = 10;

/** is_extension_request() ignores anything with a shorter data region. */
const MIN_DATA = 16;

/** HEADER + payload must fit one byte. */
const MAX_PAYLOAD = 245;

/**
 * The relying-party id, and it is NOT a hosting detail.
 *
 * okcrypto_hkdf() folds the RPID into the key derivation
 * (okcrypto.cpp:245 `const char rpid[] = "onlyagent.app"`, checked against the
 * incoming appid at device.cpp:112). The same OnlyKey at a different origin
 * therefore derives DIFFERENT KEYS, with no error at any layer - it surfaces
 * much later as "no identity matched any of the recipients".
 *
 * The browser client never sets this: both `rpId` and the appid extension are
 * commented out, so WebAuthn falls back to the page origin, which happens to
 * be onlyagent.app only because BUILD.sh writes that CNAME. This library
 * drives CTAP2 directly and so must state it. Overriding it is deliberate and
 * loud for that reason.
 */
const RP_ID = 'apps.crp.to';

/**
 * Every origin worth trying, most compatible FIRST.
 *
 * THE ORIGIN IS PART OF THE KEY, AND THAT IS THE DESIGN. `okcrypto_hkdf()`
 * reads the rpId out of the CTAP buffer, hashes it, and mixes that hash into
 * the HKDF expand step, so the same slot and the same input data derive a
 * DIFFERENT key at every origin. That is what makes per-site derived keys work
 * at all: a third-party site asks with its own hostname and gets keys only it
 * can ask for again. `webcryptcheck()` has a branch for exactly that - it
 * answers 2 for the first-party origin and 1 for any other, given the
 * `0xFFFFFFFF` OKCONNECT bootstrap and bit 2 of `derived_key_challenge_mode`
 * (setting 21, writable in config mode or on first use).
 *
 * WHICH MEANS THE CHOICE HERE IS WHICH KEYSPACE TO LAND IN, not whether the
 * device will answer. Send one origin, derive one set of keys; send another,
 * derive another set, with no error anywhere - it surfaces much later as a
 * file that will not open. So the order is pinned by a test rather than left
 * to whichever constant was added most recently.
 *
 * `apps.crp.to` leads because it is the FIRST-PARTY origin: it is the one that
 * answers 2, the full vendor extension, without depending on an EEPROM bit
 * somebody has to have set. Measured byte for byte at every pin in
 * ok-versions.json from the 2019 beta to the working tree - `stored_apprpid`
 * has never changed. `onlyagent.app` is an ADDITION the working tree made in
 * 2026 (libraries@a5b731f) and is matched by its appid HASH rather than as an
 * rpId string; no release carries it.
 *
 * Leading with `onlyagent.app` is what made the whole vendor path - every
 * derive, the vault, age identities - go unanswered on released firmware,
 * which nobody saw because a debug build returns 2 before comparing anything.
 * ok-rn/FINDING-the-vendor-path-is-origin-gated.md
 *
 * A host overrides the list with
 * `plugins.config = { okcrypto: { rpIds: [...] } }`, which is also the door to
 * third-party mode: pass a site's own hostname and the derives land in that
 * site's keyspace instead of this one.
 */
const RP_IDS = [RP_ID, 'onlyagent.app'];

/**
 * CTAP status codes, transcribed from onlykey.extra.js:245-292.
 *
 * The full table, not the 9-entry CTAP1 subset in onlykey-testing's tunnel.js:
 * the polling loop keys off the *names* CTAP1_SUCCESS,
 * CTAP2_ERR_USER_ACTION_PENDING and CTAP2_ERR_EXTENSION_NOT_SUPPORTED, and a
 * short table renders those as a bare hex string that no branch matches.
 *
 * Byte 0 of the signature is a CTAP1/U2F code, not the CTAP2 code the
 * surrounding assertion carries.
 */
const STATUS = {
  0x00: 'CTAP1_SUCCESS',
  0x01: 'CTAP1_ERR_INVALID_COMMAND',
  0x02: 'CTAP1_ERR_INVALID_PARAMETER',
  0x03: 'CTAP1_ERR_INVALID_LENGTH',
  0x04: 'CTAP1_ERR_INVALID_SEQ',
  0x05: 'CTAP1_ERR_TIMEOUT',
  0x06: 'CTAP1_ERR_CHANNEL_BUSY',
  0x0a: 'CTAP1_ERR_LOCK_REQUIRED',
  0x0b: 'CTAP1_ERR_INVALID_CHANNEL',

  0x10: 'CTAP2_ERR_CBOR_PARSING',
  0x11: 'CTAP2_ERR_CBOR_UNEXPECTED_TYPE',
  0x12: 'CTAP2_ERR_INVALID_CBOR',
  0x13: 'CTAP2_ERR_INVALID_CBOR_TYPE',
  0x14: 'CTAP2_ERR_MISSING_PARAMETER',
  0x15: 'CTAP2_ERR_LIMIT_EXCEEDED',
  0x16: 'CTAP2_ERR_UNSUPPORTED_EXTENSION',
  0x17: 'CTAP2_ERR_TOO_MANY_ELEMENTS',
  0x18: 'CTAP2_ERR_EXTENSION_NOT_SUPPORTED',
  0x19: 'CTAP2_ERR_CREDENTIAL_EXCLUDED',
  0x20: 'CTAP2_ERR_CREDENTIAL_NOT_VALID',
  0x21: 'CTAP2_ERR_PROCESSING',
  0x22: 'CTAP2_ERR_INVALID_CREDENTIAL',
  0x23: 'CTAP2_ERR_USER_ACTION_PENDING',
  0x24: 'CTAP2_ERR_OPERATION_PENDING',
  0x25: 'CTAP2_ERR_NO_OPERATIONS',
  0x26: 'CTAP2_ERR_UNSUPPORTED_ALGORITHM',
  0x27: 'CTAP2_ERR_OPERATION_DENIED',
  0x28: 'CTAP2_ERR_KEY_STORE_FULL',
  0x29: 'CTAP2_ERR_NOT_BUSY',
  0x2a: 'CTAP2_ERR_NO_OPERATION_PENDING',
  0x2b: 'CTAP2_ERR_UNSUPPORTED_OPTION',
  0x2c: 'CTAP2_ERR_INVALID_OPTION',
  0x2d: 'CTAP2_ERR_KEEPALIVE_CANCEL',
  0x2e: 'CTAP2_ERR_NO_CREDENTIALS',
  0x2f: 'CTAP2_ERR_USER_ACTION_TIMEOUT',
  0x30: 'CTAP2_ERR_NOT_ALLOWED',
  0x31: 'CTAP2_ERR_PIN_INVALID',
  0x32: 'CTAP2_ERR_PIN_BLOCKED',
  0x33: 'CTAP2_ERR_PIN_AUTH_INVALID',
  0x34: 'CTAP2_ERR_PIN_AUTH_BLOCKED',
  0x35: 'CTAP2_ERR_PIN_NOT_SET',
  0x36: 'CTAP2_ERR_PIN_REQUIRED',
  0x37: 'CTAP2_ERR_PIN_POLICY_VIOLATION',
  0x38: 'CTAP2_ERR_PIN_TOKEN_EXPIRED',
  0x39: 'CTAP2_ERR_REQUEST_TOO_LARGE',
};

/** The only status that carries a payload. See chunk.js for why that matters. */
const SUCCESS = 'CTAP1_SUCCESS';

function statusName(code) {
  return STATUS[code] || `0x${code.toString(16).padStart(2, '0')}`;
}

/**
 * Encode a vendor request as a fake credential ID.
 *
 *   [0]      cmd
 *   [1..3]   opt1, opt2, opt3
 *   [4..7]   8C 27 90 F6   the vendor magic
 *   [8]      0
 *   [9]      the REAL payload length, not the padded size
 *   [10..]   payload, zero-padded so the data region is at least 16 bytes
 */
function encodeRequest({ cmd, opt1 = 0, opt2 = 0, opt3 = 0, data }) {
  const payload = data ? Uint8Array.from(data) : new Uint8Array(0);
  if (HEADER + payload.length > 255) {
    throw new RangeError(
      `keyhandle would be ${HEADER + payload.length} bytes; the maximum payload is ` +
        `${MAX_PAYLOAD}. Chunk the request instead - see protocol/chunk.js.`,
    );
  }

  let pad = payload.length < MIN_DATA ? MIN_DATA - payload.length : 0;

  /*
   * TWO LENGTHS ARE POISONED, and the failure is silent.
   *
   * parse_credential_descriptor (ctap_parse.cpp:906-948) classifies an
   * allowList entry by its LENGTH before it looks at anything else:
   *
   *     48 == U2F_KEY_HANDLE_SIZE   -> PUB_KEY_CRED_CTAP1
   *     70 == sizeof(CredentialId)  -> a real FIDO2 credential
   *     anything else               -> PUB_KEY_CRED_CUSTOM, which is the only
   *                                    type is_extension_request() ever sees
   *
   * So a request that happens to encode to exactly 48 or 70 bytes is never
   * offered to the tunnel at all - it is parsed as somebody's credential,
   * fails to match one, and the assertion comes back "no credentials". The
   * magic bytes are never even reached.
   *
   * With a 10-byte header that is a 38- or 60-byte payload: an OKSETSLOT with
   * a 38-character password, say. One extra pad byte moves it out of the way,
   * and trailing padding is already known-harmless - the firmware slices the
   * payload at fixed offsets and the shipped client has always padded to
   * MIN_DATA.
   */
  const POISONED = [48, 70];
  if (POISONED.includes(HEADER + payload.length + pad)) pad += 1;

  const out = new Uint8Array(HEADER + payload.length + pad);
  out[0] = cmd & 0xff;
  out[1] = opt1 & 0xff;
  out[2] = opt2 & 0xff;
  out[3] = opt3 & 0xff;
  out.set(MAGIC, 4);
  out[8] = 0;
  // The true length, so the firmware slices correctly despite the padding.
  out[9] = payload.length & 0xff;
  out.set(payload, HEADER);
  return out;
}

/**
 * Decode a CTAP2 getAssertion response.
 *
 * @param {Map} assertion  the decoded CBOR map: 2 = authData, 3 = signature
 * @returns {{status: string, code: number, data: Uint8Array|null,
 *            error: string|null, count: number|null}}
 *
 * The whole answer rides in the signature: byte 0 is the status, the rest is
 * the payload. `data` is null when the signature is just the status byte -
 * and that is not a rare case. Dereferencing it unguarded inside a .then() is
 * how the shipped client stranded its promise, leaving a WebAuthn prompt on
 * screen forever (onlykey-api.js:295-303).
 */
function decodeAssertion(assertion) {
  const authData = assertion.get(2);
  const signature = assertion.get(3);
  if (!signature || !signature.length) {
    throw new Error('assertion carried no signature');
  }

  const sig = Uint8Array.from(signature);
  const code = sig[0];
  const data = sig.length > 1 ? sig.subarray(1) : null;

  /*
   * A device error arrives as an ASCII string in place of a payload. The
   * bound is on the SIGNATURE length (72-byte default sigder_sz, plus the
   * status byte) - onlykey-testing's tunnel.js tests data.length instead and
   * is off by one against the firmware's actual behaviour.
   */
  let error = null;
  if (data && sig.length < 73 && toLatin1(data.subarray(0, 6)) === 'Error ') {
    const end = data.indexOf(0x00);
    error = toLatin1(end === -1 ? data : data.subarray(0, end));
  }

  let count = null;
  if (authData && authData.length >= 37) {
    const a = Uint8Array.from(authData);
    count = new DataView(a.buffer, a.byteOffset, a.byteLength).getUint32(33, false);
  }

  return { status: statusName(code), code, data, error, count };
}

/** CTAP2 authenticatorGetAssertion parameters for a tunnelled request. */
function assertionParams(credentialId, { rpId = RP_ID, clientDataHash } = {}) {
  if (!clientDataHash || clientDataHash.length !== 32) {
    throw new Error('clientDataHash must be 32 bytes (the host supplies randomness)');
  }
  return new Map([
    [1, rpId],
    [2, clientDataHash],
    [3, [new Map([['id', credentialId], ['type', 'public-key']])]],
  ]);
}

module.exports = {
  MAGIC,
  HEADER,
  MIN_DATA,
  MAX_PAYLOAD,
  RP_ID,
  RP_IDS,
  STATUS,
  SUCCESS,
  statusName,
  encodeRequest,
  decodeAssertion,
  assertionParams,
};
