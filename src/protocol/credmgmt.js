/*
 * credmgmt.js - CTAP2 authenticatorCredentialManagement, as pure functions.
 *
 * What a person can finally do with this: see how many passkeys their key is
 * holding, which sites they belong to, and delete one. There was no way to
 * ask any of that before - a resident credential went on to the key during a
 * WebAuthn ceremony and was thereafter invisible.
 *
 * Nothing here performs I/O. A caller pairs these with CtapHid and a pinToken
 * from clientpin.js.
 *
 * ## The authenticator answers on TWO command bytes
 *
 * 0x0A is the standard one; 0x41 is the CTAP2.1-PRE preview opcode that
 * platforms shipped before the spec settled. This firmware routes BOTH to the
 * same handler (ctap.cpp:2443), so either works and a caller picks whichever
 * the rest of its stack expects.
 *
 * ## Enumeration is a WALK, and the cursor lives in the authenticator
 *
 * `curr_rp_ind`, `curr_rk_ind`, `rp_auth` and `rk_auth` are FUNCTION STATICS
 * in ctap_cred_mgmt (ctap.cpp:1736-1741). There is one set, shared by every
 * channel. Two consequences that a client cannot paper over:
 *
 *   A `*Next` without a preceding `*Begin` answers CTAP2_ERR_NO_CREDENTIALS
 *   rather than starting over - the `*_auth` flag is what says a walk is in
 *   progress, and it is cleared on any failure.
 *
 *   A second client walking at the same time moves the SAME cursor. There is
 *   no way to detect it and no way to lock. So a credential is deleted by an
 *   id read immediately before the delete, never by an index remembered from
 *   an earlier pass.
 *
 * ## A wrong pinAuth here costs a PIN attempt
 *
 * ctap_cred_mgmt_pinauth calls ctap_decrement_pin_attempts on a mismatch
 * (ctap.cpp:1609-1616) - the same eight-attempt counter that locks FIDO2
 * permanently. A bug in the byte string being authenticated is therefore as
 * expensive as a bug in the PIN itself, which is why `pinAuthMessage` below
 * is built from the EXACT CBOR that goes on the wire rather than from a
 * re-encoding of the same values.
 */
'use strict';

const cbor = require('./cbor');
const clientpin = require('./clientpin');

/** Request map keys (ctap.h:52-63). */
const PARAM = {
  SUB_COMMAND: 0x01,
  SUB_COMMAND_PARAMS: 0x02,
  PIN_PROTOCOL: 0x03,
  PIN_AUTH: 0x04,
};

/** Subcommands (ctap.h:53-58). */
const SUB = {
  METADATA: 0x01,
  RP_BEGIN: 0x02,
  RP_NEXT: 0x03,
  RK_BEGIN: 0x04,
  RK_NEXT: 0x05,
  RK_DELETE: 0x06,
};

/** Keys inside subCommandParams (ctap.h:60-61). */
const SUB_PARAM = {
  RP_ID_HASH: 0x01,
  CREDENTIAL_ID: 0x02,
};

/**
 * Response map keys, read off the encoders rather than the spec:
 * ctap_cred_metadata (ctap.cpp:1471), ctap_cred_rp (1492) and ctap_cred_rk
 * (1548).
 */
const RESP = {
  EXISTING_RESIDENT_CREDENTIALS: 0x01,
  MAX_POSSIBLE_REMAINING: 0x02,
  RP: 0x03,
  RP_ID_HASH: 0x04,
  TOTAL_RPS: 0x05,
  USER: 0x06,
  CREDENTIAL_ID: 0x07,
  PUBLIC_KEY: 0x08,
  TOTAL_CREDENTIALS: 0x09,
  CRED_PROTECT: 0x0a,
};

/** The standard command byte, and the preview one this firmware also takes. */
const COMMAND = 0x0a;
const COMMAND_PREVIEW = 0x41;

/**
 * The bytes a credMgmt pinAuth is computed over.
 *
 * The subcommand byte, then the subCommandParams map EXACTLY as encoded
 * (ctap.cpp:1607, hashing `{cmd, subCommandParamsCborCopy}` for
 * `size + 1` bytes). The firmware keeps the raw span from the parser
 * (ctap_parse.cpp:1086-1095), so what it hashes is the bytes that arrived -
 * not a re-encoding. Two encoders that disagree by one integer width would
 * produce a valid HMAC of a different message, and the counter would pay for
 * it.
 *
 * Commands with no params hash one byte: the subcommand.
 */
function pinAuthMessage(subCommand, paramsBytes = null) {
  const params = paramsBytes || new Uint8Array(0);
  const out = new Uint8Array(1 + params.length);
  out[0] = subCommand;
  out.set(params, 1);
  return out;
}

/**
 * Build one credential-management request.
 *
 * @param {number} subCommand    SUB.*
 * @param {Uint8Array} pinToken  from clientpin.readPinToken
 * @param {Map} [params]         subCommandParams, or null
 *
 * The params map is encoded ONCE and both sent and authenticated from those
 * same bytes, which is the whole point - see pinAuthMessage.
 */
function request(subCommand, pinToken, params = null) {
  const map = new Map([[PARAM.SUB_COMMAND, subCommand]]);

  let paramsBytes = null;
  if (params) {
    paramsBytes = cbor.encode(params);
    map.set(PARAM.SUB_COMMAND_PARAMS, params);
  }

  /*
   * Only four subcommands take a pinAuth at all; the two `*Next` walks do
   * not (ctap.cpp:1598-1605). Sending one where it is not wanted is not
   * harmless - it would be verified against a message the firmware never
   * hashes, and the mismatch costs an attempt.
   */
  const needsAuth = subCommand === SUB.METADATA
    || subCommand === SUB.RP_BEGIN
    || subCommand === SUB.RK_BEGIN
    || subCommand === SUB.RK_DELETE;

  if (needsAuth) {
    if (!pinToken) throw new Error(`credential management ${subCommand} needs a pinToken`);
    map.set(PARAM.PIN_PROTOCOL, clientpin.PIN_PROTOCOL);
    map.set(
      PARAM.PIN_AUTH,
      clientpin.pinTokenAuth(pinToken, pinAuthMessage(subCommand, paramsBytes)),
    );
  }

  return map;
}

/** How many resident credentials are stored, and how many more fit. */
function metadataParams(pinToken) {
  return request(SUB.METADATA, pinToken);
}

/** Start walking the relying parties. */
function rpBeginParams(pinToken) {
  return request(SUB.RP_BEGIN, pinToken);
}

/** The next relying party. NO pinAuth - the walk is already authenticated. */
function rpNextParams() {
  return request(SUB.RP_NEXT, null);
}

/**
 * Start walking the credentials of one relying party.
 *
 * @param {Uint8Array} rpIdHash  SHA-256 of the rpId, 32 bytes. It comes back
 *                               from the RP walk (RESP.RP_ID_HASH), which is
 *                               where a caller should get it - hashing an
 *                               rpId by hand is how a client ends up walking
 *                               a site it only thinks it named.
 */
function rkBeginParams(pinToken, rpIdHash) {
  if (!(rpIdHash instanceof Uint8Array) || rpIdHash.length !== 32) {
    throw new Error('an rpIdHash is 32 bytes - take it from the RP listing');
  }
  return request(SUB.RK_BEGIN, pinToken, new Map([[SUB_PARAM.RP_ID_HASH, rpIdHash]]));
}

/** The next credential. NO pinAuth. */
function rkNextParams() {
  return request(SUB.RK_NEXT, null);
}

/**
 * Delete one credential, BY ID.
 *
 * @param {Map} credentialId  the descriptor exactly as it came back from the
 *                            credential walk (RESP.CREDENTIAL_ID) - a map of
 *                            `id` and `type`
 *
 * By id and never by index, and re-read immediately before: the enumeration
 * cursors are firmware statics shared across channels, so an index from an
 * earlier pass can name a different credential by the time it is used. This
 * one is irreversible and there is no confirmation at the device.
 */
function rkDeleteParams(pinToken, credentialId) {
  if (!(credentialId instanceof Map)) {
    throw new Error(
      'delete takes the credential descriptor the listing returned, not an index',
    );
  }
  return request(SUB.RK_DELETE, pinToken, new Map([[SUB_PARAM.CREDENTIAL_ID, credentialId]]));
}

/* ---- reading the answers ------------------------------------------------ */

/**
 * @returns {{stored: number, remaining: number}}
 *
 * ZERO IS AN ANSWER, not a failure. A key with no resident credentials
 * returns success with an empty body for every OTHER subcommand
 * (ctap.cpp:1754) - metadata is the exception that still answers properly,
 * which is why it is the right thing to ask first.
 */
function readMetadata(response) {
  if (!(response instanceof Map)) return { stored: 0, remaining: 0 };
  return {
    stored: response.get(RESP.EXISTING_RESIDENT_CREDENTIALS) || 0,
    remaining: response.get(RESP.MAX_POSSIBLE_REMAINING) || 0,
  };
}

/**
 * One relying party from the walk.
 *
 * @returns {{id: string, name: string, rpIdHash: Uint8Array, total: number|null}|null}
 *
 * `total` is present only on the FIRST answer of a walk (ctap.cpp:1526-1530
 * adds it when rp_count > 0), so a caller counts down from it rather than
 * expecting it every time.
 */
function readRp(response) {
  if (!(response instanceof Map)) return null;
  const rp = response.get(RESP.RP);
  const rpIdHash = response.get(RESP.RP_ID_HASH);
  if (!rp || !rpIdHash) return null;
  return {
    id: rp.get('id') || '',
    name: rp.get('name') || '',
    rpIdHash,
    total: response.has(RESP.TOTAL_RPS) ? response.get(RESP.TOTAL_RPS) : null,
  };
}

/**
 * One credential from the walk.
 *
 * @returns {{user: Map|null, credentialId: Map|null, publicKey: Map|null,
 *            total: number|null, credProtect: number|null}|null}
 *
 * `credentialId` is handed back as the MAP it arrived as, because that is
 * what a delete has to send back. Rebuilding it from its parts is how a
 * client deletes something it did not mean to.
 */
function readCredential(response) {
  if (!(response instanceof Map)) return null;
  const credentialId = response.get(RESP.CREDENTIAL_ID);
  if (!credentialId) return null;
  return {
    user: response.get(RESP.USER) || null,
    credentialId,
    publicKey: response.get(RESP.PUBLIC_KEY) || null,
    total: response.has(RESP.TOTAL_CREDENTIALS) ? response.get(RESP.TOTAL_CREDENTIALS) : null,
    credProtect: response.has(RESP.CRED_PROTECT) ? response.get(RESP.CRED_PROTECT) : null,
  };
}

/** The readable name of a credential's user, for a list on a screen. */
function describeUser(user) {
  if (!(user instanceof Map)) return '';
  return String(user.get('displayName') || user.get('name') || '');
}

module.exports = {
  COMMAND,
  COMMAND_PREVIEW,
  PARAM,
  SUB,
  SUB_PARAM,
  RESP,

  pinAuthMessage,
  request,
  metadataParams,
  rpBeginParams,
  rpNextParams,
  rkBeginParams,
  rkNextParams,
  rkDeleteParams,

  readMetadata,
  readRp,
  readCredential,
  describeUser,
};
