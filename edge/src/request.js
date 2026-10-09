'use strict';

/**
 * EDGE_REQUEST - a budget request, the same message on every channel
 * (onlykey-edge build/mcp-service.md 4.7a, decided 2026-10-03).
 *
 * The key only ever sees hashes - the reason hash, the identity labels - but
 * the person must approve the TEXT and the NAMES. So a budget request goes to
 * the APP (ok-rn), never to the key, and the app builds what the key gets:
 *
 *   { type: 'EDGE_REQUEST', v: 1,
 *     nonce:  16 random bytes (hex) - an app drops one it has seen,
 *     reason: the text the person reads,
 *     scopes: [{ op: 'sign' | 'decrypt', slot, cap, identity? }],
 *             identity is a NAME ("ssh://agent@nitro16", "gpg://Agent <a@x>"),
 *             required on a derived code (R11a), never a hash,
 *     lifetime: minutes, REQUIRED (1 minute .. 24 hours; never the key's 12 h default),
 *     continue?: a budget id - "continues <budget>": the same scopes, new
 *             uses and a new lifetime, opened with a press like a new budget }
 *
 * Every hash the key gets - the identity labels, the reason hash - the APP
 * makes from the names and the text. A request carrying hashes of its own
 * (reasonHash, label, labels ...) is not read for them: nothing here looks.
 *
 * WHO ASKS is the Bluetooth pairing (Brad, 2026-10-08: "so the claude key thing is overkill";
 * "lets cut it out"): the phone takes a request only inside the encrypted session of a computer
 * paired with its 6-digit code, and names that computer on the sheet. No agent key, no signature,
 * no registration - the pairing already proves which computer it is, and Revoke cuts it off.
 *
 * Channels: Bluetooth first (the phone's vendor bridge keeps it for the app),
 * the Worker mailbox later (sealed). Pure: no device, no Node built-ins.
 */

const crypto = require('../../src/crypto/provider');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { randomBytes } = require('../../src/vendor/exports/@noble/ciphers/utils.js');
const { utf8ToBytes, toHex } = require('../../src/bytes');
const { OP } = require('./codes');
const grants = require('./grants');

const TYPE = 'EDGE_REQUEST';
/* D4 (Brad, 2026-10-03): at most 300 uses per budget */
const MAX_REQUEST_USES = 300;
/* CHOSEN: a request names its lifetime, 1 minute to 24 hours; the firmware's own default (12 h) is not implied */
const MAX_LIFETIME_MINUTES = 24 * 60;
/* the typed refusals an app answers with (4.7a), plus 'invalid' for a request that fails check() */
/* still_live (4.7a, 2026-10-03): a continue names a budget that has not ended - only an ended budget can be continued */
/* busy (2026-10-04): another request is on the phone's sheet - one at a time, never queued */
const REFUSALS = Object.freeze(['declined', 'timeout', 'copy_unverified', 'receipt_owed', 'still_live', 'invalid', 'busy']);
const OPS = Object.freeze({ sign: OP.SIGN, decrypt: OP.DECRYPT });

const isHex = (s, n) => typeof s === 'string' && s.length === n * 2 && /^[0-9a-f]+$/i.test(s);
const isU32 = (n) => Number.isInteger(n) && n >= 0 && n <= 0xffffffff;

/** The asking side (an agent on a paired computer): a request. */
async function build({ reason, scopes, lifetime, continueOf = null, nonce = randomBytes(16) }) {
  return {
    type: TYPE, v: 1,
    nonce: toHex(nonce),
    reason: String(reason),
    scopes: scopes.map((s) => ({ op: s.op, slot: s.slot, cap: s.cap, ...(s.identity ? { identity: String(s.identity) } : {}) })),
    lifetime,
    ...(continueOf !== null && continueOf !== undefined ? { continue: continueOf } : {}),
  };
}

/*
 * A P-256 signer from a 32-byte secret - this computer's own sync key (<edge home>/peer.key):
 * it signs every sync message, so the phone can tell which computer sent a log. No list
 * of peers since 2026-10-08 (Brad: peers dropped) - the Bluetooth pairing is the gate.
 */
function peerSignerFromSecret(secret) {
  return {
    publicKey: p256.getPublicKey(secret, false).slice(1),
    sign: (bytes) => p256.sign(bytes, secret, { prehash: true }),
  };
}

/**
 * The app side, first: is it a well-formed request, and new? seen: the nonces already taken
 * (a Set the app keeps). -> {ok} or {ok: false, reason: 'malformed' | 'replayed'}. An app DROPS
 * these - it answers nothing. Who asks was settled before: the paired computer's encrypted
 * session (the phone's vendor bridge).
 */
function verify(msg, { seen } = {}) {
  if (!msg || msg.type !== TYPE || msg.v !== 1 || !isHex(msg.nonce, 16)
    || typeof msg.reason !== 'string' || !Array.isArray(msg.scopes) || !Number.isInteger(msg.lifetime)
    || (msg.continue !== undefined && !isU32(msg.continue))) {
    return { ok: false, reason: 'malformed' };
  }
  if (seen && seen.has(msg.nonce.toLowerCase())) return { ok: false, reason: 'replayed' };
  return { ok: true };
}

/**
 * The app side, second: is the request one a budget may be? Caps (each >= 1,
 * together <= 300, D4), the lifetime (1 minute .. 24 hours), the ops, and an
 * identity on every derived code (R11a) that parses. -> {ok} or {ok: false, reason}.
 */
function check(msg) {
  if (msg.scopes.length < 1 || msg.scopes.length > 4) return { ok: false, reason: 'a budget has 1 to 4 scopes' };
  let uses = 0;
  for (const s of msg.scopes) {
    if (!(s.op in OPS)) return { ok: false, reason: `unknown op "${s.op}"` };
    if (!Number.isInteger(s.slot) || s.slot < 1 || s.slot > 255) return { ok: false, reason: `bad slot ${s.slot}` };
    if (!Number.isInteger(s.cap) || s.cap < 1) return { ok: false, reason: `bad cap ${s.cap}` };
    uses += s.cap;
    if (grants.isDerivedCode(s.slot)) {
      if (!s.identity) return { ok: false, reason: `slot ${s.slot} is a derived code: the scope must name its identity (R11a)` };
      try { grants.identityLabel(s.identity); } catch (e) { return { ok: false, reason: e.message }; }
    } else if (s.identity) {
      return { ok: false, reason: `slot ${s.slot} is a stored key: it takes no identity` };
    }
  }
  if (uses > MAX_REQUEST_USES) return { ok: false, reason: `${uses} uses - a budget has at most ${MAX_REQUEST_USES} (D4)` };
  if (msg.lifetime < 1 || msg.lifetime > MAX_LIFETIME_MINUTES) return { ok: false, reason: `a lifetime of ${msg.lifetime} minutes - 1 to ${MAX_LIFETIME_MINUTES}` };
  return { ok: true, uses };
}

/* the scopes the key gets: the op as a number, identity kept - the lib's grant() makes the label from the name itself */
function grantScopes(msg) {
  return msg.scopes.map((s) => ({ op: OPS[s.op], slot: s.slot, cap: s.cap, ...(s.identity ? { identity: s.identity } : {}) }));
}

/* the reason hash the key gets, made by the APP from the text the person read - never one the agent sends */
function reasonHash(reason) {
  return crypto.sha256(utf8ToBytes(String(reason)));
}

/**
 * What the approval sheet shows: the text, the names (the identities the agent asks
 * for), the caps, the lifetime (who asks - the paired computer - the app adds). No "yours" mark and no red warning since
 * 2026-10-08 (Brad: "the agent can look at my keychain ... it can ask me to use it";
 * he reads the identities on the sheet and decides).
 */
function view(msg, { covered = [] } = {}) {
  const scopes = msg.scopes.map((s) => ({ ...s }));
  return {
    reason: msg.reason,
    lifetime: msg.lifetime,
    uses: msg.scopes.reduce((n, s) => n + s.cap, 0),
    scopes,
    continues: msg.continue === undefined ? null : msg.continue,
    /*
     * 4.7a: live budgets that already cover an identity (or slot) this request
     * names - "this agent already has N uses left on <identity> until <time>".
     * [{identity?, slot, usesLeft, endsAt?, grantId, sameComputer}], from the app.
     */
    covered,
  };
}

/* a continue keeps the scopes: the same ops, slots and identities, in any order; only the caps may change */
const scopeKey = (s) => `${s.op}/${s.slot}/${s.identity || ''}`;
function sameScopes(a, b) {
  if (a.length !== b.length) return false;
  const x = a.map(scopeKey).sort();
  const y = b.map(scopeKey).sort();
  return x.every((k, i) => k === y[i]);
}

module.exports = {
  TYPE, MAX_REQUEST_USES, MAX_LIFETIME_MINUTES, REFUSALS,
  build, verify, check, grantScopes, reasonHash, view, sameScopes,
  peerSignerFromSecret,
};
