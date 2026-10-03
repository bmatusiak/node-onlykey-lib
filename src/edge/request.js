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
 *     agent:  the agent service's registered Ed25519 public key (hex),
 *     nonce:  16 random bytes (hex) - an app drops one it has seen,
 *     reason: the text the person reads,
 *     scopes: [{ op: 'sign' | 'decrypt', slot, cap, identity? }],
 *             identity is a NAME ("ssh://agent@nitro16", "gpg://Agent <a@x>"),
 *             required on a derived code (R11a), never a hash,
 *     lifetime: minutes,
 *     signature: Ed25519 over body(), by the agent key (hex) }
 *
 * Channels: Bluetooth first (the phone's vendor bridge keeps it for the app),
 * the Worker mailbox later (sealed). Pure: no device, no Node built-ins.
 */

const { sha256 } = require('../vendor/exports/@noble/hashes/sha2.js');
const { ed25519 } = require('../vendor/exports/@noble/curves/ed25519.js');
const { randomBytes } = require('../vendor/exports/@noble/ciphers/utils.js');
const { utf8ToBytes, toHex, fromHex } = require('../bytes');
const { OP } = require('./codes');
const grants = require('./grants');

const TYPE = 'EDGE_REQUEST';
const BODY_TAG = 'OKEDGE-REQUEST-v1';
/* D4 (Brad, 2026-10-03): at most 300 uses per budget */
const MAX_REQUEST_USES = 300;
/* CHOSEN: a request names its lifetime, 1 minute to 24 hours; the firmware's own default (12 h) is not implied */
const MAX_LIFETIME_MINUTES = 24 * 60;
/* the typed refusals an app answers with (4.7a), plus 'invalid' for a request that fails check() */
const REFUSALS = Object.freeze(['declined', 'timeout', 'copy_unverified', 'ticket_owed', 'restoring', 'invalid']);
const OPS = Object.freeze({ sign: OP.SIGN, decrypt: OP.DECRYPT });

const u16 = (n) => Uint8Array.of(n & 0xff, (n >>> 8) & 0xff);
const concat = (parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};

/*
 * The signed bytes: one unambiguous encoding, so the app checks exactly what
 * the agent signed - every length is written, nothing is JSON-dependent.
 */
function body({ agent, nonce, reason, scopes, lifetime }) {
  const reasonBytes = utf8ToBytes(String(reason));
  if (reasonBytes.length > 0xffff) throw new RangeError('edge request: the reason is too long');
  const parts = [utf8ToBytes(BODY_TAG), fromHex(agent), fromHex(nonce), u16(reasonBytes.length), reasonBytes, Uint8Array.of(scopes.length)];
  for (const s of scopes) {
    const name = utf8ToBytes(s.identity || '');
    if (name.length > 0xff) throw new RangeError('edge request: an identity name is too long');
    parts.push(Uint8Array.of(OPS[s.op] || 0, s.slot & 0xff), u16(s.cap), Uint8Array.of(name.length), name);
  }
  parts.push(u16(lifetime));
  return concat(parts);
}

/**
 * The agent side: a signed request. signer: {publicKey: 32 bytes,
 * sign(bytes) -> 64 bytes (sync or async)} - the agent service's own key.
 */
async function build({ signer, reason, scopes, lifetime, nonce = randomBytes(16) }) {
  const msg = {
    type: TYPE, v: 1,
    agent: toHex(signer.publicKey),
    nonce: toHex(nonce),
    reason: String(reason),
    scopes: scopes.map((s) => ({ op: s.op, slot: s.slot, cap: s.cap, ...(s.identity ? { identity: String(s.identity) } : {}) })),
    lifetime,
  };
  msg.signature = toHex(await signer.sign(body(msg)));
  return msg;
}

/* an Ed25519 signer from a 32-byte secret - the agent service's key, for tests and the CLI */
function signerFromSecret(secret) {
  return { publicKey: ed25519.getPublicKey(secret), sign: (bytes) => ed25519.sign(bytes, secret) };
}

const isHex = (s, n) => typeof s === 'string' && s.length === n * 2 && /^[0-9a-f]+$/i.test(s);

/**
 * The app side, first: is it a request from a registered agent, signed, and
 * new? registered: agent public keys (hex) the person registered with a press;
 * seen: the nonces already taken (a Set the app keeps). -> {ok} or {ok: false,
 * reason: 'malformed' | 'unregistered' | 'bad-signature' | 'replayed'}. An app
 * DROPS these - it answers nothing.
 */
function verify(msg, { registered, seen }) {
  if (!msg || msg.type !== TYPE || msg.v !== 1 || !isHex(msg.agent, 32) || !isHex(msg.nonce, 16) || !isHex(msg.signature, 64)
    || typeof msg.reason !== 'string' || !Array.isArray(msg.scopes) || !Number.isInteger(msg.lifetime)) {
    return { ok: false, reason: 'malformed' };
  }
  const agent = msg.agent.toLowerCase();
  if (!(registered || []).some((k) => String(k).toLowerCase() === agent)) return { ok: false, reason: 'unregistered' };
  let good = false;
  try {
    good = ed25519.verify(fromHex(msg.signature), body(msg), fromHex(msg.agent));
  } catch { good = false; }
  if (!good) return { ok: false, reason: 'bad-signature' };
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
  return sha256(utf8ToBytes(String(reason)));
}

/**
 * What the approval sheet shows: the text, the names, the caps, the lifetime,
 * who asks. ownIdentities: the person's own identity names (ok-rn's list,
 * starting with ssh://bmatusiak@localhost) - a scope naming one is marked own,
 * and the sheet shows a red warning and asks a second confirm (Brad, 2026-10-03).
 */
function view(msg, { ownIdentities = [] } = {}) {
  const own = new Set(ownIdentities.map((n) => String(n)));
  const scopes = msg.scopes.map((s) => ({ ...s, own: Boolean(s.identity && own.has(s.identity)) }));
  return {
    agent: msg.agent,
    reason: msg.reason,
    lifetime: msg.lifetime,
    uses: msg.scopes.reduce((n, s) => n + s.cap, 0),
    scopes,
    ownWarning: scopes.some((s) => s.own),
  };
}

module.exports = {
  TYPE, MAX_REQUEST_USES, MAX_LIFETIME_MINUTES, REFUSALS,
  body, build, signerFromSecret, verify, check, grantScopes, reasonHash, view,
};
