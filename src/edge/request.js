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
 *     lifetime: minutes, REQUIRED (1 minute .. 24 hours; never the key's 12 h default),
 *     continue?: a budget id - "continues <budget>": the same scopes, new
 *             uses and a new lifetime, opened with a press like a new budget,
 *     signature: Ed25519 over body(), by the agent key (hex) }
 *
 * Every hash the key gets - the identity labels, the reason hash - the APP
 * makes from the names and the text. A request carrying hashes of its own
 * (reasonHash, label, labels ...) is not read for them: nothing here looks.
 *
 * Before an agent may ask, its key is registered ONCE, with a press:
 *
 *   { type: 'EDGE_REGISTER', v: 1, agent, name, nonce, signature }
 *
 * signed by the agent key itself (it holds the secret). Until then an app
 * refuses the agent's requests without reading them.
 *
 * Channels: Bluetooth first (the phone's vendor bridge keeps it for the app),
 * the Worker mailbox later (sealed). Pure: no device, no Node built-ins.
 */

const crypto = require('../crypto/provider');
const { ed25519 } = require('../vendor/exports/@noble/curves/ed25519.js');
const { p256 } = require('../vendor/exports/@noble/curves/nist.js');
const { randomBytes } = require('../vendor/exports/@noble/ciphers/utils.js');
const { utf8ToBytes, toHex, fromHex } = require('../bytes');
const { OP } = require('./codes');
const grants = require('./grants');

const TYPE = 'EDGE_REQUEST';
const REGISTER_TYPE = 'EDGE_REGISTER';
const BODY_TAG = 'OKEDGE-REQUEST-v1';
const REGISTER_TAG = 'OKEDGE-REGISTER-v1';
/* D4 (Brad, 2026-10-03): at most 300 uses per budget */
const MAX_REQUEST_USES = 300;
/* CHOSEN: a request names its lifetime, 1 minute to 24 hours; the firmware's own default (12 h) is not implied */
const MAX_LIFETIME_MINUTES = 24 * 60;
/* the typed refusals an app answers with (4.7a), plus 'invalid' for a request that fails check() */
/* still_live (4.7a, 2026-10-03): a continue names a budget that has not ended - only an ended budget can be continued */
/* busy (2026-10-04): another request is on the phone's sheet - one at a time, never queued */
const REFUSALS = Object.freeze(['declined', 'timeout', 'copy_unverified', 'ticket_owed', 'restoring', 'still_live', 'invalid', 'busy']);
const OPS = Object.freeze({ sign: OP.SIGN, decrypt: OP.DECRYPT });

const u16 = (n) => Uint8Array.of(n & 0xff, (n >>> 8) & 0xff);
const u32 = (n) => Uint8Array.of(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff);
const isU32 = (n) => Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
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
function body({ agent, nonce, reason, scopes, lifetime, continue: cont }) {
  const reasonBytes = utf8ToBytes(String(reason));
  if (reasonBytes.length > 0xffff) throw new RangeError('edge request: the reason is too long');
  const parts = [utf8ToBytes(BODY_TAG), fromHex(agent), fromHex(nonce), u16(reasonBytes.length), reasonBytes, Uint8Array.of(scopes.length)];
  for (const s of scopes) {
    const name = utf8ToBytes(s.identity || '');
    if (name.length > 0xff) throw new RangeError('edge request: an identity name is too long');
    parts.push(Uint8Array.of(OPS[s.op] || 0, s.slot & 0xff), u16(s.cap), Uint8Array.of(name.length), name);
  }
  parts.push(u16(lifetime));
  /* a continue adds its tail; a request without one ends at the lifetime (the length tells them apart) */
  if (cont !== undefined && cont !== null) parts.push(Uint8Array.of(1), u32(cont));
  return concat(parts);
}

/**
 * The agent side: a signed request. signer: {publicKey: 32 bytes,
 * sign(bytes) -> 64 bytes (sync or async)} - the agent service's own key.
 */
async function build({ signer, reason, scopes, lifetime, continueOf = null, nonce = randomBytes(16) }) {
  const msg = {
    type: TYPE, v: 1,
    agent: toHex(signer.publicKey),
    nonce: toHex(nonce),
    reason: String(reason),
    scopes: scopes.map((s) => ({ op: s.op, slot: s.slot, cap: s.cap, ...(s.identity ? { identity: String(s.identity) } : {}) })),
    lifetime,
    ...(continueOf !== null && continueOf !== undefined ? { continue: continueOf } : {}),
  };
  msg.signature = toHex(await signer.sign(body(msg)));
  return msg;
}

/* the signed bytes of a registration: proof the agent holds the key it registers */
function registerBody({ agent, nonce, name }) {
  const n = utf8ToBytes(String(name));
  if (n.length > 0xff) throw new RangeError('edge register: the name is too long');
  return concat([utf8ToBytes(REGISTER_TAG), fromHex(agent), fromHex(nonce), Uint8Array.of(n.length), n]);
}

/** The agent side: ask to be registered, under a name the person reads. */
async function buildRegister({ signer, name, nonce = randomBytes(16) }) {
  const msg = { type: REGISTER_TYPE, v: 1, agent: toHex(signer.publicKey), name: String(name), nonce: toHex(nonce) };
  msg.signature = toHex(await signer.sign(registerBody(msg)));
  return msg;
}

/** The app side: a registration signed by the key it names, and new. -> {ok} or {ok: false, reason} */
function verifyRegister(msg, { seen } = {}) {
  if (!msg || msg.type !== REGISTER_TYPE || msg.v !== 1 || !isHex(msg.agent, 32) || !isHex(msg.nonce, 16) || !isHex(msg.signature, 64)
    || typeof msg.name !== 'string' || !msg.name.trim() || utf8ToBytes(msg.name).length > 0xff) {
    return { ok: false, reason: 'malformed' };
  }
  let good = false;
  try {
    good = crypto.ed25519Verify(fromHex(msg.signature), registerBody(msg), fromHex(msg.agent));
  } catch { good = false; }
  if (!good) return { ok: false, reason: 'bad-signature' };
  if (seen && seen.has(msg.nonce.toLowerCase())) return { ok: false, reason: 'replayed' };
  return { ok: true };
}

/* an Ed25519 signer from a 32-byte secret - the agent service's key, for tests and the CLI */
function signerFromSecret(secret) {
  return { publicKey: ed25519.getPublicKey(secret), sign: (bytes) => ed25519.sign(bytes, secret) };
}

/*
 * R20 (okedge sync phase 2, P2a, Brad 2026-10-05): a place that keeps copies -
 * this PC's copy store first - asks to be added as a known peer:
 *
 *   { type: 'EDGE_PEER_ADD', v: 1, peer, name, nonce, signature }
 *
 * peer = its P-256 key, X || Y (hex, 64 bytes) - the KEY's list holds it, and a
 * sync only goes to places on that list. Signed by that key (ECDSA P-256 over
 * SHA-256 of the body), so nobody adds a key they do not hold - the place must
 * later sign receipts with it (R21). The phone shows the sheet; the person says
 * Yes and presses; the key links it (peer-add). Not tied to a registered agent:
 * the copy store is not the agent, and the agent cannot vouch for where copies go.
 */
const PEER_TYPE = 'EDGE_PEER_ADD';
const PEER_TAG = 'OKEDGE-PEER-ADD-v1';

function peerBody({ peer, nonce, name }) {
  const n = utf8ToBytes(String(name));
  if (n.length > 0xff) throw new RangeError('edge peer add: the name is too long');
  return concat([utf8ToBytes(PEER_TAG), fromHex(peer), fromHex(nonce), Uint8Array.of(n.length), n]);
}

/** The place's side: ask the phone to add it, under a name the person reads. signer: peerSignerFromSecret. */
async function buildPeerAdd({ signer, name, nonce = randomBytes(16) }) {
  const msg = { type: PEER_TYPE, v: 1, peer: toHex(signer.publicKey), name: String(name), nonce: toHex(nonce) };
  msg.signature = toHex(await signer.sign(peerBody(msg)));
  return msg;
}

/** The app's side: signed by the key it names, and new. -> {ok} or {ok: false, reason} */
function verifyPeerAdd(msg, { seen } = {}) {
  if (!msg || msg.type !== PEER_TYPE || msg.v !== 1 || !isHex(msg.peer, 64) || !isHex(msg.nonce, 16) || !isHex(msg.signature, 64)
    || typeof msg.name !== 'string' || !msg.name.trim() || utf8ToBytes(msg.name).length > 0xff) {
    return { ok: false, reason: 'malformed' };
  }
  let good = false;
  try {
    good = crypto.p256Verify(fromHex(msg.signature), peerBody(msg), Uint8Array.from([4, ...fromHex(msg.peer)]));
  } catch { good = false; }
  if (!good) return { ok: false, reason: 'bad-signature' };
  if (seen && seen.has(msg.nonce.toLowerCase())) return { ok: false, reason: 'replayed' };
  return { ok: true };
}

/* a P-256 signer from a 32-byte secret - the copy store's peer key; publicKey is X || Y, as the key lists it */
function peerSignerFromSecret(secret) {
  return {
    publicKey: p256.getPublicKey(secret, false).slice(1),
    sign: (bytes) => p256.sign(bytes, secret, { prehash: true }),
  };
}

/* the agent key as the sheet and the agent both print it, so the person can compare: first 8 . last 8 hex */
function fingerprint(agentHex) {
  const h = String(agentHex).toLowerCase();
  return `${h.slice(0, 8)}…${h.slice(-8)}`;
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
  /* who asks, first: an agent not registered is refused before anything else in its request is read */
  if (!msg || msg.type !== TYPE || !isHex(msg.agent, 32)) return { ok: false, reason: 'malformed' };
  const agent = msg.agent.toLowerCase();
  if (!(registered || []).some((k) => String(k).toLowerCase() === agent)) return { ok: false, reason: 'unregistered' };
  if (msg.v !== 1 || !isHex(msg.nonce, 16) || !isHex(msg.signature, 64)
    || typeof msg.reason !== 'string' || !Array.isArray(msg.scopes) || !Number.isInteger(msg.lifetime)
    || (msg.continue !== undefined && !isU32(msg.continue))) {
    return { ok: false, reason: 'malformed' };
  }
  let good = false;
  try {
    good = crypto.ed25519Verify(fromHex(msg.signature), body(msg), fromHex(msg.agent));
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
  return crypto.sha256(utf8ToBytes(String(reason)));
}

/**
 * What the approval sheet shows: the text, the names, the caps, the lifetime,
 * who asks. ownIdentities: the person's own identity names (ok-rn's list,
 * starting with ssh://bmatusiak@localhost) - a scope naming one is marked own,
 * and the sheet shows a red warning and asks a second confirm (Brad, 2026-10-03).
 */
function view(msg, { ownIdentities = [], covered = [] } = {}) {
  const own = new Set(ownIdentities.map((n) => String(n)));
  const scopes = msg.scopes.map((s) => ({ ...s, own: Boolean(s.identity && own.has(s.identity)) }));
  return {
    agent: msg.agent,
    reason: msg.reason,
    lifetime: msg.lifetime,
    uses: msg.scopes.reduce((n, s) => n + s.cap, 0),
    scopes,
    ownWarning: scopes.some((s) => s.own),
    continues: msg.continue === undefined ? null : msg.continue,
    /*
     * 4.7a: live budgets that already cover an identity (or slot) this request
     * names - "this agent already has N uses left on <identity> until <time>".
     * [{identity?, slot, usesLeft, endsAt?, grantId, sameAgent}], from the app.
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
  TYPE, REGISTER_TYPE, MAX_REQUEST_USES, MAX_LIFETIME_MINUTES, REFUSALS,
  body, build, signerFromSecret, verify, check, grantScopes, reasonHash, view, sameScopes,
  registerBody, buildRegister, verifyRegister, fingerprint,
  PEER_TYPE, peerBody, buildPeerAdd, verifyPeerAdd, peerSignerFromSecret,
};
