'use strict';

/**
 * The in-person key swap between two phones, quantum-safe (GUEST-BOOK-SPEC.md; Brad,
 * 2026-10-12: "i want to be able to trade quauntum safe betwen users", trusted "through X-Wing
 * only, no new firmware").
 *
 * WHO IS WHO. The SHOWER shows the invite QR (invite.js); the SCANNER scans it and connects.
 * Each phone's contact identity is the derived X-Wing key under "okrn-contact:v1" on ITS
 * OnlyKey: the public key is read without a press, and the only private operation - opening
 * a seal sent to it - happens on the OnlyKey (okcrypto.deviceAge.decapsulate, one press). This
 * module never sees a private key; `identity.decapsulate(ct)` is the device.
 *
 *   scanner                                   shower
 *   OPEN   {nB}                         ->
 *                                       <-    KEYS    {pubA, nA}
 *     pubA must hash to the QR's id: a stand-in shower is refused here.
 *   REVEAL {pubB, ctA, MAC_t}           ->    ctA seals ssA to pubA. MAC_t proves the scanner
 *                                             holds the QR's token - checked BEFORE the
 *                                             shower's OnlyKey is asked to press.
 *                                             ssA = decapsulate(ctA)   [shower's press]
 *                                       <-    DONE    {ctB, MAC_K(a)}
 *     ssB = decapsulate(ctB)   [scanner's press]
 *   CONFIRM {MAC_K(b)}                  ->
 *
 *   K = HKDF(ssA || ssB, transcript), transcript = H(id, token, pubA, pubB, nA, nB, ctA, ctB)
 *
 * WHY THIS IS ENOUGH. Each side derives K only if the other side's OnlyKey opened its seal -
 * X-Wing never fails on the wrong key, it answers a different secret, so a pretender ends
 * with a different K and the MAC tells. The shower's key is pinned by the QR (id); the
 * scanner's by being in front of it (token), which is what "verified, in person" means. No
 * code to compare: the QR, seen with one's own eyes, is that check.
 *
 * THEN THE CARDS: one sealed frame each way (btpair's AES-256-GCM seal/open, counters that only
 * go up) carrying the public keys each person picked. Public only, both ways: a card with a
 * private key in it is refused when sealed and when opened.
 *
 * Its own labels ("okrn-contact/v1/..."), so nothing here can be mistaken for btpair's
 * computer pairing, whose message shapes it borrows.
 */

const { ml_kem768_x25519: xwing } = require('../../src/vendor/exports/@noble/post-quantum/hybrid.js');
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { hmac } = require('../../src/vendor/exports/@noble/hashes/hmac.js');
const { hkdf } = require('../../src/vendor/exports/@noble/hashes/hkdf.js');
const btpair = require('../../src/btpair');
const { idOf, tokensAt } = require('./invite');
const { FORMATS, MAX_TEXT, refusePublicOnly } = require('./formats');

const VERSION = 1;
const PUB = 1216;
const CT = 1120;
const N = 32;
const T = Object.freeze({ OPEN: 0x31, KEYS: 0x32, REVEAL: 0x33, DONE: 0x34, CONFIRM: 0x35, CARD: 0x36, BYE: 0x37 });
/* why a phone ends the link: it has sent and received ("done"), or it closed without giving keys ("leaving") */
const BYE_REASONS = ['done', 'leaving'];
const MAX_KEYS = 16;
const NAME_MAX = 64;
const MAX_CARD = 60000;

const te = new TextEncoder();
const td = new TextDecoder();
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
const bytesOf = (p) => (typeof p === 'string' ? te.encode(p) : p);
const H = (...parts) => sha256(concat(...parts.map(bytesOf)));
const mac = (key, ...parts) => hmac(sha256, key, concat(...parts.map(bytesOf)));
const header = (t) => Uint8Array.of(t, VERSION);
function same(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
function fail(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}
/** The message body after [type][version], of exactly `len` bytes when given; else throws. */
function body(msg, type, len, what) {
  if (!(msg instanceof Uint8Array) || msg.length < 2 || msg[0] !== type || msg[1] !== VERSION) {
    throw fail('ESWAP_MSG', `not the ${what} the swap expects`);
  }
  if (len !== undefined && msg.length !== 2 + len) throw fail('ESWAP_MSG', `the ${what} has the wrong length`);
  return msg.slice(2);
}
const transcriptOf = (s) => H('okrn-contact/v1/transcript', s.invite.id, s.invite.token, s.pubA, s.pubB, s.nA, s.nB, s.ctA, s.ctB);
const keyOf = (ssA, ssB, transcript) => hkdf(sha256, concat(ssA, ssB), transcript, te.encode('okrn-contact/v1/key'), N);
function sessionOf(K, transcript, role) {
  const k = hkdf(sha256, K, transcript, te.encode('okrn-contact/v1/session'), 2 * N);
  const a2b = k.slice(0, N);
  const b2a = k.slice(N);
  return role === 'shower'
    ? { send: a2b, recv: b2a, sendCtr: 0, recvCtr: -1, dirSend: 1, dirRecv: 0 }
    : { send: b2a, recv: a2b, sendCtr: 0, recvCtr: -1, dirSend: 0, dirRecv: 1 };
}
function checkIdentity(identity) {
  if (!identity || !(identity.publicKey instanceof Uint8Array) || identity.publicKey.length !== PUB) {
    throw new Error('a swap needs this phone\'s 1216-byte X-Wing contact key');
  }
  if (typeof identity.decapsulate !== 'function') throw new Error('a swap needs the OnlyKey\'s decapsulate');
}
async function opened(identity, ct) {
  const ss = Uint8Array.from(await identity.decapsulate(ct));
  if (ss.length !== N) throw fail('ESWAP_DEVICE', `the OnlyKey answered ${ss.length} bytes, not a 32-byte secret`);
  return ss;
}

/* ------------------------------------------------------------ the shower (shows the QR) */

/** @param {{identity: {publicKey, decapsulate}, invite: {id, token}, randomBytes}} p */
function showerStart({ identity, invite, randomBytes }) {
  checkIdentity(identity);
  if (!same(idOf(identity.publicKey), invite.id)) throw new Error('this invite was made for another contact key');
  return { role: 'shower', identity, invite, randomBytes, step: 'open' };
}

/** OPEN -> KEYS. */
function showerOnOpen(state, msg) {
  if (state.step !== 'open') throw fail('ESWAP_STEP', 'the swap already started');
  const nB = body(msg, T.OPEN, N, 'opening');
  const nA = state.randomBytes(N);
  return { state: { ...state, nA, nB, pubA: state.identity.publicKey, step: 'reveal' }, msg: concat(header(T.KEYS), state.identity.publicKey, nA) };
}

/**
 * REVEAL -> DONE. The token is checked first; only then is the OnlyKey asked to open the
 * scanner's seal (the press). Async: that is the device.
 */
async function showerOnReveal(state, msg, now = Date.now()) {
  if (state.step !== 'reveal') throw fail('ESWAP_STEP', 'not waiting for the scanner\'s keys');
  const b = body(msg, T.REVEAL, PUB + CT + N, 'scanner\'s keys');
  const pubB = b.slice(0, PUB);
  const ctA = b.slice(PUB, PUB + CT);
  const proof = b.slice(PUB + CT);
  /* the token the scanner proves: this window's or the previous one's on a rotating QR (invite.js) */
  const token = tokensAt(state.invite, now).find((t) => same(proof, mac(t, 'okrn-contact/v1/reveal', state.nA, state.nB, pubB, ctA)));
  if (!token) {
    throw fail('ESWAP_TOKEN', 'the other phone does not hold this QR\'s current token - it did not scan it, or scanned it more than a minute ago');
  }
  const ssA = await opened(state.identity, ctA);
  const { cipherText: ctB, sharedSecret: ssB } = xwing.encapsulate(pubB);
  const s = { ...state, invite: { ...state.invite, token }, pubB, ctA, ctB };
  const transcript = transcriptOf(s);
  const K = keyOf(ssA, ssB, transcript);
  return { state: { ...s, K, transcript, step: 'confirm' }, msg: concat(header(T.DONE), ctB, mac(K, 'okrn-contact/v1/a-confirm')) };
}

/** CONFIRM -> the session, and the scanner's contact key. */
function showerOnConfirm(state, msg) {
  if (state.step !== 'confirm') throw fail('ESWAP_STEP', 'not waiting for the scanner\'s confirmation');
  const m = body(msg, T.CONFIRM, N, 'confirmation');
  if (!same(m, mac(state.K, 'okrn-contact/v1/b-confirm'))) {
    throw fail('ESWAP_CONFIRM', 'the other phone\'s OnlyKey did not open its seal - not the key it showed');
  }
  return { session: sessionOf(state.K, state.transcript, 'shower'), peer: { publicKey: state.pubB, id: idOf(state.pubB) } };
}

/* ------------------------------------------------------------ the scanner (scans the QR) */

/** @param {{identity: {publicKey, decapsulate}, invite: {id, token}, randomBytes}} p -> {state, msg: OPEN} */
function scannerStart({ identity, invite, randomBytes }) {
  checkIdentity(identity);
  const nB = randomBytes(N);
  return { state: { role: 'scanner', identity, invite, nB, pubB: identity.publicKey, step: 'keys' }, msg: concat(header(T.OPEN), nB) };
}

/** KEYS -> REVEAL. The shower's key must be the one the QR names. */
function scannerOnKeys(state, msg) {
  if (state.step !== 'keys') throw fail('ESWAP_STEP', 'not waiting for the other phone\'s key');
  const b = body(msg, T.KEYS, PUB + N, 'other phone\'s key');
  const pubA = b.slice(0, PUB);
  const nA = b.slice(PUB);
  if (!same(idOf(pubA), state.invite.id)) {
    throw fail('ESWAP_ID', 'the phone that answered is not the one whose QR you scanned');
  }
  const { cipherText: ctA, sharedSecret: ssA } = xwing.encapsulate(pubA);
  const proof = mac(state.invite.token, 'okrn-contact/v1/reveal', nA, state.nB, state.pubB, ctA);
  return { state: { ...state, pubA, nA, ctA, ssA, step: 'done' }, msg: concat(header(T.REVEAL), state.pubB, ctA, proof) };
}

/** DONE -> CONFIRM, the session and the shower's contact key. Async: this OnlyKey's press. */
async function scannerOnDone(state, msg) {
  if (state.step !== 'done') throw fail('ESWAP_STEP', 'not waiting for the other phone\'s answer');
  const b = body(msg, T.DONE, CT + N, 'other phone\'s answer');
  const ctB = b.slice(0, CT);
  const ssB = await opened(state.identity, ctB);
  const s = { ...state, ctB };
  const transcript = transcriptOf(s);
  const K = keyOf(state.ssA, ssB, transcript);
  if (!same(b.slice(CT), mac(K, 'okrn-contact/v1/a-confirm'))) {
    throw fail('ESWAP_CONFIRM', 'the other phone\'s OnlyKey did not open its seal - not the key its QR named');
  }
  return {
    msg: concat(header(T.CONFIRM), mac(K, 'okrn-contact/v1/b-confirm')),
    session: sessionOf(K, transcript, 'scanner'),
    peer: { publicKey: state.pubA, id: idOf(state.pubA) },
  };
}

/* ------------------------------------------------------------ the cards */

/** The keys a person picked: {name, keys: [{format, label, text}]}, public only and bounded. */
function checkCard(card) {
  if (!card || typeof card !== 'object' || !Array.isArray(card.keys)) throw fail('ESWAP_CARD', 'a card is {name, keys: [...]}');
  if (card.keys.length > MAX_KEYS) throw fail('ESWAP_CARD', `a card carries at most ${MAX_KEYS} keys`);
  /* a swap is a trade (Brad, 2026-10-13: "i dont want to trade without a key"): one key at least, both ways */
  if (!card.keys.length) throw fail('ESWAP_CARD', 'a swap card carries at least one key');
  const name = String(card.name || '').slice(0, NAME_MAX);
  const keys = card.keys.map((k) => {
    if (!k || !FORMATS.includes(k.format)) throw fail('ESWAP_CARD', `a key of an unknown format: ${k && k.format}`);
    const text = String(k.text || '');
    if (!text || text.length > MAX_TEXT) throw fail('ESWAP_CARD', 'a key on the card is empty or too long');
    refusePublicOnly(text);
    return { format: k.format, label: String(k.label || '').slice(0, NAME_MAX), text };
  });
  return { name, keys };
}

/** Seal this person's card for the other phone. */
function sealCard(session, card) {
  const plain = te.encode(JSON.stringify(checkCard(card)));
  /* the link frames a message with a 16-bit length (CTAP-BLE): a card must fit one */
  if (plain.length > MAX_CARD) throw fail('ESWAP_CARD', `the picked keys are ${plain.length} bytes; one swap carries at most ${MAX_CARD} - pick fewer`);
  return concat(header(T.CARD), btpair.seal(session, plain));
}

/** Open the other phone's card; refused if tampered, replayed, malformed or carrying a private key. */
function openCard(session, msg) {
  const frame = body(msg, T.CARD, undefined, 'card');
  let card;
  try { card = JSON.parse(td.decode(btpair.open(session, frame))); } catch (e) {
    if (e && e.code) throw e;
    throw fail('ESWAP_CARD', 'the card is not readable');
  }
  return checkCard(card);
}

/*
 * GOODBYE (Brad, 2026-10-12: "there is no reason to keep a link open if nothing will be send, it
 * should send a goodbye so the other phone knows"). Sealed like a card and on the same counter, so
 * a stranger cannot end someone else's swap and an old goodbye cannot be replayed. "done": this
 * phone has sent its card and received theirs - on an ordered link the other phone has both too.
 * "leaving": this phone closed the sheet without giving keys - nothing more will come.
 */
function sealBye(session, reason) {
  if (!BYE_REASONS.includes(reason)) throw new Error(`a goodbye is one of ${BYE_REASONS.join(', ')}`);
  return concat(header(T.BYE), btpair.seal(session, te.encode(JSON.stringify({ bye: reason }))));
}

/** The other phone's next sealed message: {kind: 'card', card} or {kind: 'bye', reason}. */
function openMessage(session, msg) {
  if (msg instanceof Uint8Array && msg[0] === T.CARD) return { kind: 'card', card: openCard(session, msg) };
  const frame = body(msg, T.BYE, undefined, 'goodbye');
  let m;
  try { m = JSON.parse(td.decode(btpair.open(session, frame))); } catch (e) {
    if (e && e.code) throw e;
    throw fail('ESWAP_MSG', 'the goodbye is not readable');
  }
  if (!m || !BYE_REASONS.includes(m.bye)) throw fail('ESWAP_MSG', 'a goodbye with no reason');
  return { kind: 'bye', reason: m.bye };
}

module.exports = {
  VERSION, T, BYE_REASONS,
  showerStart, showerOnOpen, showerOnReveal, showerOnConfirm,
  scannerStart, scannerOnKeys, scannerOnDone,
  sealCard, openCard, checkCard, sealBye, openMessage,
};
