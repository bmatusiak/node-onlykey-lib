'use strict';

const { utf8ToBytes } = require('../../src/bytes');

/**
 * Edge budgets ("grants", spec L2): checking a self-press.
 *
 * THE CONSTRUCTION (firmware.md R11-R13; bmatusiak/provable). When a person
 * clasps a budget of n uses (n = the sum of its scopes' caps, <= 1024), the key
 * draws a secret seed and publishes only
 *
 *   G = H^n(seed)            the grant genesis, H = SHA-256
 *
 * Use i (1..n) reveals v_i = H^(n-i)(seed). Anyone can check H^i(v_i) == G,
 * and nobody without the seed can make a v_{i+1} the key has not revealed (it
 * would be a SHA-256 preimage of v_i). So each self-press proves it was spent
 * from THIS budget at THIS step. The key also returns
 *
 *   mac = HMAC-SHA256(key = v_i, msg = subject)
 *
 * which ties the revealed step to what was approved (the link's subject).
 * CHOSEN: i counts from 1, so use 1 reveals H^(n-1)(seed) and use n the seed.
 */
const crypto = require('../../src/crypto/provider');
const { TAG, OP } = require('./codes');
const chain = require('./chain');
const { H, hmacSha256, bytes32, same, u8 } = require('./hash');

/* R15b: a lifetime of 0 means the key's default, 12 hours (Brad, 2026-10-02) */
const DEFAULT_LIFETIME_MINUTES = 12 * 60;

function u16le(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff) throw new RangeError(`edge: lifetime not a u16 of minutes: ${n}`);
  return Uint8Array.of(n & 0xff, n >>> 8);
}

/*
 * One budget's chain: at most 1024 uses (firmware.md R11; Brad, 2026-10-02:
 * back from 255, "too few once the VM and the Pi are in the loop"). Caps stay
 * u16 per scope. The cost: up to 1,024 SHA-256 runs at the press (G) and per
 * reveal; RAM and flash are unchanged.
 */
const MAX_USES = 1024;

function hashTimes(v, times) {
  return crypto.sha256Repeat(v, times);
}

/** The value use `step` reveals, from the seed (for tests and fakes - a host never has the seed). */
function reveal(seed, uses, step) {
  checkCount(uses);
  if (!Number.isInteger(step) || step < 1 || step > uses) throw new RangeError(`edge: step ${step} outside 1..${uses}`);
  return hashTimes(bytes32(seed, 'seed'), uses - step);
}

function grantGenesis(seed, uses) {
  checkCount(uses);
  return hashTimes(bytes32(seed, 'seed'), uses);
}

function checkCount(uses) {
  if (!Number.isInteger(uses) || uses < 1 || uses > MAX_USES) throw new RangeError(`edge: a budget has 1..${MAX_USES} uses, not ${uses}`);
}

/**
 * Check one self-press: {genesis, uses, step, value, mac, subject}.
 * -> {ok: true} or {ok: false, reason}:
 *    past-cap      step beyond the budget's uses (or below 1)
 *    wrong-step    the value is from THIS budget, but at another step
 *    wrong-budget  the value is from no step of this budget
 *    mac-mismatch  the value is right, but the MAC is not over this subject
 */
function checkSelfPress({ genesis, uses, step, value, mac, subject }) {
  bytes32(genesis, 'genesis');
  bytes32(value, 'value');
  if (!Number.isInteger(uses) || uses < 1 || uses > MAX_USES || !Number.isInteger(step) || step < 1 || step > uses) {
    return { ok: false, reason: 'past-cap' };
  }
  if (!same(hashTimes(value, step), genesis)) {
    /* bounded (<= 1024 hashes): tell a mislabelled step from a foreign value */
    let x = value;
    for (let k = 1; k <= uses; k++) {
      x = crypto.sha256(x);
      if (k !== step && same(x, genesis)) return { ok: false, reason: 'wrong-step', actualStep: k };
    }
    return { ok: false, reason: 'wrong-budget' };
  }
  if (!same(hmacSha256(value, bytes32(subject, 'subject')), mac)) return { ok: false, reason: 'mac-mismatch' };
  return { ok: true };
}

/**
 * Check a budget's spends in the order the chain recorded them: each must pass
 * checkSelfPress, and the steps must run 1, 2, 3... (a repeated step is a
 * replayed reveal; a skipped one is a self-press missing from the chain).
 * -> {ok, spent, failure?: {index, step, reason}}  reasons: the four above,
 *    plus step-reused and step-skipped.
 */
function checkSpends(genesis, uses, spends) {
  for (let i = 0; i < spends.length; i++) {
    const s = spends[i];
    if (s.step <= i) return { ok: false, spent: i, failure: { index: i, step: s.step, reason: 'step-reused' } };
    if (s.step > i + 1) return { ok: false, spent: i, failure: { index: i, step: s.step, reason: 'step-skipped' } };
    const r = checkSelfPress({ genesis, uses, ...s });
    if (!r.ok) return { ok: false, spent: i, failure: { index: i, step: s.step, reason: r.reason } };
  }
  return { ok: true, spent: spends.length };
}

/*
 * EACH BUDGET IS ITS OWN PROVABLE CHAIN, OPENED BY A SIGNED PRESS (owner,
 * 2026-10-02: "like a provable blockchain - each budget has its own genesis,
 * each genesis gets started with the firmware button press by getting signed").
 *
 * The firmware is minimal (one signature, owner's "safe cuts"): the key's
 * grant-create link commits to G in its subject,
 *
 *   subject = SHA256("OKEDGE-GRANT-v1" || scopes || reason_hash || G)
 *
 * and the press is answered with a CHECKPOINT over that link (chain.js). So
 * the genesis is signed through the chain: the signature covers the head, the
 * head is the link welded onto the head before it, the link's subject covers
 * G. Anyone with the Edge public key can check a budget's opening on its own,
 * and every reveal then hashes back to G (checkSelfPress).
 *
 * Scopes are encoded as a count byte, then per scope op (u8), slot (u8), cap
 * (u16 LE).
 */
/*
 * R11a (2026-10-02, found when Brad's GitHub login signed on slot 201): the
 * agent sign codes 201-203 / 221-223 are shared by EVERY derived identity of
 * that curve - the 32-byte derive label picks which one signs. So a scope on
 * them must name one identity, or a budget for the agent's key would pay for,
 * and make owe, Brad's own logins. A scope carries it as `identity` (a name:
 * "ssh://agent@nitro16", "gpg://Agent <a@x>") - the app turns the name into
 * the label itself and never trusts a label hash handed to it - or as `label`
 * (the 32 bytes) where the caller already holds them.
 */
function isDerivedCode(slot) {
  return (slot >= 201 && slot <= 203) || (slot >= 221 && slot <= 223);
}

/* the derive label of an identity NAME, exactly as the agents hash it (protocol/agent.js identityHash) */
function identityLabel(name) {
  const { identityHash } = require('../../src/protocol/agent');
  const text = String(name);
  const gpg = /^gpg:\/\/(.+)$/.exec(text);
  if (gpg) return identityHash({ gpg: gpg[1] });
  const ssh = /^ssh:\/\/(?:([^@]+)@)?(.+)$/.exec(text);
  if (ssh) return identityHash({ ssh: { user: ssh[1] || undefined, host: ssh[2] } });
  throw new Error(`edge: an identity is "ssh://user@host" or "gpg://user id", not "${text}"`);
}

/* a derived-code scope's 32-byte label; null for a stored slot (there the slot is the key) */
function scopeLabel(s) {
  if (!isDerivedCode(s.slot)) return null;
  if (s.label instanceof Uint8Array && s.label.length === 32) return s.label;
  if (typeof s.identity === 'string' && s.identity) return identityLabel(s.identity);
  throw new RangeError(`edge: a scope on derived code ${s.slot} must name its identity (R11a) - give it identity: "ssh://..." or "gpg://..."`);
}

function encodeScopes(scopes) {
  if (!Array.isArray(scopes) || scopes.length < 1 || scopes.length > 4) throw new RangeError('edge: a budget has 1 to 4 scopes');
  const out = new Uint8Array(1 + 4 * scopes.length);
  out[0] = scopes.length;
  scopes.forEach((s, i) => {
    out.set(u8(s.op), 1 + 4 * i);
    out.set(u8(s.slot), 2 + 4 * i);
    if (!Number.isInteger(s.cap) || s.cap < 1 || s.cap > MAX_USES) throw new RangeError(`edge: scope cap ${s.cap}`);
    out[3 + 4 * i] = s.cap & 0xff;
    out[4 + 4 * i] = s.cap >>> 8;
  });
  return out;
}


/*
 * R12 + R15b (2026-10-02): the subject ends with the lifetime the person
 * approved (u16 LE minutes, 0 = the key's default), so the checkpoint over the
 * grant-create link signs the genesis AND how long the budget may live.
 */
function grantSubject({ scopes, reasonHash, genesis, lifetime = 0 }) {
  /* R11a: then the FULL labels of derived-code scopes, in scope order - the identities the person approved */
  const labels = scopes.map(scopeLabel).filter(Boolean);
  return H(TAG.GRANT, encodeScopes(scopes), bytes32(reasonHash, 'reasonHash'), bytes32(genesis, 'genesis'), u16le(lifetime), ...labels);
}

/*
 * R13a (2026-10-02): TX start {token, intent} starts ONE self-press for ONE request:
 *   token = SHA256("OKEDGE-TX-v1" || head || subject || intent)
 * subject = SHA-256 of exactly the bytes the agent will submit - the subject
 * the link records. The key recomputes it from ITS head and the request it
 * gets; anything else (a stale head, another program's request) uses the TX start
 * up and needs a press.
 */
/*
 * The subject of a sign/decrypt: SHA-256 of EXACTLY the bytes the firmware
 * primes - the reassembled payload it hands okcore_prime_user_confirmation,
 * which the Edge plugin hashes into the link (pend.subject). For a chunked
 * request that is every chunk joined, without the framing. What a host signs
 * or decrypts must be these bytes and no others, or the TX start token will not
 * match and the key asks for a press.
 */
function requestSubject(bytes) {
  if (!(bytes instanceof Uint8Array) || !bytes.length) throw new TypeError('edge: requestSubject needs the request bytes');
  return crypto.sha256(bytes);
}

/*
 * R13a + R13b, ONE formula (the TX start rename, 2026-10-07):
 *   token = SHA256("OKEDGE-TX-v1" || head || subject || intent)
 * intent = the 16 bytes intentOf() makes, or 16 zero bytes when the use names
 * none - the key then writes no intent into the link. The old split (ARM-v1
 * without an intent, -v2 with one) is gone.
 */
const NO_INTENT = new Uint8Array(16);
function txToken({ head, subject, intent = null }) {
  if (intent && (!(intent instanceof Uint8Array) || intent.length !== 16)) throw new TypeError('edge: intent must be 16 bytes (intentOf)');
  return H(TAG.TX, bytes32(head, 'head'), bytes32(subject, 'subject'), intent || NO_INTENT);
}

/** R13b: what a use is for, as the 16 bytes a self-press link carries in 47-62 */
function intentOf(text) {
  if (typeof text !== 'string' || !text.length) throw new TypeError('edge: an intent is non-empty text');
  return H(TAG.INTENT, utf8ToBytes(text)).slice(0, 16); /* the text as UTF-8 */
}

/**
 * Check a budget's opening as one standalone proof:
 *   {deviceId, publicKey, link (its grant-create link), prevHead (the head
 *    before it), head + signature (the checkpoint the press answered with),
 *    scopes, reasonHash, genesis, uses}
 * -> {ok: true, grantId, seq} or {ok: false, reason}:
 *   uses-mismatch      the scopes' caps do not add up to uses
 *   not-a-grant-create the link is not a grant-create
 *   subject-mismatch   the link does not commit to these scopes, reason and G
 *   weld-mismatch      the signed head is not this link welded onto prevHead
 *   bad-signature      the checkpoint is not the Edge key's over (seq, head)
 * prevHead is not trusted: a wrong one cannot weld to the signed head.
 */
function verifyBudgetOpening({ deviceId, publicKey, link, prevHead, head, signature, scopes, reasonHash, genesis, uses, lifetime = 0 }) {
  if (scopes.reduce((n, s) => n + s.cap, 0) !== uses) return { ok: false, reason: 'uses-mismatch' };
  const f = chain.decodeLink(link);
  if (f.op !== OP.GRANT_CREATE) return { ok: false, reason: 'not-a-grant-create' };
  if (!same(f.subject, grantSubject({ scopes, reasonHash, genesis, lifetime }))) return { ok: false, reason: 'subject-mismatch' };
  if (!same(chain.weld(prevHead, link), head)) return { ok: false, reason: 'weld-mismatch' };
  if (!chain.verifyCheckpoint({ deviceId, seq: f.seq, head }, signature, publicKey)) return { ok: false, reason: 'bad-signature' };
  return { ok: true, grantId: f.grantId, seq: f.seq };
}

/*
 * AGENT_ADD's subject (mcp-service.md 4.7a): SHA256("OKEDGE-AGENT-v1" ||
 * the agent's Ed25519 key). The key links the registration; the app keeps the
 * list, and a copy shows when each agent was added with a press.
 */
function agentSubject(agentKey) {
  return H('OKEDGE-AGENT-v1', bytes32(agentKey, 'agentKey'));
}

/*
 * No peer, sibling or anchor subjects since 2026-10-08: pairing and sync are the app's
 * (Brad: "pairing and sync is all app stuff, not firmware"), so the key links none of them.
 */

/*
 * THE OWNER STATEMENT (Brad, 2026-10-08: "if it has the private ecc key to sign the block,
 * then i want the log"; a device names its own fingerprint with a NAMETAG). Each key signs,
 * with an OWNER key derived from its secret with no salt - the same on every device made
 * from the same backup - a statement about itself: its device id, its checkpoint key, its
 * seq and the hash of its nametag (okplugin_edge.cpp statement()). Any device of yours
 * checks another's statement with ITS OWN owner public key: it verifies only if the same
 * OnlyKey secret made it. No press, no link.
 */
const NAMETAG_MAX = 64; /* characters, trimmed */

/** A nametag as the person typed it -> its hash, the 32 bytes the key signs. Throws on an empty or too long one. */
function nametagHash(nametag) {
  const t = String(nametag ?? '').trim();
  if (!t) throw new TypeError('edge: a nametag needs at least one character');
  if ([...t].length > NAMETAG_MAX) throw new RangeError(`edge: a nametag is at most ${NAMETAG_MAX} characters`);
  return H('OKEDGE-NAMETAG-v1', utf8ToBytes(t));
}

/** SHA256("OKEDGE-STATEMENT-v1" || device id 16 || checkpoint pubkey X||Y 64 || seq u32 LE || nametag hash 32) - what the owner key signs. */
function statementDigest({ deviceId, publicKey, seq, nametagHash: nh }) {
  const id = Uint8Array.from(deviceId);
  const pub = Uint8Array.from(publicKey);
  const tag = Uint8Array.from(nh);
  if (id.length !== 16 || pub.length !== 64 || tag.length !== 32 || !Number.isInteger(seq) || seq < 0 || seq > 0xffffffff) {
    throw new TypeError('edge: a statement is the device id (16), the checkpoint key X||Y (64), a u32 seq and a nametag hash (32)');
  }
  const s4 = Uint8Array.of(seq & 0xff, (seq >>> 8) & 0xff, (seq >>> 16) & 0xff, (seq >>> 24) & 0xff);
  return H('OKEDGE-STATEMENT-v1', id, pub, s4, tag);
}

/**
 * Is this statement signed by MY owner key, and does it name the key it carries?
 * statement: {deviceId, publicKey, seq, nametag (text), signature}; ownerKey: this device's
 * own owner public key (X||Y). -> boolean (false on anything malformed)
 */
function verifyStatement(statement, ownerKey) {
  try {
    const { deviceId, publicKey, seq, nametag, signature } = statement || {};
    if (!same(chain.deviceIdOf(Uint8Array.from(publicKey)), Uint8Array.from(deviceId))) return false; /* the id is the key's */
    /* seq null = the key had no link yet: it signed 0xFFFFFFFF */
    const digest = statementDigest({ deviceId, publicKey, seq: seq === null ? 0xffffffff : seq, nametagHash: nametagHash(nametag) });
    const owner = Uint8Array.from(ownerKey);
    return crypto.p256VerifyDigest(Uint8Array.from(signature), digest, owner.length === 64 ? Uint8Array.from([4, ...owner]) : owner, { lowS: false });
  } catch {
    return false;
  }
}

module.exports = {
  agentSubject, NAMETAG_MAX, nametagHash, statementDigest, verifyStatement,
  MAX_USES, grantGenesis, reveal, checkSelfPress, checkSpends,
  encodeScopes, grantSubject, requestSubject, txToken, intentOf, verifyBudgetOpening, DEFAULT_LIFETIME_MINUTES,
  isDerivedCode, identityLabel, scopeLabel,
};
