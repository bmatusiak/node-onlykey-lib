'use strict';

/**
 * Edge budgets ("grants", spec L2): checking a self-press.
 *
 * THE CONSTRUCTION (firmware.md R11-R13; bmatusiak/provable). When a person
 * clasps a budget of n uses (n = the sum of its scopes' caps, <= 255), the key
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
const { sha256 } = require('../vendor/exports/@noble/hashes/sha2.js');
const { TAG, OP } = require('./codes');
const chain = require('./chain');
const { H, hmacSha256, bytes32, same, u8 } = require('./hash');

/* owner, 2026-10-02: "1 budget max chain is 255" (the spec said 1024) */
const MAX_USES = 255;

function hashTimes(v, times) {
  let x = v;
  for (let k = 0; k < times; k++) x = sha256(x);
  return x;
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
    /* bounded (<= 255 hashes): tell a mislabelled step from a foreign value */
    let x = value;
    for (let k = 1; k <= uses; k++) {
      x = sha256(x);
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


function grantSubject({ scopes, reasonHash, genesis }) {
  return H(TAG.GRANT, encodeScopes(scopes), bytes32(reasonHash, 'reasonHash'), bytes32(genesis, 'genesis'));
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
function verifyBudgetOpening({ deviceId, publicKey, link, prevHead, head, signature, scopes, reasonHash, genesis, uses }) {
  if (scopes.reduce((n, s) => n + s.cap, 0) !== uses) return { ok: false, reason: 'uses-mismatch' };
  const f = chain.decodeLink(link);
  if (f.op !== OP.GRANT_CREATE) return { ok: false, reason: 'not-a-grant-create' };
  if (!same(f.subject, grantSubject({ scopes, reasonHash, genesis }))) return { ok: false, reason: 'subject-mismatch' };
  if (!same(chain.weld(prevHead, link), head)) return { ok: false, reason: 'weld-mismatch' };
  if (!chain.verifyCheckpoint({ deviceId, seq: f.seq, head }, signature, publicKey)) return { ok: false, reason: 'bad-signature' };
  return { ok: true, grantId: f.grantId, seq: f.seq };
}

module.exports = {
  MAX_USES, grantGenesis, reveal, checkSelfPress, checkSpends,
  encodeScopes, grantSubject, verifyBudgetOpening,
};
