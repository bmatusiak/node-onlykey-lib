'use strict';

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
const { sha256 } = require('../vendor/exports/@noble/hashes/sha2.js');
const { p256 } = require('../vendor/exports/@noble/curves/nist.js');
const { TAG } = require('./codes');
const { hmacSha256, bytes32, same, u32le, u8, ascii } = require('./hash');
const { concat } = require('../bytes');

const MAX_USES = 1024;

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
    /* bounded (<= 1024 hashes): tell a mislabelled step from a foreign value */
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
 * EACH BUDGET IS ITS OWN PROVABLE CHAIN, STARTED BY A SIGNED PRESS (owner,
 * 2026-10-02: "like a provable blockchain - each budget has its own genesis,
 * each genesis gets started with the firmware button press by getting signed").
 *
 * When the person presses to approve a budget, the key signs its genesis G with
 * the Edge signing key (firmware.md R7: derived under `okedge-log`, never the
 * attestation key). Anyone with that public key can then check a budget on its
 * own - the signature proves a human press on THIS key opened it, and every
 * reveal hashes back to G (checkSelfPress) - without the rest of the history.
 * The signed digest also commits to the device chain's head at the press, so
 * budgets are ordered like blocks and none can be dropped or moved.
 *
 * CHOSEN: P-256 ECDSA (the receipts' curve, R21) over the 32-byte digest as-is,
 * signature r||s (64 bytes), S not normalised (the key does not normalise S -
 * see crypto/pgp-cert.js verifyDigest). Scopes are encoded as a count byte, then
 * per scope op (u8), slot (u8), cap (u16 LE).
 *
 *   digest = SHA256("OKEDGE-BUDGET-v1" || device_id || grant_id (u32 LE)
 *                   || G || uses (u16 LE) || scopes || reason_hash
 *                   || chain_seq (u32 LE) || chain_head)
 *
 * chain_seq = the seq of the budget's own grant-create link; chain_head = the
 * device chain's head just BEFORE it (head[chain_seq - 1], the device genesis
 * for seq 0) - the block this budget is built on.
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

/** The bytes the digest is taken over (what an ECDSA-SHA256 signer that hashes for itself would sign). */
function budgetGenesisMessage({ deviceId, grantId, genesis, uses, scopes, reasonHash, chainSeq, chainHead }) {
  checkCount(uses);
  return concat([ascii(TAG.BUDGET), deviceId, u32le(grantId), bytes32(genesis, 'genesis'), new Uint8Array([uses & 0xff, uses >>> 8]),
    encodeScopes(scopes), bytes32(reasonHash, 'reasonHash'), u32le(chainSeq), bytes32(chainHead, 'chainHead')]);
}

function budgetGenesisDigest(fields) {
  return sha256(budgetGenesisMessage(fields));
}

/* the key returns P-256 public keys as X||Y (64 bytes); accept the SEC1 04||X||Y form too */
function sec1(publicKey) {
  if (publicKey.length === 64) return Uint8Array.from([4, ...publicKey]);
  return publicKey;
}

/**
 * Check a budget's signed genesis: {deviceId, grantId, genesis, uses, scopes,
 * reasonHash, chainSeq, chainHead}, the key's 64-byte signature, and the Edge
 * public key. -> {ok: true} or {ok: false, reason}:
 *   uses-mismatch  the scopes' caps do not add up to the budget's uses
 *   bad-signature  not signed by this key over exactly these fields
 */
function verifyBudgetGenesis(fields, signature, publicKey) {
  const total = fields.scopes.reduce((n, s) => n + s.cap, 0);
  if (total !== fields.uses) return { ok: false, reason: 'uses-mismatch' };
  let ok = false;
  try {
    ok = p256.verify(Uint8Array.from(signature), budgetGenesisDigest(fields), sec1(publicKey), { prehash: false, lowS: false });
  } catch {
    ok = false;
  }
  return ok ? { ok: true } : { ok: false, reason: 'bad-signature' };
}

/** What the key does at the press - for the fake key and tests; a host never holds the Edge signing key. */
function signBudgetGenesis(fields, secretKey) {
  return p256.sign(budgetGenesisDigest(fields), secretKey, { prehash: false, lowS: false });
}

module.exports = {
  MAX_USES, grantGenesis, reveal, checkSelfPress, checkSpends,
  encodeScopes, budgetGenesisMessage, budgetGenesisDigest, verifyBudgetGenesis, signBudgetGenesis,
};
