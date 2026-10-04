'use strict';

/**
 * Edge chain (spec L1): the 64-byte link, the welds, and verifying a run of
 * links against the key.
 *
 * THE CHAIN (firmware.md R2-R3). The key records every decision as a 64-byte
 * link and keeps only the HEAD:
 *
 *   head[-1] = SHA256("OKEDGE-GENESIS-v1" || device_id)
 *   head[n]  = SHA256("OKEDGE-LINK-v1"    || head[n-1] || link[n])
 *
 *   off size field
 *    0   4   seq (u32 LE, from 0)
 *    4   1   op (codes.OP)
 *    5   1   decision (codes.DECISION; for op = ticket, the ticket code)
 *    6   1   slot
 *    7   1   flags (codes.FLAG)
 *    8  32   subject
 *   40   4   grant_id (u32 LE); for op = ticket, ref_seq
 *   44   2   grant_step (u16 LE)
 *   46  18   reserved (the key writes zeros; they are hashed like any byte)
 *
 * WHO IS TRUSTED. Hosts keep the full chain; the key keeps the head and a
 * small ring. A host's copy (a "mirror") is UNTRUSTED: anyone with the phone
 * or the Worker can edit it. Only these are trusted, and only if the caller
 * got them from the key this session (spec B4):
 *   - the start: genesis(device_id), or a head the caller already verified;
 *   - `anchors`: (seq, head) pairs whose signature was checked (checkpoints);
 *   - `expectHead`: the key's live HEAD.
 * Trust spreads FORWARD by recomputing welds, and BACKWARD through the heads a
 * mirror stores beside each link (R5/R6 read each link with its head, so a copy
 * can be rebuilt from the key's head down): if weld(head[k-1], link[k]) equals a
 * trusted head[k], then head[k-1] is the real one too - forging it would need a
 * SHA-256 preimage. Everything trust cannot reach is a GAP (unverifiable,
 * amber), never "verified" - and never "tampered" either, unless a check that
 * could be made failed.
 */
const { OP, TAG } = require('./codes');
const { p256 } = require('../vendor/exports/@noble/curves/nist.js');
const { sha256 } = require('../vendor/exports/@noble/hashes/sha2.js');
const { concat } = require('../bytes');
const { H, ascii, u32le, bytes32, same } = require('./hash');

const LINK_BYTES = 64;

const REASONS = Object.freeze([
  'hash-mismatch', // a link does not weld to the head stored or anchored for it
  'seq-gap', // links the key still holds (>= ringFrom) are missing
  'seq-reorder', // seq not strictly rising: reordered, duplicated or replayed
  'head-mismatch', // the chain does not reach the key's live head
  'rollback', // the key's head is behind, or off, what this host saw before
  'device-mismatch', // the mirror was recorded for another key
]);

function encodeLink(f) {
  const b = new Uint8Array(LINK_BYTES);
  b.set(u32le(f.seq), 0);
  b[4] = f.op;
  b[5] = f.decision;
  b[6] = f.slot || 0;
  b[7] = f.flags || 0;
  b.set(bytes32(f.subject, 'subject'), 8);
  b.set(u32le(f.grantId || 0), 40);
  const step = f.grantStep || 0;
  if (!Number.isInteger(step) || step < 0 || step > 0xffff) throw new RangeError(`edge: grantStep not a u16: ${step}`);
  b[44] = step & 0xff;
  b[45] = step >>> 8;
  if (f.reserved) b.set(f.reserved.subarray(0, 18), 46);
  /* R3 (2026-10-03): byte 46 = which of the budget's scopes paid, 1-based, on a budget-spending link; 0 elsewhere */
  if (f.scope !== undefined) {
    if (!Number.isInteger(f.scope) || f.scope < 0 || f.scope > 0xff) throw new RangeError(`edge: scope not a byte: ${f.scope}`);
    b[46] = f.scope;
  }
  return b;
}

function decodeLink(b) {
  if (!(b instanceof Uint8Array) || b.length !== LINK_BYTES) throw new TypeError(`edge: a link is ${LINK_BYTES} bytes`);
  const u32 = (o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
  const isTicket = b[4] === OP.TICKET;
  return {
    seq: u32(0),
    op: b[4],
    decision: b[5],
    slot: b[6],
    flags: b[7],
    subject: b.slice(8, 40),
    grantId: u32(40),
    grantStep: b[44] | (b[45] << 8),
    /* the ticket reuses two fields (R16): its code and the seq it answers */
    ...(isTicket ? { code: b[5], refSeq: u32(40) } : {}),
    /* R3: the scope that paid (1-based) on a link that spends a budget; 0 on every other link and on links before R3 */
    scope: b[46],
    reservedZero: b.subarray(47).every((x) => x === 0),
  };
}

function genesis(deviceId) {
  if (!(deviceId instanceof Uint8Array) || deviceId.length === 0) throw new TypeError('edge: deviceId must be non-empty bytes');
  return H(TAG.GENESIS, deviceId);
}

/*
 * R28 continue (onlykey-edge firmware.md, decided 2026-10-04): a device moving to
 * its own chain - a pre-R28 key after the update, or a backup restored onto another
 * device - writes as its FIRST link op CONTINUE, at the next seq after the chain it
 * continues, welded onto its NEW genesis. Its subject commits to the chain it came
 * from and the debts it carries (oldest first):
 *   SHA256("OKEDGE-CONTINUE-v1" || old device_id || old seq u32 || old head || debt seqs u32...)
 * A host keeps the old copy (and the old checkpoint key) beside the new one and
 * checks this subject against it.
 */
function continueSubject({ oldDeviceId, oldSeq, oldHead, owedSeqs = [] }) {
  if (!(oldDeviceId instanceof Uint8Array) || oldDeviceId.length !== 16) throw new TypeError('edge: oldDeviceId must be 16 bytes');
  return H(TAG.CONTINUE, oldDeviceId, u32le(oldSeq), bytes32(oldHead, 'oldHead'), ...owedSeqs.map((s) => u32le(s)));
}

/*
 * Where a copy's chain starts: genesis at seq 0, or - when its first link is a
 * CONTINUE - genesis at that link's seq (R28). Everything before it belongs to the
 * chain it continued, not to this one.
 */
function chainStart(entries, deviceId) {
  const first = (entries || [])[0];
  if (first) {
    const d = decodeLink(first.link || first);
    if (d.op === OP.CONTINUE) return { fromSeq: d.seq, fromHead: genesis(deviceId) };
  }
  return { fromSeq: 0, fromHead: genesis(deviceId) };
}

function weld(head, link) {
  if (!(link instanceof Uint8Array) || link.length !== LINK_BYTES) throw new TypeError(`edge: a link is ${LINK_BYTES} bytes`);
  return H(TAG.LINK, bytes32(head, 'head'), link);
}

/** Heads for a run of links from a start head: [head[first], head[first+1], ...]. */
function heads(links, startHead) {
  const out = [];
  let h = startHead;
  for (const l of links) out.push((h = weld(h, l)));
  return out;
}

/* entries may be raw links or {link, head?}; head = the weld the mirror stored */
function normalise(entries) {
  return entries.map((e) => (e instanceof Uint8Array ? { link: e, head: null } : { link: e.link, head: e.head || null }));
}

/**
 * Verify a run of links (oldest first, as the mirror holds them).
 *
 * opts:
 *   deviceId        the key being verified (its genesis is the default start)
 *   mirrorDeviceId  the key the mirror says it belongs to -> device-mismatch
 *   fromSeq, fromHead  start somewhere other than genesis: fromHead = head[fromSeq-1]
 *   anchors         [{seq, head}] verified checkpoints: resume points after a gap
 *   expectHead      {seq, head} the key's live HEAD
 *   lastSeen        {seq, head} the head this host verified last session -> rollback
 *   ringFrom        lowest seq the key's ring still holds: missing links at or
 *                   above it are tampering (they could have been read), below it
 *                   they are a gap
 *
 * -> {ok, verifiedThrough, gaps: [{from, to}], failure?: {seq, reason}}
 *    verifiedThrough = the last seq of the unbroken verified run from the start
 *    (fromSeq - 1 when none); gaps = every unverifiable range up to the end.
 */
function verify(entries, opts = {}) {
  const fromSeq = opts.fromSeq || 0;
  const start = opts.fromHead || (opts.deviceId ? genesis(opts.deviceId) : null);
  if (!start) throw new TypeError('edge.verify: give deviceId or fromHead');
  const fail = (seq, reason) => ({ ok: false, verifiedThrough: fromSeq - 1, gaps: [], failure: { seq, reason } });

  if (opts.mirrorDeviceId && opts.deviceId && !same(opts.mirrorDeviceId, opts.deviceId)) {
    return fail(fromSeq, 'device-mismatch');
  }
  const exp = opts.expectHead || null;
  const last = opts.lastSeen || null;
  if (exp && last && exp.seq < last.seq) return fail(exp.seq, 'rollback');

  /* order first: the array order is what the mirror claims */
  const list = normalise(entries);
  const bySeq = new Map();
  let prev = fromSeq - 1;
  for (const e of list) {
    const seq = decodeLink(e.link).seq;
    if (seq <= prev) return fail(seq, 'seq-reorder');
    bySeq.set(seq, e);
    prev = seq;
  }
  const lastEntry = prev;
  if (exp && exp.seq < lastEntry) return fail(exp.seq + 1, 'rollback'); // the mirror is ahead of the key
  const end = exp ? exp.seq : lastEntry;

  /* trusted heads by seq; `source` remembers which kind, to name a failure */
  const trusted = new Map([[fromSeq - 1, { head: start, source: 'start' }]]);
  for (const a of opts.anchors || []) trusted.set(a.seq, { head: bytes32(a.head, 'anchor head'), source: 'anchor' });
  if (exp) {
    const had = trusted.get(exp.seq);
    if (had && !same(had.head, exp.head)) return fail(exp.seq, 'head-mismatch');
    trusted.set(exp.seq, { head: bytes32(exp.head, 'expectHead.head'), source: 'key' });
  }

  const verified = new Set();
  const failures = [];
  const mismatchAt = (seq) => failures.push({ seq, reason: trusted.get(seq)?.source === 'key' ? 'head-mismatch' : 'hash-mismatch' });

  /* forward: recompute from every trusted head */
  for (let seq = fromSeq; seq <= end; seq++) {
    const e = bySeq.get(seq);
    const before = trusted.get(seq - 1);
    if (!e || !before) continue;
    const h = weld(before.head, e.link);
    const known = trusted.get(seq);
    if (known && !same(known.head, h)) { mismatchAt(seq); continue; }
    if (e.head && !same(e.head, h)) { failures.push({ seq, reason: 'hash-mismatch' }); continue; }
    if (!known) trusted.set(seq, { head: h, source: 'computed' });
    verified.add(seq);
  }
  /* backward: from each trusted head, down through the heads the mirror stored */
  for (let seq = end; seq > fromSeq; seq--) {
    const t = trusted.get(seq);
    const e = bySeq.get(seq);
    const below = bySeq.get(seq - 1);
    if (!t || !e || verified.has(seq) || !below || !below.head || trusted.has(seq - 1)) continue;
    if (!same(weld(below.head, e.link), t.head)) { mismatchAt(seq); continue; }
    trusted.set(seq - 1, { head: below.head, source: 'computed' });
    verified.add(seq);
  }

  /* missing links the key could still have given us are not a gap: they were removed */
  if (opts.ringFrom !== undefined) {
    for (let seq = Math.max(fromSeq, opts.ringFrom); seq <= end; seq++) {
      if (!bySeq.has(seq)) { failures.push({ seq, reason: 'seq-gap' }); break; }
    }
  }
  if (last && trusted.has(last.seq) && !same(trusted.get(last.seq).head, last.head)) {
    failures.push({ seq: last.seq, reason: 'rollback' });
  }

  failures.sort((a, b) => a.seq - b.seq);
  const failure = failures[0];
  const stop = failure ? failure.seq : end + 1; // nothing at or past a failure counts as verified
  let through = fromSeq - 1;
  while (through + 1 < stop && verified.has(through + 1)) through++;
  const gaps = [];
  for (let seq = fromSeq; seq <= end; seq++) {
    if (verified.has(seq) && seq < stop) continue;
    const g = gaps[gaps.length - 1];
    if (g && g.to === seq - 1) g.to = seq;
    else gaps.push({ from: seq, to: seq });
  }
  return failure ? { ok: false, verifiedThrough: through, gaps, failure } : { ok: true, verifiedThrough: through, gaps };
}

/*
 * THE KEY'S ONE SIGNATURE: a checkpoint over (seq, head) (firmware R7), made
 * with the Edge key - P-256, derived from the key's own secret and never
 * reachable by a generic sign request. A budget's opening is answered with a
 * checkpoint over its grant-create link (grants.verifyBudgetOpening).
 *
 *   digest = SHA256("OKEDGE-CKPT-v1" || device_id || seq (u32 LE) || head)
 *
 * CHOSEN: raw P-256 over the 32-byte digest, signature r||s, S not normalised
 * (the key does not normalise S - see crypto/pgp-cert.js verifyDigest).
 */

/* the key gives P-256 public keys as X||Y (64 bytes); SEC1 04||X||Y is accepted too */
function sec1(publicKey) {
  if (!(publicKey instanceof Uint8Array)) throw new TypeError('edge: a public key is bytes');
  return publicKey.length === 64 ? Uint8Array.from([4, ...publicKey]) : publicKey;
}

/** device_id = SHA256("OKEDGE-DEVICE-v1" || public key X||Y)[0..16] - the key derives it the same way. */
function deviceIdOf(publicKey) {
  const xy = publicKey.length === 65 ? publicKey.subarray(1) : publicKey;
  if (xy.length !== 64) throw new TypeError('edge: the Edge public key is 64 bytes X||Y');
  return H(TAG.DEVICE, xy).slice(0, 16);
}

function checkpointMessage({ deviceId, seq, head }) {
  return concat([ascii(TAG.CHECKPOINT), deviceId, u32le(seq), bytes32(head, 'head')]);
}

function checkpointDigest(fields) {
  return sha256(checkpointMessage(fields));
}

/** {deviceId, seq, head}, the key's 64-byte signature, the Edge public key -> boolean */
function verifyCheckpoint(fields, signature, publicKey) {
  try {
    return p256.verify(Uint8Array.from(signature), checkpointDigest(fields), sec1(publicKey), { prehash: false, lowS: false });
  } catch {
    return false;
  }
}

/** What the key does - for the fake key and tests; a host never holds the Edge key. */
function signCheckpoint(fields, secretKey) {
  return p256.sign(checkpointDigest(fields), secretKey, { prehash: false, lowS: false });
}

module.exports = {
  LINK_BYTES, REASONS, encodeLink, decodeLink, genesis, continueSubject, chainStart, weld, heads, verify,
  deviceIdOf, checkpointMessage, checkpointDigest, verifyCheckpoint, signCheckpoint,
};
