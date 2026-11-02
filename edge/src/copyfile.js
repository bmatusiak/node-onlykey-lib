'use strict';

/**
 * A COMPUTER'S COPY OF ONE DEVICE'S EDGE CHAIN, as data (ok-edge stage 0c; PROPOSAL-one-gui.md).
 *
 * The copy used to live only in the CLI (edge/cli/copy.js), tied to one file per device on disk.
 * The bucket carries the same copy on every front end, so what a copy IS - its JSON, how two copies
 * of one device merge, the blocks it makes for an outside check - lives here, pure; the CLI's file
 * store and the bucket both use it.
 *
 * TWO COPIES OF ONE DEVICE MERGE by the rules the CLI already kept one at a time:
 *   links      the union by seq; a link that DIFFERS at a seq both hold is a fork - reported,
 *              never repaired (sync.js: "it REPORTS, never repairs"), and nothing is taken
 *   seals      union by seq; only the newest keeps its ML-DSA-65 half (one hybrid anchor, "B")
 *   checkpoint the newer replaces the older, never the other way round
 *   statement  the later one (by seq)
 *   openings   union by budget (each was checked against the links when it was kept)
 *   notes      union (reasons, receipt messages, seen marks, and who wrote a reason and when - notes.who)
 *   keys       must be the same keys - two keys are two devices, never one copy
 *   anchor     where a copy began trusting the key (a checkpoint, or a LOSS accepted): the earlier of the two - the
 *              union of links reaches back to it (S4, 2026-11-02: it lived only in the app's AsyncStorage)
 *   refusals   the computers' refused TX starts (seq, computer, at, why): union, the newest REFUSALS_KEPT
 *   seals      ...and a seal's `ended` (the budget it closed) is kept when either copy has it
 * Brad, 2026-10-21: merge "to not lose important logging".
 */

const { toHex, fromHex } = require('../../src/bytes');
const chain = require('./chain');
const block = require('./block');

const VERSION = 1;
/* the refused TX starts a copy keeps - the newest, as the app's Edge tab shows them */
const REFUSALS_KEPT = 50;
const seqOf = (r) => chain.decodeLink(r.link).seq;
const hex = (b) => (b ? toHex(b) : '');

/** A copy with nothing in it yet. */
function empty(deviceId) {
  return { deviceId, links: [], lastSeen: null, publicKey: null, publicKeyPq: null, seals: [], checkpoint: null, statement: null, openings: [], anchor: null, refusals: [] };
}

/**
 * A copy from its JSON (the CLI's copy-<id>.json, the bucket's edge.copies entries). An older
 * version is the old chain's: read as no copy.
 * @param {object|null} s
 * @param {Uint8Array} deviceId
 */
function fromJSON(s, deviceId) {
  if (!s || s.v !== VERSION) return empty(deviceId);
  return {
    deviceId,
    links: s.links.map((l) => ({ link: fromHex(l.link), head: fromHex(l.head), ...(l.reveal ? { reveal: fromHex(l.reveal) } : {}) })),
    lastSeen: s.lastSeen ? { seq: s.lastSeen.seq, head: fromHex(s.lastSeen.head) } : null,
    publicKey: s.publicKey ? fromHex(s.publicKey) : null,
    publicKeyPq: s.publicKeyPq ? fromHex(s.publicKeyPq) : null,
    /* only the newest seal keeps signaturePq ("B"); the checkpoint without one loads as empty bytes and fails its check */
    seals: (s.seals || []).map((x) => ({ seq: x.seq, head: fromHex(x.head), signature: fromHex(x.signature), ...(x.signaturePq ? { signaturePq: fromHex(x.signaturePq) } : {}), ...(x.ended !== undefined ? { ended: x.ended } : {}) })),
    openings: Array.isArray(s.openings) ? s.openings : [],
    anchor: s.anchor ? { seq: s.anchor.seq, head: fromHex(s.anchor.head) } : null,
    refusals: Array.isArray(s.refusals) ? s.refusals : [],
    notes: s.notes && typeof s.notes === 'object' ? s.notes : { reasons: {}, messages: {} },
    checkpoint: s.checkpoint ? {
      seq: s.checkpoint.seq, head: fromHex(s.checkpoint.head), signature: fromHex(s.checkpoint.signature), signaturePq: fromHex(s.checkpoint.signaturePq || ''),
    } : null,
    statement: s.statement ? {
      deviceId: fromHex(s.statement.deviceId), publicKey: fromHex(s.statement.publicKey), publicKeyPq: fromHex(s.statement.publicKeyPq || ''),
      seq: s.statement.seq ?? null, nametag: s.statement.nametag, signature: fromHex(s.statement.signature), signaturePq: fromHex(s.statement.signaturePq || ''),
    } : null,
  };
}

/**
 * A copy as JSON.
 * @param {ReturnType<typeof empty>} c
 */
function toJSON(c) {
  return {
    v: VERSION,
    deviceId: toHex(c.deviceId),
    links: c.links.map((l) => ({ link: toHex(l.link), head: toHex(l.head), ...(l.reveal ? { reveal: toHex(l.reveal) } : {}) })),
    lastSeen: c.lastSeen ? { seq: c.lastSeen.seq, head: toHex(c.lastSeen.head) } : null,
    ...(c.publicKey ? { publicKey: toHex(c.publicKey) } : {}),
    ...(c.publicKeyPq ? { publicKeyPq: toHex(c.publicKeyPq) } : {}),
    seals: (c.seals || []).map((x) => ({ seq: x.seq, head: toHex(x.head), signature: toHex(x.signature), ...(x.signaturePq && x.signaturePq.length ? { signaturePq: toHex(x.signaturePq) } : {}), ...(x.ended !== undefined ? { ended: x.ended } : {}) })),
    ...(c.openings && c.openings.length ? { openings: c.openings } : {}),
    ...(c.anchor ? { anchor: { seq: c.anchor.seq, head: toHex(c.anchor.head) } } : {}),
    ...(c.refusals && c.refusals.length ? { refusals: c.refusals } : {}),
    ...(c.notes ? { notes: c.notes } : {}),
    ...(c.checkpoint ? { checkpoint: {
      seq: c.checkpoint.seq, head: toHex(c.checkpoint.head), signature: toHex(c.checkpoint.signature), signaturePq: toHex(c.checkpoint.signaturePq || new Uint8Array(0)),
    } } : {}),
    ...(c.statement ? { statement: {
      deviceId: toHex(c.statement.deviceId), publicKey: toHex(c.statement.publicKey), publicKeyPq: toHex(c.statement.publicKeyPq || new Uint8Array(0)),
      seq: c.statement.seq ?? null, nametag: c.statement.nametag, signature: toHex(c.statement.signature), signaturePq: toHex(c.statement.signaturePq || new Uint8Array(0)),
    } } : {}),
  };
}

/* only the newest seal keeps its ML-DSA-65 half */
function oneAnchor(seals) {
  const sorted = [...seals].sort((a, b) => a.seq - b.seq);
  return sorted.map((x, i) => {
    if (i === sorted.length - 1) return x;
    const { signaturePq: _older, ...p256 } = x;
    return p256;
  });
}

/**
 * Two copies of one device into one.
 * @param {ReturnType<typeof empty>} a the copy kept here
 * @param {ReturnType<typeof empty>} b the copy brought in
 * @returns {{copy: ReturnType<typeof empty>, taken: number, fork: null | {seq: number, reason: string}}}
 *   fork: the copies disagree - `a` is kept as it was, nothing of `b` is taken
 */
function merge(a, b) {
  if (hex(a.deviceId) !== hex(b.deviceId)) throw new Error('two devices\' copies do not merge');
  const keysA = a.publicKey && b.publicKey && hex(a.publicKey) !== hex(b.publicKey);
  const keysPq = a.publicKeyPq && b.publicKeyPq && hex(a.publicKeyPq) !== hex(b.publicKeyPq);
  if (keysA || keysPq) return { copy: a, taken: 0, fork: { seq: -1, reason: 'the copies name different keys for this device' } };

  /* links: the same bytes at every seq both hold, or it is a fork */
  const bySeq = new Map(a.links.map((l) => [seqOf(l), l]));
  for (const l of b.links) {
    const have = bySeq.get(seqOf(l));
    if (have && (hex(have.link) !== hex(l.link) || hex(have.head) !== hex(l.head))) {
      return { copy: a, taken: 0, fork: { seq: seqOf(l), reason: `the copies disagree at #${seqOf(l)} - a fork, reported, never repaired` } };
    }
  }
  /* the union by seq: shared seqs agree (checked above), so nothing either copy holds is dropped */
  let taken = 0;
  for (const l of b.links) {
    if (!bySeq.has(seqOf(l))) {
      bySeq.set(seqOf(l), l);
      taken += 1;
    }
  }
  const links = [...bySeq.values()].sort((x, y) => seqOf(x) - seqOf(y));

  const seals = new Map(a.seals.map((x) => [x.seq, x]));
  for (const x of b.seals) {
    const was = seals.get(x.seq);
    if (!was) seals.set(x.seq, x);
    /* the same seal: the one that knows which budget it closed */
    else if (was.ended === undefined && x.ended !== undefined) seals.set(x.seq, { ...was, ended: x.ended });
  }
  /* refused TX starts: the union (one per seq, computer and time), the newest kept */
  const refusalKey = (r) => `${r.seq}|${r.computer}|${r.at}`;
  const refused = new Map([...(b.refusals || []), ...(a.refusals || [])].map((r) => [refusalKey(r), r]));
  const refusals = [...refused.values()].sort((x, y) => (x.at || 0) - (y.at || 0)).slice(-REFUSALS_KEPT);
  const newer = (x, y, seq) => (!x ? y : !y ? x : seq(y) > seq(x) ? y : x);
  const openings = new Map((a.openings || []).map((o) => [o.grantId, o]));
  for (const o of b.openings || []) if (!openings.has(o.grantId)) openings.set(o.grantId, o);
  const na = a.notes || { reasons: {}, messages: {} };
  const nb = b.notes || { reasons: {}, messages: {} };

  return {
    copy: {
      deviceId: a.deviceId,
      links,
      lastSeen: newer(a.lastSeen, b.lastSeen, (x) => x.seq),
      publicKey: a.publicKey || b.publicKey,
      publicKeyPq: a.publicKeyPq || b.publicKeyPq,
      seals: oneAnchor([...seals.values()]),
      checkpoint: newer(a.checkpoint, b.checkpoint, (x) => x.seq),
      statement: newer(a.statement, b.statement, (x) => x.seq ?? -1),
      openings: [...openings.values()].sort((x, y) => x.grantId - y.grantId),
      notes: {
        reasons: { ...nb.reasons, ...na.reasons }, messages: { ...nb.messages, ...na.messages }, seen: { ...(nb.seen || {}), ...(na.seen || {}) },
        ...(na.who || nb.who ? { who: { ...(nb.who || {}), ...(na.who || {}) } } : {}),
      },
      /* the earlier anchor: the union of links reaches back to it */
      anchor: !a.anchor ? (b.anchor || null) : !b.anchor ? a.anchor : (b.anchor.seq < a.anchor.seq ? b.anchor : a.anchor),
      refusals,
    },
    taken,
    fork: null,
  };
}

/**
 * The copy as JSON blocks (block.js), each checked against the public keys kept with the copy - the
 * newest block with both halves (the one hybrid anchor), older ones by P-256 - and against the block
 * before it. The audit dump: public, checkable by anyone with the keys.
 * @param {ReturnType<typeof empty>} c
 * @param {{net: string}} opts
 */
function blocks(c, { net }) {
  const r = block.blocksFrom({ net, deviceId: c.deviceId, records: c.links, seals: c.seals });
  const out = [];
  for (const [i, b] of r.blocks.entries()) {
    const anchor = i === r.blocks.length - 1;
    const v = c.publicKey ? block.verifyBlock(b, c.publicKey, c.publicKeyPq, out.length ? out[out.length - 1].block : null, { anchor }) : { ok: false, reason: 'no public key kept - it is read from the key with the copy (any edge command with the key plugged in)' };
    out.push({ block: b, id: block.blockId(b), ok: v.ok, ...(v.ok ? {} : { reason: v.reason }) });
  }
  return { deviceId: toHex(c.deviceId), blocks: out, open: r.open, ...(r.reason ? { reason: r.reason } : {}) };
}

module.exports = { VERSION, REFUSALS_KEPT, empty, fromJSON, toJSON, merge, blocks, seqOf };
