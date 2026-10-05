'use strict';

/**
 * okedge sync, phase 2 (onlykey-edge build/mcp-service.md §4.2b; Brad,
 * 2026-10-05): a place that keeps copies (this PC's copy store first) brings
 * the PHONE's copy of the key's chain up to date - the links the phone lacks,
 * from a copy the PC verified (R27). Pure: no device, no Node built-ins.
 *
 * The rules this follows (Brad / the spec session):
 *  - only a place on the KEY's peer list (R20) may offer links;
 *  - a sync that changes anything shows a sheet, takes Yes and a press, and the
 *    press writes a `sync` link (op 20) whose subject is SHA256 of what moved;
 *    it owes no ticket;
 *  - it moves history only - never budgets, debts, registrations or "yours";
 *  - it REPORTS, never repairs: a link that disagrees with one the phone
 *    already holds is a fork, and the whole sync stops there.
 *
 * Two messages, each signed by the place's own P-256 key (request.peerSigner):
 *
 *   EDGE_SYNC_HAVE  {deviceId, name}        -> the phone's answer: {ok, ranges}
 *   EDGE_SYNC_LINKS {sid, deviceId, part, parts, links: [[link, head, reveal|null] hex]}
 *                                           -> {ok, staged} for a part before the last;
 *                                              the last one is answered after the sheet
 *
 * A batch is at most BATCH links: the vendor wire carries about 14 KB per
 * message (255 pieces), and a link record is 128 bytes, 256 as hex.
 */

const { sha256 } = require('../vendor/exports/@noble/hashes/sha2.js');
const { p256 } = require('../vendor/exports/@noble/curves/nist.js');
const { randomBytes } = require('../vendor/exports/@noble/ciphers/utils.js');
const { utf8ToBytes, toHex, fromHex, concat } = require('../bytes');
const chain = require('./chain');
const { H, u32le } = require('./hash');

const HAVE_TYPE = 'EDGE_SYNC_HAVE';
const LINKS_TYPE = 'EDGE_SYNC_LINKS';
const TAG = 'OKEDGE-SYNC-MSG-v1';
const SUBJECT_TAG = 'OKEDGE-SYNC-v1';
const BATCH = 40;

const isHex = (s, n) => typeof s === 'string' && (n === undefined ? s.length % 2 === 0 : s.length === n * 2) && /^[0-9a-f]*$/i.test(s);

/* what a message's signature covers: the tag, its type, the place's key, the nonce, the payload as sent */
function body({ type, peer, nonce, payload }) {
  return concat([utf8ToBytes(TAG), utf8ToBytes(type), fromHex(peer), fromHex(nonce), utf8ToBytes(JSON.stringify(payload))]);
}

async function sign(type, signer, payload, nonce = randomBytes(16)) {
  const msg = { type, v: 1, peer: toHex(signer.publicKey), nonce: toHex(nonce), payload };
  msg.signature = toHex(await signer.sign(body(msg)));
  return msg;
}

/** The place's side, first: what does the phone's copy of this chain hold? */
function buildHave({ signer, deviceId, name }) {
  return sign(HAVE_TYPE, signer, { deviceId: toHex(deviceId), name: String(name) });
}

/**
 * The place's side: the links the phone lacks, in signed batches of <= BATCH.
 * records: [{link, head, reveal?}] (bytes). -> [message, ...] (one sid for all)
 */
async function buildLinks({ signer, deviceId, records, sid = toHex(randomBytes(8)) }) {
  const parts = Math.max(1, Math.ceil(records.length / BATCH));
  const out = [];
  for (let part = 0; part < parts; part += 1) {
    const links = records.slice(part * BATCH, (part + 1) * BATCH)
      .map((r) => [toHex(r.link), toHex(r.head), r.reveal ? toHex(r.reveal) : null]);
    out.push(await sign(LINKS_TYPE, signer, { sid, deviceId: toHex(deviceId), part, parts, links }));
  }
  return out;
}

/**
 * The phone's side: signed by the key it names, well formed, new. Whether that
 * key is on the KEY's peer list is the caller's check (it needs the device).
 * -> {ok} | {ok: false, reason}
 */
function verify(msg, { seen } = {}) {
  if (!msg || (msg.type !== HAVE_TYPE && msg.type !== LINKS_TYPE) || msg.v !== 1 || !isHex(msg.peer, 64)
    || !isHex(msg.nonce, 16) || !isHex(msg.signature, 64) || !msg.payload || typeof msg.payload !== 'object' || !isHex(msg.payload.deviceId, 16)) {
    return { ok: false, reason: 'malformed' };
  }
  const p = msg.payload;
  if (msg.type === HAVE_TYPE && (typeof p.name !== 'string' || !p.name.trim() || utf8ToBytes(p.name).length > 0xff)) return { ok: false, reason: 'malformed' };
  if (msg.type === LINKS_TYPE) {
    if (!isHex(p.sid, 8) || !Number.isInteger(p.part) || !Number.isInteger(p.parts) || p.part < 0 || p.part >= p.parts || p.parts > 255
      || !Array.isArray(p.links) || p.links.length > BATCH
      || !p.links.every((l) => Array.isArray(l) && isHex(l[0], 64) && isHex(l[1], 32) && (l[2] === null || isHex(l[2], 32)))) {
      return { ok: false, reason: 'malformed' };
    }
  }
  let good = false;
  try {
    good = p256.verify(fromHex(msg.signature), body(msg), Uint8Array.from([4, ...fromHex(msg.peer)]), { prehash: true });
  } catch { good = false; }
  if (!good) return { ok: false, reason: 'bad-signature' };
  if (seen && seen.has(msg.nonce.toLowerCase())) return { ok: false, reason: 'replayed' };
  return { ok: true };
}

/** The records a LINKS message carries, as bytes. */
function recordsOf(msg) {
  return msg.payload.links.map(([l, h, r]) => ({ link: fromHex(l), head: fromHex(h), reveal: r ? fromHex(r) : null }));
}

/** [[from, to], ...] covering a set of seqs - what a copy holds, said compactly. */
function rangesOf(seqs) {
  const s = [...new Set(seqs)].sort((a, b) => a - b);
  const out = [];
  for (const n of s) {
    const last = out[out.length - 1];
    if (last && n === last[1] + 1) last[1] = n;
    else out.push([n, n]);
  }
  return out;
}

const inRanges = (ranges, n) => ranges.some(([a, b]) => n >= a && n <= b);

/** The place's side: its records the phone's ranges do not cover. */
function missing(records, ranges) {
  return records.filter((r) => !inRanges(ranges, chain.decodeLink(r.link).seq));
}

const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * The phone's side: its copy's records + the offered ones, by seq. A seq on
 * both sides with different bytes is a FORK - reported, never chosen between.
 * -> {links (sorted by seq), added: [records], conflicts: [seq]}
 */
function merge(have, offered) {
  const bySeq = new Map(have.map((r) => [chain.decodeLink(r.link).seq, r]));
  const added = [];
  const conflicts = [];
  for (const r of offered) {
    const seq = chain.decodeLink(r.link).seq;
    const mine = bySeq.get(seq);
    if (mine) {
      if (!sameBytes(mine.link, r.link) || !sameBytes(mine.head, r.head)) conflicts.push(seq);
      continue;
    }
    bySeq.set(seq, r);
    added.push(r);
  }
  const links = [...bySeq.entries()].sort((a, b) => a[0] - b[0]).map(([, r]) => r);
  added.sort((a, b) => chain.decodeLink(a.link).seq - chain.decodeLink(b.link).seq);
  return { links, added, conflicts };
}

const bytesOf = (b) => (b instanceof Uint8Array ? b : fromHex(b));

/**
 * The `sync` link's fields (spec, 2026-10-05; onlykey-edge firmware.md):
 * SHA256(peer pubkey X || Y) . first seq moved . last seq moved . the phone
 * copy's head after the merge . SHA256(the merged Key Chain list), or 32 zero
 * bytes when no list moved. The KEY computes the subject from these (SYNC's
 * three parts) and checks the peer hash is one of its own peers.
 * -> {peerHash, first, last, head, keychain}
 */
function syncFields({ peer, added, head, keychainHash = null }) {
  if (!added.length) throw new RangeError('edge sync: nothing moved, nothing to record');
  const seqs = added.map((r) => chain.decodeLink(r.link).seq);
  const h = bytesOf(head);
  if (h.length !== 32) throw new TypeError('edge sync: the copy head is 32 bytes');
  const kc = keychainHash ? bytesOf(keychainHash) : new Uint8Array(32);
  if (kc.length !== 32) throw new TypeError('edge sync: the Key Chain hash is 32 bytes');
  return { peerHash: sha256(bytesOf(peer)), first: Math.min(...seqs), last: Math.max(...seqs), head: h, keychain: kc };
}

/**
 * The subject: SHA256("OKEDGE-SYNC-v1" || peerHash || u32le first || u32le last
 * || head || keychain) - the bytes the key hashes, in its order.
 */
function syncSubject(fields) {
  const f = fields.peerHash ? fields : syncFields(fields);
  return H(SUBJECT_TAG, f.peerHash, u32le(f.first), u32le(f.last), f.head, f.keychain);
}

module.exports = {
  HAVE_TYPE, LINKS_TYPE, BATCH,
  body, buildHave, buildLinks, verify, recordsOf, rangesOf, missing, merge, syncFields, syncSubject,
};
