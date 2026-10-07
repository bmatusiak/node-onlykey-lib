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

const crypto = require('../crypto/provider');
const { randomBytes } = require('../vendor/exports/@noble/ciphers/utils.js');
const { utf8ToBytes, toHex, fromHex, concat } = require('../bytes');
const chain = require('./chain');
const { H, u32le } = require('./hash');

const HAVE_TYPE = 'EDGE_SYNC_HAVE';
const LINKS_TYPE = 'EDGE_SYNC_LINKS';
/*
 * The Key Chain public list (Brad / the spec, 2026-10-05: "merged, never marking
 * anything yours"). The place sends its WHOLE list in parts; COMMIT asks the
 * phone to merge links and list and show ONE sheet; after the press the place
 * TAKEs back the merged list, so both hold the same one - the sync link's last
 * field is its digest.
 */
const KEYCHAIN_TYPE = 'EDGE_SYNC_KEYCHAIN';
const COMMIT_TYPE = 'EDGE_SYNC_COMMIT';
const TAKE_TYPE = 'EDGE_SYNC_TAKE';
/* R29 (P2b): pair the phone's key with another key of yours - the place relays that key */
const SIBLING_TYPE = 'EDGE_SIBLING_ADD';
/*
 * R30 (P2c): a sync between siblings. GIVE asks a phone for its own copy of its
 * chain (read-only, history only - a place on the key's list may keep copies
 * anyway); HAVE and LINKS carry `chain` = whose links they are (absent: the
 * phone's own); ANCHOR ends it - one sheet, a press, the anchor link.
 */
const GIVE_TYPE = 'EDGE_SYNC_GIVE';
const ANCHOR_TYPE = 'EDGE_SYNC_ANCHOR';
const TYPES = [HAVE_TYPE, LINKS_TYPE, KEYCHAIN_TYPE, COMMIT_TYPE, TAKE_TYPE, SIBLING_TYPE, GIVE_TYPE, ANCHOR_TYPE];
/* a Key Chain part: JSON text up to this many characters (the wire carries ~14 KB a message) */
const KEYCHAIN_PART_CHARS = 8000;
/* no link moved, only the Key Chain list: the sync link's seq fields (CHOSEN, pending the spec) */
const NO_SEQ = 0xffffffff;
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
function buildHave({ signer, deviceId, name, chain = null }) {
  return sign(HAVE_TYPE, signer, { deviceId: toHex(deviceId), name: String(name), ...(chain ? { chain: toHex(chain) } : {}) });
}

/**
 * The place's side: the links the phone lacks, in signed batches of <= BATCH.
 * records: [{link, head, reveal?}] (bytes). -> [message, ...] (one sid for all)
 */
async function buildLinks({ signer, deviceId, records, sid = toHex(randomBytes(8)), chain = null }) {
  const parts = Math.max(1, Math.ceil(records.length / BATCH));
  const out = [];
  for (let part = 0; part < parts; part += 1) {
    const links = records.slice(part * BATCH, (part + 1) * BATCH)
      .map((r) => [toHex(r.link), toHex(r.head), r.reveal ? toHex(r.reveal) : null]);
    out.push(await sign(LINKS_TYPE, signer, { sid, deviceId: toHex(deviceId), part, parts, links, ...(chain ? { chain: toHex(chain) } : {}) }));
  }
  return out;
}

/**
 * R29 (P2b): ask the phone whose key is `deviceId` to pair it with another
 * key of yours (its Edge key X || Y and device id, read from that key by this
 * place). The place only RELAYS that key - the phone shows a code made from
 * both keys (grants.siblingCode) that the other phone shows too.
 */
function buildSibling({ signer, deviceId, key, id, name }) {
  return sign(SIBLING_TYPE, signer, { deviceId: toHex(deviceId), key: toHex(key), id: toHex(id), name: String(name) });
}

/**
 * The phone's side: signed by the key it names, well formed, new. Whether that
 * key is on the KEY's peer list is the caller's check (it needs the device).
 * -> {ok} | {ok: false, reason}
 */
function verify(msg, { seen } = {}) {
  if (!msg || !TYPES.includes(msg.type) || msg.v !== 1 || !isHex(msg.peer, 64)
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
  const partOk = () => isHex(p.sid, 8) && Number.isInteger(p.part) && Number.isInteger(p.parts) && p.part >= 0 && p.part < p.parts && p.parts <= 255;
  if (msg.type === KEYCHAIN_TYPE && (!partOk() || !Array.isArray(p.entries))) return { ok: false, reason: 'malformed' };
  if (msg.type === COMMIT_TYPE && (!isHex(p.sid, 8) || !Number.isInteger(p.linkParts) || !Number.isInteger(p.keychainParts)
    || p.linkParts < 0 || p.keychainParts < 0 || p.linkParts > 255 || p.keychainParts > 255)) return { ok: false, reason: 'malformed' };
  if (msg.type === TAKE_TYPE && (!isHex(p.sid, 8) || !Number.isInteger(p.part) || p.part < 0 || p.part > 255)) return { ok: false, reason: 'malformed' };
  if (p.chain !== undefined && !isHex(p.chain, 16)) return { ok: false, reason: 'malformed' };
  if (msg.type === GIVE_TYPE && (!Number.isInteger(p.from) || p.from < 0 || p.from > 0xffffffff)) return { ok: false, reason: 'malformed' };
  if (msg.type === ANCHOR_TYPE) {
    const c = p.checkpoint;
    if (!isHex(p.sid, 8) || !isHex(p.chain, 16) || !Number.isInteger(p.linkParts) || p.linkParts < 0 || p.linkParts > 255
      || typeof p.name !== 'string' || !p.name.trim() || utf8ToBytes(p.name).length > 0xff
      || !c || !Number.isInteger(c.seq) || c.seq < 0 || c.seq > 0xffffffff || !isHex(c.head, 32) || !isHex(c.signature, 64)) {
      return { ok: false, reason: 'malformed' };
    }
  }
  if (msg.type === SIBLING_TYPE && (!isHex(p.key, 64) || !isHex(p.id, 16) || typeof p.name !== 'string' || !p.name.trim()
    || utf8ToBytes(p.name).length > 0xff)) return { ok: false, reason: 'malformed' };
  let good = false;
  try {
    good = crypto.p256Verify(fromHex(msg.signature), body(msg), Uint8Array.from([4, ...fromHex(msg.peer)]));
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
  if (!added.length && !keychainHash) throw new RangeError('edge sync: nothing moved, nothing to record');
  /* only the Key Chain list moved: no link range to name (NO_SEQ) */
  const seqs = added.length ? added.map((r) => chain.decodeLink(r.link).seq) : [NO_SEQ];
  const h = bytesOf(head);
  if (h.length !== 32) throw new TypeError('edge sync: the copy head is 32 bytes');
  const kc = keychainHash ? bytesOf(keychainHash) : new Uint8Array(32);
  if (kc.length !== 32) throw new TypeError('edge sync: the Key Chain hash is 32 bytes');
  return { peerHash: crypto.sha256(bytesOf(peer)), first: Math.min(...seqs), last: Math.max(...seqs), head: h, keychain: kc };
}

/**
 * The subject: SHA256("OKEDGE-SYNC-v1" || peerHash || u32le first || u32le last
 * || head || keychain) - the bytes the key hashes, in its order.
 */
function syncSubject(fields) {
  const f = fields.peerHash ? fields : syncFields(fields);
  return H(SUBJECT_TAG, f.peerHash, u32le(f.first), u32le(f.last), f.head, f.keychain);
}

/* ------------------------------------------------ the Key Chain list */

const list = require('../keychain/list');

/*
 * CANONICAL: keys sorted at every level. The same entry built two ways (the
 * phone joining twins, the computer parsing what it took back) had its keys in
 * a different order - identical content, different text - so every sync counted
 * the same entries as new to the computer and asked for a press again (the A13,
 * 2026-10-05), and the two sides' digests of one list could differ.
 */
function canon(v) {
  if (Array.isArray(v)) return v.map(canon);
  if (v && typeof v === 'object') return Object.keys(v).sort().reduce((o, k) => { o[k] = canon(v[k]); return o; }, {});
  return v;
}

/*
 * What a list IS, for comparing and for the digest - not when each key was last
 * used. lastSeen moves by itself: the agent derives its identities on every
 * start, the soft key records it, and every sync after counted that as new and
 * asked for a press (the A13, 2026-10-05: 2 entries, every time). It still
 * travels with a sync that moves something real; it never makes one.
 */
const VOLATILE = ['lastSeen'];

/** The entries as list.serialize writes them (public key hex), id order, keys sorted, no lastSeen - one text for one list, on any side. */
function keychainText(entries) {
  const sorted = [...entries].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const doc = JSON.parse(list.serialize(sorted));
  doc.entries = doc.entries.map((e) => { const o = { ...e }; for (const k of VOLATILE) delete o[k]; return o; });
  return JSON.stringify(canon(doc));
}

/** SHA256 of the list in id order - the sync link's last field when a list moved. */
function keychainDigest(entries) {
  return crypto.sha256(utf8ToBytes(keychainText(entries)));
}

/** Entries as plain JSON objects (public key hex), split into parts of about KEYCHAIN_PART_CHARS. */
function keychainParts(entries) {
  /* the full entries, lastSeen included - only the comparison leaves it out */
  const plain = JSON.parse(list.serialize([...entries].sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0)))).entries;
  const parts = [];
  let cur = [];
  let size = 0;
  for (const e of plain) {
    const n = JSON.stringify(e).length;
    if (cur.length && size + n > KEYCHAIN_PART_CHARS) { parts.push(cur); cur = []; size = 0; }
    cur.push(e);
    size += n;
  }
  parts.push(cur);
  return parts;
}

/** Plain entry objects back to entries - every one checked again (list.parse refuses anything private or "yours"). */
function keychainEntriesOf(plain) {
  return list.parse(JSON.stringify({ format: list.FORMAT, version: list.VERSION, entries: plain }));
}

/** The place's side: its whole list, signed parts under the sync's sid. */
async function buildKeychain({ signer, deviceId, sid, entries }) {
  const parts = keychainParts(entries);
  const out = [];
  for (let part = 0; part < parts.length; part += 1) {
    out.push(await sign(KEYCHAIN_TYPE, signer, { sid, deviceId: toHex(deviceId), part, parts: parts.length, entries: parts[part] }));
  }
  return out;
}

/** The place's side: "that is everything - merge it and ask". pcIds: the ids its list holds. */
function buildCommit({ signer, deviceId, sid, linkParts, keychainParts: kcParts }) {
  return sign(COMMIT_TYPE, signer, { sid, deviceId: toHex(deviceId), linkParts, keychainParts: kcParts });
}

/** R30: the place asks the phone whose key is `deviceId` for its copy of its own chain, from seq `from` (BATCH at a time). */
function buildGive({ signer, deviceId, from = 0 }) {
  return sign(GIVE_TYPE, signer, { deviceId: toHex(deviceId), from });
}

/**
 * R30: "that is the sibling's chain up to its signed checkpoint - anchor it".
 * chain: the sibling's device id; checkpoint: {seq, head, signature} from the
 * sibling's key; name: the sibling as the place calls it (shown, never trusted).
 */
function buildAnchor({ signer, deviceId, sid, chain, linkParts, checkpoint, name }) {
  return sign(ANCHOR_TYPE, signer, {
    sid, deviceId: toHex(deviceId), chain: toHex(chain), linkParts, name: String(name),
    checkpoint: { seq: checkpoint.seq, head: toHex(checkpoint.head), signature: toHex(checkpoint.signature) },
  });
}

/**
 * R30 (P2c): before a phone anchors its sibling, the sibling's chain as offered
 * must hold up - the phone's side, no I/O.
 *   records:    the phone's copy of the sibling's chain merged with what came
 *   publicKey:  the sibling's Edge key (X || Y), from the KEY's sibling list
 *   checkpoint: {seq, head, signature} the place read from the sibling's key
 *   anchors:    [{seq, head}] this phone anchored that sibling at before
 * ALARMS (spec R30: "a sibling anchors a head its own chain doesn't contain:
 * one device's rollback or tampering is proven by the other"):
 *   bad-checkpoint - not signed by the sibling's key;
 *   rollback       - the sibling's head is now older than one already anchored;
 *   changed        - at a seq already anchored, the sibling's chain now holds another head;
 *   tampered       - the links do not verify up to the signed checkpoint.
 * -> {ok: true, verifiedThrough, open} | {ok: false, alarm, seq?, detail?}
 *
 * @param {{records: Array<{link: Uint8Array, head: Uint8Array, reveal?: Uint8Array|null}>, publicKey: Uint8Array,
 *   checkpoint: {seq: number, head: Uint8Array, signature: Uint8Array}, anchors?: Array<{seq: number, head: Uint8Array}>}} o
 * @returns {{ok: boolean, alarm?: string, seq?: number, detail?: string, verifiedThrough?: number, open?: any[]}}
 */
function anchorCheck({ records, publicKey, checkpoint, anchors = [] }) {
  const chainLib = require('./chain');
  const copyLib = require('./copy');
  const deviceId = chainLib.deviceIdOf(publicKey);
  const cp = { seq: checkpoint.seq, head: Uint8Array.from(checkpoint.head) };
  if (!chainLib.verifyCheckpoint({ deviceId, ...cp }, checkpoint.signature, publicKey)) return { ok: false, alarm: 'bad-checkpoint', seq: cp.seq };
  const newest = anchors.reduce((m, a) => (m === null || a.seq > m.seq ? a : m), null);
  if (newest && cp.seq < newest.seq) return { ok: false, alarm: 'rollback', seq: newest.seq, detail: `its head is #${cp.seq}, older than #${newest.seq} anchored before` };
  const upTo = records.filter((r) => chainLib.decodeLink(r.link).seq <= cp.seq);
  const bySeq = new Map(upTo.map((r) => [chainLib.decodeLink(r.link).seq, r]));
  for (const a of anchors) {
    const at = a.seq === cp.seq ? cp.head : bySeq.get(a.seq) ? bySeq.get(a.seq).head : null;
    if (at && toHex(at) !== toHex(a.head)) return { ok: false, alarm: 'changed', seq: a.seq, detail: `#${a.seq} holds another head than the one anchored` };
  }
  const v = copyLib.assess({ links: upTo }, { publicKey, head: cp, held: [], checkpoint: { ...cp, signature: checkpoint.signature } });
  if (v.chain.failure) return { ok: false, alarm: 'tampered', seq: v.chain.failure.seq, detail: v.chain.failure.reason };
  return { ok: true, verifiedThrough: v.chain.verifiedThrough, open: v.open };
}

/** The place's side, after the press: one part of the merged list. */
function buildTake({ signer, deviceId, sid, part }) {
  return sign(TAKE_TYPE, signer, { sid, deviceId: toHex(deviceId), part });
}

/**
 * The phone's side: its list + the place's. -> {merged, in (entries new to the
 * phone, or joined with a twin), out (merged entries the place does not hold as
 * they are)} - out is what TAKE will give back.
 */
function keychainPlan(phoneEntries, placeEntries) {
  const m = list.merge(phoneEntries, placeEntries);
  const mine = new Map(placeEntries.map((e) => [e.id, keychainText([e])]));
  const out = m.entries.filter((e) => mine.get(e.id) !== keychainText([e]));
  /* in: new to the phone, joined with a twin, or given fields it lacked */
  return { merged: m.entries, in: m.added + m.paired + m.joined, out: out.length };
}

/**
 * The place's side, after TAKE: the merged list must hold every entry the place
 * had (by id, or joined into a twin) - a phone that dropped one is refused.
 * -> {ok, entries} | {ok: false, missing: [id]}
 */
function checkTaken(placeEntries, taken) {
  const ids = new Set(taken.map((e) => e.id));
  const missing = placeEntries.filter((e) => !ids.has(e.id) && !list.findTwin(taken, e)).map((e) => e.id);
  return missing.length ? { ok: false, missing } : { ok: true, entries: taken };
}

module.exports = {
  HAVE_TYPE, LINKS_TYPE, KEYCHAIN_TYPE, COMMIT_TYPE, TAKE_TYPE, SIBLING_TYPE, GIVE_TYPE, ANCHOR_TYPE, BATCH, NO_SEQ, buildSibling, buildGive, buildAnchor, anchorCheck,
  keychainText, keychainDigest, keychainParts, keychainEntriesOf, buildKeychain, buildCommit, buildTake, keychainPlan, checkTaken,
  body, buildHave, buildLinks, verify, recordsOf, rangesOf, missing, merge, syncFields, syncSubject,
};
