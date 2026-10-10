'use strict';

/**
 * onlykey-js edge sync, phase 2 (onlykey-edge APP.md; Brad,
 * 2026-10-05): a place that keeps copies (this PC's copy store first) brings
 * the PHONE's copy of the key's chain up to date - the links the phone lacks,
 * from a copy the PC verified (R27). Pure: no device, no Node built-ins.
 *
 * The rules this follows (Brad / the spec session; as of 2026-10-08):
 *  - a computer the person approved for Bluetooth (paired with its 6-digit code)
 *    may offer links; until 2026-10-08 that was a place on the KEY's peer list
 *    (R20), and the key and the phone keep no peer list now;
 *  - the phone's OWN links merge at once (its own key's, checked against its
 *    signature) - no sheet, no press, no link on the key. Until 2026-10-08 a sync
 *    took Yes and a press and the key wrote a `sync` link (op 20); that op is unused;
 *  - another device's log is HELD on the phone (OFFER) until the person approves
 *    it from the Edge tab's banner, merged only when complete;
 *  - it moves history only - never budgets, debts or "yours";
 *  - it REPORTS, never repairs: a link that disagrees with one the phone
 *    already holds is a fork, and the whole sync stops there.
 *
 * Each message is signed by the place's own P-256 key (request.peerSigner); the
 * first two:
 *
 *   EDGE_SYNC_HAVE  {deviceId, name}        -> the phone's answer: {ok, ranges}
 *   EDGE_SYNC_LINKS {sid, deviceId, part, parts, links: [[link, head, reveal|null] hex]}
 *                                           -> {ok, staged} for a part before the last;
 *                                              the last one is answered after the sheet
 *
 * A batch is at most BATCH links: the vendor wire carries about 14 KB per
 * message (255 pieces), and a link record is 128 bytes, 256 as hex.
 */

const crypto = require('../../src/crypto/provider');
const { randomBytes } = require('../../src/vendor/exports/@noble/ciphers/utils.js');
const { utf8ToBytes, toHex, fromHex, concat } = require('../../src/bytes');
const chain = require('./chain');
const { H, u32le } = require('./hash');

const HAVE_TYPE = 'EDGE_SYNC_HAVE';
const LINKS_TYPE = 'EDGE_SYNC_LINKS';
const COMMIT_TYPE = 'EDGE_SYNC_COMMIT';
/*
 * GIVE asks a phone for its own copy of its chain (read-only, history only); HAVE and
 * LINKS carry `chain` = whose links they are (absent: the phone's own). No sibling or
 * anchor message since 2026-10-08: pairing and sync are all the app's (Brad), and
 * another device's log is offered and HELD until the person approves it.
 */
const GIVE_TYPE = 'EDGE_SYNC_GIVE';
/*
 * OFFER (2026-10-08) ends a sync of ANOTHER device's log: its links (LINKS with `chain`) up
 * to its key's signed checkpoint, and its owner statement. The phone HOLDS it - no sheet pops
 * up, nothing merges - until the person approves the merge from the Edge tab's banner (Brad:
 * "hold these blocks in the app until approved and merged"). devices.classify sorts it.
 */
const OFFER_TYPE = 'EDGE_SYNC_OFFER';
const TYPES = [HAVE_TYPE, LINKS_TYPE, COMMIT_TYPE, GIVE_TYPE, OFFER_TYPE];
/* a Key Chain part: JSON text up to this many characters (the wire carries ~14 KB a message) */
/* "no seq": a checkpoint of a key with no link yet (anchorCheck); it once filled the retired sync link's seq fields when only the Key Chain list moved */
const NO_SEQ = 0xffffffff;
const TAG = 'OKEDGE-SYNC-MSG-v1';
const BATCH = 40;

const isHex = (s, n) => typeof s === 'string' && (n === undefined ? s.length % 2 === 0 : s.length === n * 2) && /^[0-9a-f]*$/i.test(s);

/*
 * What a message's signature covers: the tag, its type, the place's key, the nonce,
 * and the payload in its canonical form - keys sorted at every level (canon below).
 * Since the clean start (v1, Brad 2026-10-07): it was the payload as sent, so two
 * writers that built the same payload in a different key order signed different
 * bytes. canon, not the blocks' strict subset (block.js), because a payload carries
 * the Key Chain list, whose names may be any text.
 */
function body({ type, peer, nonce, payload }) {
  return concat([utf8ToBytes(TAG), utf8ToBytes(type), fromHex(peer), fromHex(nonce), utf8ToBytes(JSON.stringify(canon(payload)))]);
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
 * The phone's side: signed by the key it names, well formed, new. Which computer
 * that key is, is the caller's to show (the link itself came over a Bluetooth
 * pairing the person approved with its 6-digit code).
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
  if (msg.type === COMMIT_TYPE && (!isHex(p.sid, 8) || !Number.isInteger(p.linkParts) || p.linkParts < 0 || p.linkParts > 255)) return { ok: false, reason: 'malformed' };
  if (p.chain !== undefined && !isHex(p.chain, 16)) return { ok: false, reason: 'malformed' };
  if (msg.type === GIVE_TYPE && (!Number.isInteger(p.from) || p.from < 0 || p.from > 0xffffffff)) return { ok: false, reason: 'malformed' };
  if (msg.type === OFFER_TYPE) {
    const c = p.checkpoint;
    const st = p.statement;
    const u32ok = (n) => Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
    if (!isHex(p.sid, 8) || !isHex(p.chain, 16) || !Number.isInteger(p.linkParts) || p.linkParts < 0 || p.linkParts > 255
      || !c || !u32ok(c.seq) || !isHex(c.head, 32) || !isHex(c.signature, 64)
      || !st || !isHex(st.publicKey, 64) || !(st.seq === null || u32ok(st.seq)) || typeof st.nametag !== 'string' || !st.nametag.trim()
      || utf8ToBytes(st.nametag).length > 0xff || !isHex(st.signature, 64)
      || (p.openings !== undefined && (!Array.isArray(p.openings) || p.openings.length > 500 || p.openings.some((o) => !o || typeof o !== 'object')))
      || (p.notes !== undefined && (!p.notes || typeof p.notes !== 'object'))) {
      return { ok: false, reason: 'malformed' };
    }
  }
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

/* CANONICAL: keys sorted at every level, so the same payload always signs as the same bytes */
function canon(v) {
  if (Array.isArray(v)) return v.map(canon);
  if (v && typeof v === 'object') return Object.keys(v).sort().reduce((o, k) => { o[k] = canon(v[k]); return o; }, {});
  return v;
}

/**
 * The computer's side: "that is device `chain`'s log up to its signed checkpoint, with its
 * statement" - for the phone whose key is `deviceId` to HOLD until the person approves.
 * checkpoint: {seq, head, signature}; statement: {publicKey, seq, nametag, signature} (as
 * plugin.statement gives it, or as that device's phone kept it).
 */
function buildOffer({ signer, deviceId, sid, chain: chainId, linkParts, checkpoint, statement, openings = [], notes = null }) {
  return sign(OFFER_TYPE, signer, {
    sid, deviceId: toHex(deviceId), chain: toHex(chainId), linkParts,
    checkpoint: { seq: checkpoint.seq, head: toHex(checkpoint.head), signature: toHex(checkpoint.signature) },
    statement: { publicKey: toHex(statement.publicKey), seq: statement.seq ?? null, nametag: String(statement.nametag), signature: toHex(statement.signature) },
    /* the budgets' opening words (devices.checkOpenings) - the receiving phone checks each against the log */
    openings: (openings || []).slice(0, 500),
    /* its notes, intents and receipt messages by seq - each screen checks them against the chain's hashes */
    notes: require('./devices').shapeNotes(notes),
  });
}

/** The place's side: "that is every part" - the phone merges its own links at once (no sheet, no press since 2026-10-08). */
function buildCommit({ signer, deviceId, sid, linkParts }) {
  return sign(COMMIT_TYPE, signer, { sid, deviceId: toHex(deviceId), linkParts });
}

/** R30: the place asks the phone whose key is `deviceId` for its copy of its own chain, from seq `from` (BATCH at a time). */
function buildGive({ signer, deviceId, from = 0 }) {
  return sign(GIVE_TYPE, signer, { deviceId: toHex(deviceId), from });
}

/**
 * Before a phone merges another device's log, that chain as offered must hold up - the
 * phone's side, no I/O (devices.classify runs it). (Named for the anchors it served until
 * 2026-10-08; the check itself is unchanged.)
 *   records:    the phone's copy of that chain merged with what came
 *   publicKey:  that device's checkpoint key (X || Y), as its statement names it
 *   checkpoint: {seq, head, signature} read from that device's key
 *   anchors:    [{seq, head}] the points of that chain this phone merged before
 * ALARMS (spec R30, written when the key kept siblings: "a sibling anchors a head its
 * own chain doesn't contain: one device's rollback or tampering is proven by the other";
 * the check now runs on the phone, against heads it merged before):
 *   bad-checkpoint - not signed by that device's key;
 *   rollback       - that device's head is now older than one this phone merged before;
 *   changed        - at a seq merged before, that device's chain now holds another head;
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
  /*
   * A key with no link yet signs NO_SEQ (0xffffffff): an empty chain, checked at once. Read as a
   * seq, the check counted toward four billion and the computer's sync hung (a new Pixel's first
   * sync, 2026-10-08). A link offered past an empty checkpoint is not this chain's.
   */
  if (cp.seq === NO_SEQ) return records.length ? { ok: false, alarm: 'tampered', seq: cp.seq, detail: 'links offered past an empty checkpoint' } : { ok: true, verifiedThrough: -1, open: false };
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

module.exports = {
  HAVE_TYPE, LINKS_TYPE, COMMIT_TYPE, GIVE_TYPE, OFFER_TYPE, BATCH, NO_SEQ, buildGive, buildOffer, anchorCheck,
  buildCommit,
  body, buildHave, buildLinks, verify, recordsOf, rangesOf, missing, merge,
};
