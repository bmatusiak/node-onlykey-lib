'use strict';

/**
 * Edge BLOCKS as JSON (Brad, 2026-10-07: "we use hash of a json"; "that is
 * actually what i wanted"; "i dont want every transaction").
 *
 * WHAT A BLOCK IS. The key keeps its small 64-byte links and signs a checkpoint
 * over its head when a block closes - a budget ends, or a sync (BLOCKS.md §1).
 * A block is the links between two such seals, written as ONE canonical JSON
 * document. The key never sees the JSON: it still welds binary links and signs
 * its head. The JSON is what a host keeps, shows, exports and hands to anyone
 * who wants to check: jq reads it, and a few lines of any language verify it.
 *
 *   block id = SHA-256(canonical JSON of the block)
 *
 * WHY EVERY LINK IS WRITTEN AS ITS FIELDS, NOT AS HEX. A reader should see
 * "op": "sign", "grant": 12, "step": 3 - not 64 bytes of hex. The fields are
 * exactly the link's byte layout (chain.js), so the checker re-encodes each one
 * to the same 64 bytes and welds them. Nothing is stored twice, so nothing can
 * disagree with itself: a field that does not re-encode to a link the key would
 * write is refused when the block is built.
 *
 * WHY A STRICT SUBSET OF RFC 8785. Every program that writes a block (this
 * library, the app, Python vectors, an outside auditor) must produce the same
 * bytes, or the same block gets two ids and looks tampered - the false
 * "tampered" this project already fought once. RFC 8785's hard parts are numbers
 * and non-ASCII strings; a block uses neither: integers up to 2^53, ASCII strings
 * (hex, names), arrays, objects with ASCII keys, true/false/null. canonical()
 * throws on anything else, so a block can never quietly depend on an
 * implementation's float or Unicode rules. Within the subset the output equals
 * RFC 8785, and equals Python's json.dumps(sort_keys=True, separators=(",", ":")).
 *
 * WHAT IS TRUSTED. Only the key's signature: verifyBlock() needs the device's
 * Edge public key from the key (this session), never one carried in the block.
 */
const { OP } = require('./codes');
const chain = require('./chain');
const { anchorSubject } = require('./grants');
const crypto = require('../../src/crypto/provider');
const { toHex, fromHex } = require('../../src/bytes');

const BLOCK_VERSION = 1;
const NETS = Object.freeze(['live', 'test']);

/* the op names a block uses: OP's keys, lower case ("sign", "grant_create", …) */
const OP_NAME = Object.freeze(Object.fromEntries(Object.entries(OP).map(([k, v]) => [v, k.toLowerCase()])));
const OP_CODE = Object.freeze(Object.fromEntries(Object.entries(OP_NAME).map(([v, k]) => [k, Number(v)])));

/* ---- canonical JSON (the strict subset) ---- */

function canonical(value) {
  const out = [];
  write(value, out, '$');
  return out.join('');
}

function write(v, out, at) {
  if (v === null || v === true || v === false) { out.push(String(v)); return; }
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new TypeError(`edge block: ${at} is not a safe integer (${v}) - blocks hold integers only`);
    out.push(String(v));
    return;
  }
  if (typeof v === 'string') { out.push(str(v, at)); return; }
  if (Array.isArray(v)) {
    out.push('[');
    v.forEach((x, i) => { if (i) out.push(','); write(x, out, `${at}[${i}]`); });
    out.push(']');
    return;
  }
  if (typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype) {
    /* ASCII keys only, so code-unit order (RFC 8785) and byte order agree */
    const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
    out.push('{');
    keys.forEach((k, i) => {
      if (i) out.push(',');
      out.push(str(k, `${at} key`), ':');
      write(v[k], out, `${at}.${k}`);
    });
    out.push('}');
    return;
  }
  throw new TypeError(`edge block: ${at} has a value a block cannot hold (${typeof v})`);
}

function str(s, at) {
  if (!/^[\x20-\x7e]*$/.test(s)) throw new TypeError(`edge block: ${at} is not printable ASCII`);
  return `"${s.replace(/[\\"]/g, (c) => `\\${c}`)}"`;
}

function blockId(block) {
  return toHex(crypto.sha256(new TextEncoder().encode(canonical(block))));
}

/* ---- one link <-> its fields ---- */

const hex = (b) => toHex(Uint8Array.from(b));

function linkFields(bytes) {
  const d = chain.decodeLink(bytes);
  const name = OP_NAME[d.op];
  if (!name) throw new TypeError(`edge block: link ${d.seq} has an op this library does not know (${d.op})`);
  const f = {
    seq: d.seq,
    op: name,
    decision: d.decision,
    slot: d.slot,
    flags: d.flags,
    subject: hex(d.subject),
    grant: d.grantId,
    step: d.grantStep,
    scope: d.scope,
    intent: d.intent ? hex(d.intent) : null,
    v: d.version,
  };
  /* the fields must give back the very bytes - else this link is not one the key writes */
  if (toHex(linkBytes(f)) !== toHex(bytes)) {
    throw new TypeError(`edge block: link ${d.seq} has bytes its fields cannot carry (reserved bytes not zero)`);
  }
  return f;
}

function linkBytes(f) {
  const op = OP_CODE[f.op];
  if (op === undefined) throw new TypeError(`edge block: link ${f.seq} names an unknown op "${f.op}"`);
  return chain.encodeLink({
    seq: f.seq,
    op,
    decision: f.decision,
    slot: f.slot,
    flags: f.flags,
    subject: fromHex(f.subject),
    grantId: f.grant,
    grantStep: f.step,
    scope: f.scope,
    intent: f.intent ? fromHex(f.intent) : undefined,
    version: f.v,
  });
}

/* ---- build ---- */

/**
 * One block: the links between two seals, and the seal.
 *
 * @param {object} o
 * @param {'live'|'test'} o.net
 * @param {Uint8Array} o.deviceId           16 bytes
 * @param {{seq: number, head: Uint8Array}} o.start  the head BEFORE the first link: the
 *   previous block's checkpoint, or genesis (seq = the first link's seq)
 * @param {string|null} o.prev               the previous block's id (hex), null for the first
 * @param {Uint8Array[]} o.links             64-byte links, in seq order, ending at the checkpoint
 * @param {{seq: number, head: Uint8Array, signature: Uint8Array}} o.checkpoint  the key's seal
 * @param {{deviceId, seq, head, signature}[]} [o.seen]  the sibling checkpoints this block's
 *   ANCHOR links record (each must match an ANCHOR link's subject)
 */
function buildBlock({ net, deviceId, start, prev = null, links, checkpoint, seen = [] }) {
  if (!NETS.includes(net)) throw new TypeError(`edge block: net must be ${NETS.join(' or ')}`);
  const block = {
    v: BLOCK_VERSION,
    net,
    device: hex(deviceId),
    prev,
    start: { seq: start.seq, head: hex(start.head) },
    links: links.map((l) => linkFields(Uint8Array.from(l))),
    checkpoint: { seq: checkpoint.seq, head: hex(checkpoint.head), sig: hex(checkpoint.signature) },
    seen: seen.map((s) => ({ device: hex(s.deviceId), seq: s.seq, head: hex(s.head), sig: hex(s.signature) })),
  };
  canonical(block); /* throws now, not when someone first hashes it */
  return block;
}

/* ---- a copy -> its blocks ---- */

/**
 * The blocks a copy holds: its links cut at its seals, each block naming the one
 * before it. A copy that does not reach back to its chain's start (genesis, or a
 * CONTINUE link) cannot say what came before, so it gives no blocks - after the
 * clean start every copy is whole from genesis.
 *
 * @param {object} o
 * @param {'live'|'test'} o.net
 * @param {Uint8Array} o.deviceId
 * @param {{link: Uint8Array}[]} o.records  the copy, in seq order
 * @param {{seq, head, signature}[]} o.seals  the key's checkpoints taken when a block closed
 * @param {{deviceId, seq, head, signature}[]} [o.seen]  sibling checkpoints this chain anchored
 * -> {blocks, open (links after the last seal), reason?}
 */
function blocksFrom({ net, deviceId, records, seals, seen = [] }) {
  const recs = (records || []).map((r) => Uint8Array.from(r.link || r));
  if (!recs.length) return { blocks: [], open: 0 };
  const startAt = chain.chainStart(recs.map((link) => ({ link })), deviceId);
  if (chain.decodeLink(recs[0]).seq !== startAt.fromSeq) {
    return { blocks: [], open: recs.length, reason: `the copy starts at #${chain.decodeLink(recs[0]).seq}, not at its chain's start` };
  }
  const bySeq = new Map(recs.map((l) => [chain.decodeLink(l).seq, l]));
  const anchorOf = new Map(seen.map((s) => [hex(anchorSubject(s)), s]));
  const blocks = [];
  let start = { seq: startAt.fromSeq, head: startAt.fromHead };
  let prev = null;
  for (const s of [...seals].sort((a, b) => a.seq - b.seq)) {
    if (s.seq < start.seq) continue;
    const links = [];
    for (let q = start.seq; q <= s.seq; q += 1) {
      if (!bySeq.has(q)) return { blocks, open: recs.length - countUpTo(blocks), reason: `the copy has no link #${q}` };
      links.push(bySeq.get(q));
    }
    const mine = links.filter((l) => chain.decodeLink(l).op === OP.ANCHOR).map((l) => anchorOf.get(hex(chain.decodeLink(l).subject))).filter(Boolean);
    const b = buildBlock({ net, deviceId, start, prev, links, checkpoint: { seq: s.seq, head: Uint8Array.from(s.head), signature: Uint8Array.from(s.signature) }, seen: mine });
    blocks.push(b);
    prev = blockId(b);
    start = { seq: s.seq + 1, head: Uint8Array.from(s.head) };
  }
  return { blocks, open: recs.length - countUpTo(blocks) };
}

const countUpTo = (blocks) => blocks.reduce((n, b) => n + b.links.length, 0);

/* ---- verify ---- */

/**
 * Check a block on its own terms, trusting only `publicKey` (the device's Edge
 * key, read from the key). With `prevBlock`, also check it continues that block.
 * -> {ok: true, id} or {ok: false, reason}
 *
 * @param {object} block
 * @param {Uint8Array} publicKey  the device's Edge public key (X||Y), from the key
 * @param {object|null} [prevBlock]
 * @returns {{ok: boolean, id?: string, reason?: string}}
 */
function verifyBlock(block, publicKey, prevBlock = null) {
  const fail = (reason) => ({ ok: false, reason });
  try {
    if (!block || block.v !== BLOCK_VERSION) return fail('version');
    if (!NETS.includes(block.net)) return fail('net');
    const id = blockId(block);
    const deviceId = chain.deviceIdOf(publicKey);
    if (hex(deviceId) !== block.device) return fail('device');

    const start = { seq: block.start.seq, head: fromHex(block.start.head) };
    if (prevBlock) {
      if (block.prev !== blockId(prevBlock)) return fail('prev');
      if (prevBlock.device !== block.device || prevBlock.net !== block.net) return fail('prev');
      if (block.start.head !== prevBlock.checkpoint.head || block.start.seq !== prevBlock.checkpoint.seq + 1) return fail('prev');
    } else if (block.prev === null) {
      /* the first block starts at genesis (a CONTINUE chain starts at its first link's seq) */
      if (toHex(start.head) !== toHex(chain.genesis(deviceId))) return fail('genesis');
    }

    let head = start.head;
    let seq = start.seq;
    const anchors = new Set();
    for (const f of block.links) {
      if (f.seq !== seq) return fail('seq');
      const bytes = linkBytes(f);
      linkFields(bytes); /* throws on a link the key would not write */
      head = chain.weld(head, bytes);
      if (f.op === 'anchor') anchors.add(f.subject);
      seq += 1;
    }
    /* the seal sits on the last link (an empty block: on the head it started from) */
    if (seq - 1 !== block.checkpoint.seq) return fail('checkpoint');
    if (toHex(head) !== block.checkpoint.head) return fail('checkpoint');
    const fields = { deviceId, seq: block.checkpoint.seq, head: fromHex(block.checkpoint.head) };
    if (!chain.verifyCheckpoint(fields, fromHex(block.checkpoint.sig), publicKey)) return fail('signature');

    for (const s of block.seen) {
      const subject = anchorSubject({ deviceId: fromHex(s.device), seq: s.seq, head: fromHex(s.head), signature: fromHex(s.sig) });
      if (!anchors.has(hex(subject))) return fail('seen');
    }
    return { ok: true, id };
  } catch (e) {
    return fail(`malformed: ${e.message}`);
  }
}

module.exports = { BLOCK_VERSION, NETS, canonical, blockId, buildBlock, blocksFrom, verifyBlock, linkFields, linkBytes };
