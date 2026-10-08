'use strict';

/**
 * `okedge sync`, phase 1 (onlykey-edge build/mcp-service.md §4.2b; spec session
 * 2026-10-04): the PC keeps its OWN copy of the key's chain. It reads the links
 * the key still holds (PICKUP - a read the key answers unlocked, R8, so no press)
 * and keeps them only after the whole copy verifies against the key (R27).
 *
 * Phase 1 moves nothing anywhere else: no phone copy, no Key Chain list, no other
 * device, no ANCHOR - those change something, and need a sheet + Yes + a press
 * (phase 2). It never moves budgets, debts, agent registrations or "yours" marks,
 * and it REPORTS problems (a gap, a fork, tampering); it never repairs them - the
 * repairs stay on the phone.
 *
 * The copy: <edge home>/copy-<device id, 16 hex>.json
 *   {deviceId, links: [{link, head, reveal?}] (hex), lastSeen: {seq, head} | null,
 *    publicKey, seals: [{seq, head, signature}], seen: [{deviceId, seq, head, signature}]}
 * publicKey is the key's Edge key as the key gave it at the last sync; seals and seen
 * come from the phone (it takes a seal when a budget ends) and cut the copy into
 * JSON blocks (BLOCKS.md §3) - each checked against that key, nothing trusted.
 */
const fs = require('fs');
const path = require('path');
const { chain, copy: copyLib } = require('../src');
const { toHex, fromHex } = require('../../src/bytes');

const PICKUP_MAX = 8;
const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const seqOf = (r) => chain.decodeLink(r.link).seq;

function copyFile(home, deviceId) {
  return path.join(home, `copy-${toHex(deviceId).slice(0, 16)}.json`);
}

function load(home, deviceId) {
  const f = copyFile(home, deviceId);
  if (!fs.existsSync(f)) return { deviceId, links: [], lastSeen: null, publicKey: null, seals: [], seen: [] };
  const s = JSON.parse(fs.readFileSync(f, 'utf8'));
  /* version 1 since the clean start: an older copy is the old chain's - read as no copy */
  if (s.v !== 1) return { deviceId, links: [], lastSeen: null, publicKey: null, seals: [], seen: [] };
  return {
    deviceId,
    links: s.links.map((l) => ({ link: fromHex(l.link), head: fromHex(l.head), ...(l.reveal ? { reveal: fromHex(l.reveal) } : {}) })),
    lastSeen: s.lastSeen ? { seq: s.lastSeen.seq, head: fromHex(s.lastSeen.head) } : null,
    publicKey: s.publicKey ? fromHex(s.publicKey) : null,
    seals: (s.seals || []).map((x) => ({ seq: x.seq, head: fromHex(x.head), signature: fromHex(x.signature) })),
    seen: (s.seen || []).map((x) => ({ deviceId: fromHex(x.deviceId), seq: x.seq, head: fromHex(x.head), signature: fromHex(x.signature) })),
  };
}

function save(home, c) {
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  const s = {
    v: 1,
    deviceId: toHex(c.deviceId),
    links: c.links.map((l) => ({ link: toHex(l.link), head: toHex(l.head), ...(l.reveal ? { reveal: toHex(l.reveal) } : {}) })),
    lastSeen: c.lastSeen ? { seq: c.lastSeen.seq, head: toHex(c.lastSeen.head) } : null,
    ...(c.publicKey ? { publicKey: toHex(c.publicKey) } : {}),
    seals: (c.seals || []).map((x) => ({ seq: x.seq, head: toHex(x.head), signature: toHex(x.signature) })),
    seen: (c.seen || []).map((x) => ({ deviceId: toHex(x.deviceId), seq: x.seq, head: toHex(x.head), signature: toHex(x.signature) })),
  };
  fs.writeFileSync(copyFile(home, c.deviceId), JSON.stringify(s, null, 1) + '\n', { mode: 0o600 });
}

/*
 * Does `r` belong after `prev`? A link the key wrote has bytes 47-63 zero (R3); the
 * very next seq must weld from prev's head (the phone's rule, ok-rn edgeStore - a
 * stray reply was once stored as a link there, 2026-10-04).
 */
function follows(prev, r) {
  let f;
  try { f = chain.decodeLink(r.link); } catch { return false; }
  if (!f.reservedZero) return false;
  if (!prev) return true;
  const p = seqOf(prev);
  if (f.seq <= p) return false;
  return f.seq !== p + 1 || sameBytes(chain.weld(prev.head, r.link), r.head);
}

/* the verdict, in words: verified / gap / tampered (fork, rollback, edited) */
function verdictOf(a) {
  const v = a.chain;
  if (v.failure || (v.failures && v.failures.length)) {
    const f = v.failure || v.failures[0];
    return { kind: 'tampered', seq: f.seq, reason: f.reason };
  }
  if (a.open && a.open.length) return { kind: 'gap', gaps: a.open };
  return { kind: 'verified', through: v.verifiedThrough };
}

/**
 * Bring the PC's copy up to the key's head (status: read and report only).
 * edge: the Edge plugin (head, pickup, publicKey). -> a report; changes only the
 * PC's copy file, and only when what it would store verifies (no tampering).
 */
async function sync(edge, home, { status = false } = {}) {
  const { publicKey, deviceId } = await edge.publicKey();
  const c = load(home, deviceId);
  const h = await edge.head();
  const keySeq = h.seq === null ? -1 : h.seq;
  const ringFrom = h.oldest === null ? keySeq + 1 : h.oldest;
  const candidate = { ...c, links: [...c.links], publicKey };
  let stopped = null;
  /*
   * --status reads too (reads change nothing, R8) and only skips the save: a copy
   * that has not read the newest links yet is behind, not tampered - judging it
   * without them said "does not verify: seq-gap" for a fresh copy (2026-10-04).
   */
  {
    const last = candidate.links.length ? seqOf(candidate.links[candidate.links.length - 1]) : -1;
    for (let from = Math.max(last + 1, ringFrom); from <= keySeq;) {
      const got = await edge.pickup(from, Math.min(PICKUP_MAX, keySeq - from + 1));
      if (!got.length) break;
      for (const r of got) {
        const prev = candidate.links[candidate.links.length - 1];
        if (follows(prev, r)) candidate.links.push(r);
        else if (!prev || seqOf(r) > seqOf(prev)) { stopped = seqOf(r); break; }
      }
      if (stopped !== null) break;
      from = seqOf(got[got.length - 1]) + 1;
    }
  }
  const held = keySeq < 0 || h.oldest === null ? [] : await edge.pickup(h.oldest, Math.min(PICKUP_MAX, keySeq - h.oldest + 1));
  const a = copyLib.assess({ links: candidate.links }, { publicKey, head: { seq: keySeq, head: h.head }, held }, {
    ringFrom, ...(candidate.lastSeen ? { lastSeen: candidate.lastSeen } : {}),
  });
  const verdict = verdictOf(a);
  const added = candidate.links.length - c.links.length;
  let saved = false;
  /* R27 before storing: a copy that does not verify is reported, not kept */
  if (!status && verdict.kind !== 'tampered') {
    if (verdict.kind === 'verified' || verdict.kind === 'gap') candidate.lastSeen = { seq: keySeq, head: h.head };
    save(home, candidate);
    saved = true;
  }
  const newest = candidate.links.length ? seqOf(candidate.links[candidate.links.length - 1]) : null;
  return {
    deviceId: toHex(deviceId),
    key: { seq: keySeq, head: toHex(h.head), ringFrom },
    copy: { file: copyFile(home, deviceId), count: candidate.links.length, newest, added, saved },
    verdict,
    stoppedAt: stopped,
  };
}

/** Lines for the terminal. */
function lines(r, { status = false } = {}) {
  const out = [];
  out.push(`key ${r.deviceId.slice(0, 16)}: head #${r.key.seq} (${r.key.head.slice(0, 12)}...), holds #${r.key.ringFrom}..#${r.key.seq}`);
  out.push(`PC copy: ${r.copy.count - (status ? r.copy.added : 0)} link(s)${status ? (r.copy.added ? `, ${r.copy.added} to read (okedge sync)` : ', up to date') : `, ${r.copy.added} new${r.copy.saved ? '' : ' - NOT kept'}`}`);
  const v = r.verdict;
  if (v.kind === 'verified') out.push(`verified through #${v.through}`);
  else if (v.kind === 'gap') out.push(`gap: ${v.gaps.map((g) => (g.from === g.to ? `#${g.from}` : `#${g.from}-#${g.to}`)).join(', ')} - links no copy here holds (repairs are the phone's)`);
  else out.push(`DOES NOT VERIFY at #${v.seq}: ${v.reason} - reported, nothing kept (repairs are the phone's)`);
  if (r.stoppedAt !== null && r.stoppedAt !== undefined) out.push(`stopped at #${r.stoppedAt}: a reply that does not weld onto the copy`);
  /* phase 2: what the phone took (the sheet, Yes, a press, its sync link) */
  const p = r.phone;
  if (p && p.skipped) out.push(`phone: not offered - ${p.skipped}`);
  else if (p && p.refused) out.push(`phone: ${p.refused}`);
  else if (p && p.seq === null) out.push('phone: lacks nothing this PC holds, and the Key Chain lists already match');
  else if (p) {
    out.push(`phone: took ${p.count} link(s) and ${p.keychainIn || 0} Key Chain entr${p.keychainIn === 1 ? 'y' : 'ies'} - the key recorded the sync as #${p.seq}`);
    if (p.keychainSaved === false) out.push(`Key Chain: the merged list dropped ${p.keychainMissing.length} of this PC's entries - NOT saved (${p.keychainMissing.join(', ')})`);
    else if (p.keychainOut) out.push(`Key Chain: this PC took ${p.keychainOut} entr${p.keychainOut === 1 ? 'y' : 'ies'} - ${p.keychain} in the list now`);
  }
  /* the seals that cut the copy into JSON blocks (BLOCKS.md §3; read on their own, no press) */
  if (r.blocks) out.push(`seals: ${r.blocks.seals} kept with this copy - onlykey-js edge blocks shows the blocks`);
  else if (r.blocksError) out.push(`seals: not read - ${r.blocksError}`);
  return out;
}

/*
 * Phase 2 (R20, P2a): this PC's copy store is a PLACE THAT KEEPS COPIES, with its
 * own P-256 key: <edge home>/peer.key (made on first use, this user only, like
 * agent.key). The key adds it as a known peer with the person's Yes and a press;
 * from then on a sync may send copies here, and at E5 this key signs the store's
 * receipts. It is not the agent's key: the agent asks for budgets, the store
 * keeps copies - and the store, being on the agent's own machine, never counts
 * toward k for this PC's budgets (R20, Brad 2026-10-05).
 */
function peerSigner(home) {
  const { request } = require('../src');
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  const file = path.join(home, 'peer.key');
  if (!fs.existsSync(file)) {
    const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
    fs.writeFileSync(file, toHex(p256.utils.randomSecretKey()) + '\n', { mode: 0o600 });
  }
  return request.peerSignerFromSecret(fromHex(fs.readFileSync(file, 'utf8').trim()));
}

/*
 * The phone's seals and the sibling checkpoints this chain anchored (GIVE's last
 * batch, client.sealsFromPhone), kept beside the copy. Merged by seq: the phone
 * may hold fewer than this PC already kept.
 */
function keepSeals(home, deviceId, { seals = [], seen = [] }) {
  const c = load(home, deviceId);
  const bySeq = new Map(c.seals.map((x) => [x.seq, x]));
  for (const x of seals) bySeq.set(x.seq, x);
  c.seals = [...bySeq.values()].sort((a, b) => a.seq - b.seq);
  const key = (x) => `${toHex(x.deviceId)}:${x.seq}`;
  const seenBy = new Map(c.seen.map((x) => [key(x), x]));
  for (const x of seen) seenBy.set(key(x), x);
  c.seen = [...seenBy.values()];
  save(home, c);
  return { seals: c.seals.length, seen: c.seen.length };
}

/*
 * Every copy in this home as JSON blocks (edge/src/block.js), each block checked
 * against the key's public key kept at the last sync and against the block before
 * it. -> [{deviceId, blocks: [{block, id, ok, reason?}], open, reason?}]
 */
function blocks(home, { net }) {
  const { block } = require('../src');
  if (!fs.existsSync(home)) return [];
  return fs.readdirSync(home).filter((n) => /^copy-[0-9a-f]{16}\.json$/.test(n)).map((n) => {
    const s = JSON.parse(fs.readFileSync(path.join(home, n), 'utf8'));
    const c = load(home, fromHex(s.deviceId));
    const r = block.blocksFrom({ net, deviceId: c.deviceId, records: c.links, seals: c.seals, seen: c.seen });
    const out = [];
    for (const b of r.blocks) {
      const v = c.publicKey ? block.verifyBlock(b, c.publicKey, out.length ? out[out.length - 1].block : null) : { ok: false, reason: 'no public key kept - run onlykey-js edge sync' };
      out.push({ block: b, id: block.blockId(b), ok: v.ok, ...(v.ok ? {} : { reason: v.reason }) });
    }
    return { deviceId: toHex(c.deviceId), blocks: out, open: r.open, ...(r.reason ? { reason: r.reason } : {}) };
  });
}

module.exports = { sync, lines, load, copyFile, peerSigner, keepSeals, blocks };
