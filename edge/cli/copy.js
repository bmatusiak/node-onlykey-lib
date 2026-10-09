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
 *    publicKey, seals: [{seq, head, signature}], checkpoint?, statement?}
 * One file per device: this phone's key, and since 2026-10-08 your OTHER devices' logs too
 * (each phone synced in turn, a hard key's later), each with that device's signed checkpoint and its
 * owner statement (nametag) - what this computer offers your phones to merge.
 * publicKey is the key's Edge key as the key gave it at the last sync; seals
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
  if (!fs.existsSync(f)) return { deviceId, links: [], lastSeen: null, publicKey: null, seals: [], checkpoint: null, statement: null, openings: [] };
  const s = JSON.parse(fs.readFileSync(f, 'utf8'));
  /* version 1 since the clean start: an older copy is the old chain's - read as no copy */
  if (s.v !== 1) return { deviceId, links: [], lastSeen: null, publicKey: null, seals: [], checkpoint: null, statement: null, openings: [] };
  return {
    deviceId,
    links: s.links.map((l) => ({ link: fromHex(l.link), head: fromHex(l.head), ...(l.reveal ? { reveal: fromHex(l.reveal) } : {}) })),
    lastSeen: s.lastSeen ? { seq: s.lastSeen.seq, head: fromHex(s.lastSeen.head) } : null,
    publicKey: s.publicKey ? fromHex(s.publicKey) : null,
    seals: (s.seals || []).map((x) => ({ seq: x.seq, head: fromHex(x.head), signature: fromHex(x.signature) })),
    openings: Array.isArray(s.openings) ? s.openings : [],
    notes: s.notes && typeof s.notes === 'object' ? s.notes : { reasons: {}, messages: {} },
    checkpoint: s.checkpoint ? { seq: s.checkpoint.seq, head: fromHex(s.checkpoint.head), signature: fromHex(s.checkpoint.signature) } : null,
    statement: s.statement ? { deviceId: fromHex(s.statement.deviceId), publicKey: fromHex(s.statement.publicKey), seq: s.statement.seq ?? null, nametag: s.statement.nametag, signature: fromHex(s.statement.signature) } : null,
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
    ...(c.openings && c.openings.length ? { openings: c.openings } : {}),
    ...(c.notes ? { notes: c.notes } : {}),
    ...(c.checkpoint ? { checkpoint: { seq: c.checkpoint.seq, head: toHex(c.checkpoint.head), signature: toHex(c.checkpoint.signature) } } : {}),
    ...(c.statement ? { statement: { deviceId: toHex(c.statement.deviceId), publicKey: toHex(c.statement.publicKey), seq: c.statement.seq ?? null, nametag: c.statement.nametag, signature: toHex(c.statement.signature) } } : {}),
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
async function sync(edge, home, { status = false, history = null } = {}) {
  const { publicKey, deviceId } = await edge.publicKey();
  const c = load(home, deviceId);
  const h = await edge.head();
  const keySeq = h.seq === null ? -1 : h.seq;
  const ringFrom = h.oldest === null ? keySeq + 1 : h.oldest;
  const candidate = { ...c, links: [...c.links], publicKey };
  let stopped = null;
  /*
   * THE PHONE'S HISTORY FILLS A GAP (2026-10-08, walking the setup flow): the key's ring holds
   * only its newest links, so a computer that joins late - or whose copy was reset - began at
   * the ring and could never check the chain from its genesis, so it never kept the phone's
   * statement and never offered its log. `history`: the phone's own copy (client.copyFromPhone).
   * Taken only as a run that follows from the start; assess() below then judges ALL of it
   * against the KEY's head and ring - a link that does not weld onto the key's own chain makes
   * the copy "does not verify", and nothing is kept.
   */
  if (history && history.length && (!candidate.links.length || seqOf(candidate.links[0]) > 0)) {
    const run = [];
    for (const r of [...history].sort((x, y) => seqOf(x) - seqOf(y))) {
      const prev = run[run.length - 1];
      if (!prev ? seqOf(r) === 0 && follows(null, r) : seqOf(r) === seqOf(prev) + 1 && follows(prev, r)) run.push(r);
      else if (prev && seqOf(r) <= seqOf(prev)) continue;
      else break;
    }
    const after = run.length ? seqOf(run[run.length - 1]) : -1;
    const rest = candidate.links.filter((r) => seqOf(r) > after);
    if (run.length && (!rest.length || follows(run[run.length - 1], rest[0]))) candidate.links = [...run, ...rest];
  }
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
  /* phase 2: what the phone took of its own chain (no sheet, no press, no link since 2026-10-08) */
  const p = r.phone;
  if (p && p.skipped) out.push(`phone: not offered - ${p.skipped}`);
  else if (p && p.refused) out.push(`phone: ${p.refused}`);
  else if (p && !p.count) out.push('phone: lacks nothing this PC holds');
  else if (p) out.push(`phone: took ${p.count} link(s)`);
  /* whether this computer can now offer this phone's log to your other devices (keepLog) */
  if (r.log) out.push(r.log.kept ? 'log: kept to offer to your other devices' : `log: not kept to offer - ${r.log.why}`);
  /* the seals that cut the copy into JSON blocks (BLOCKS.md §3; read on their own, no press) */
  if (r.blocks) out.push(`seals: ${r.blocks.seals} kept with this copy - onlykey-js edge blocks shows the blocks`);
  else if (r.blocksError) out.push(`seals: not read - ${r.blocksError}`);
  /* your other devices' logs this PC holds, offered to the phone - held there until you approve (2026-10-08) */
  for (const o of r.offered || []) {
    const who = `"${o.nametag}" (${o.deviceId.slice(0, 16)})`;
    out.push(o.error ? `offered ${who}: ${o.error}` : `offered ${who}: ${o.count} link(s) - held on the phone until you approve the merge (Edge tab banner)`);
  }
  return out;
}

/*
 * This computer's own sync key: <edge home>/peer.key, P-256 (made on first use, this
 * user only). It signs every sync message, so the phone knows which
 * computer offered a log. It is not the agent's key: the agent asks for budgets, the
 * store keeps copies. No peer list on the key or the phone since 2026-10-08 (Brad:
 * peers dropped) - a computer the person approved for Bluetooth may offer logs, and
 * the phone holds them until the person approves the merge.
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
 * The phone's seals (GIVE's last
 * batch, client.sealsFromPhone), kept beside the copy. Merged by seq: the phone
 * may hold fewer than this PC already kept.
 */
function keepSeals(home, deviceId, { seals = [] }) {
  const c = load(home, deviceId);
  const bySeq = new Map(c.seals.map((x) => [x.seq, x]));
  for (const x of seals) bySeq.set(x.seq, x);
  c.seals = [...bySeq.values()].sort((a, b) => a.seq - b.seq);
  save(home, c);
  return { seals: c.seals.length };
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
    const r = block.blocksFrom({ net, deviceId: c.deviceId, records: c.links, seals: c.seals });
    const out = [];
    for (const b of r.blocks) {
      const v = c.publicKey ? block.verifyBlock(b, c.publicKey, out.length ? out[out.length - 1].block : null) : { ok: false, reason: 'no public key kept - run onlykey-js edge sync' };
      out.push({ block: b, id: block.blockId(b), ok: v.ok, ...(v.ok ? {} : { reason: v.reason }) });
    }
    return { deviceId: toHex(c.deviceId), blocks: out, open: r.open, ...(r.reason ? { reason: r.reason } : {}) };
  });
}

/*
 * ANOTHER DEVICE'S LOG, kept on this computer (2026-10-08): its links up to its signed
 * checkpoint and its owner statement, as read from that device or its phone. Kept only
 * when its chain checks under its own key (sync.anchorCheck) and the statement names that
 * key; a newer checkpoint replaces an older one, never the other way round. Whether it is
 * YOURS is each phone's call (devices.classify, with its owner key) - this file only keeps it.
 * -> {kept: true} | {kept: false, why}
 */
function keepLog(home, { deviceId, publicKey, records, checkpoint, statement }) {
  const { sync: syncLib } = require('../src');
  const id = Uint8Array.from(deviceId);
  if (!statement || toHex(statement.deviceId) !== toHex(id) || toHex(statement.publicKey) !== toHex(publicKey)) return { kept: false, why: 'the statement does not name this device' };
  /* nothing to merge yet: a device whose key has no link is not kept or offered (an older app's check would read NO_SEQ as a seq) */
  if (checkpoint.seq === syncLib.NO_SEQ || !records.length) return { kept: false, why: 'its key has no link yet' };
  const check = syncLib.anchorCheck({ records, publicKey: Uint8Array.from(publicKey), checkpoint, anchors: [] });
  if (!check.ok) return { kept: false, why: `its chain does not check (${check.alarm}${check.detail ? `: ${check.detail}` : ''})` };
  const c = load(home, id);
  if (c.checkpoint && c.checkpoint.seq > checkpoint.seq) return { kept: false, why: `this computer already holds it up to #${c.checkpoint.seq}` };
  /* complete before it is kept to offer: every use's words and result, checked against the chain (devices.completeness) */
  const full = require('../src').devices.completeness({ deviceId: id, publicKey, records: records.filter((r) => seqOf(r) <= checkpoint.seq), openings: c.openings || [], notes: c.notes || null });
  if (!full.ok) return { kept: false, why: `not complete - ${full.missing.slice(0, 3).join('; ')}${full.missing.length > 3 ? ` (+${full.missing.length - 3} more)` : ''}` };
  c.publicKey = Uint8Array.from(publicKey);
  c.links = records.filter((r) => seqOf(r) <= checkpoint.seq).map((r) => ({ link: Uint8Array.from(r.link), head: Uint8Array.from(r.head), ...(r.reveal ? { reveal: Uint8Array.from(r.reveal) } : {}) }));
  c.checkpoint = checkpoint;
  if (!c.statement || (statement.seq ?? -1) >= (c.statement.seq ?? -1)) c.statement = statement;
  save(home, c);
  return { kept: true };
}

/** Every log this computer can offer, but the one of `exceptId` (the phone being synced): those with a checkpoint and a statement. */
function logsToOffer(home, exceptId) {
  if (!fs.existsSync(home)) return [];
  const skip = exceptId ? toHex(exceptId).slice(0, 16) : null;
  return fs.readdirSync(home)
    .filter((n) => /^copy-[0-9a-f]{16}\.json$/.test(n) && n.slice(5, 21) !== skip)
    .map((n) => JSON.parse(fs.readFileSync(path.join(home, n), 'utf8')))
    .filter((j) => j.v === 1 && j.checkpoint && j.statement)
    .map((j) => load(home, fromHex(j.deviceId)));
}

/**
 * The budgets' opening words a phone gave (full cards on your other devices - Brad, 2026-10-09):
 * kept only those that check against this copy's own links (devices.checkOpenings), merged by
 * budget. -> {kept: n, of: given}
 */
function keepOpenings(home, deviceId, openings) {
  const { devices } = require('../src');
  const c = load(home, Uint8Array.from(deviceId));
  if (!c.publicKey || !c.links.length) return { kept: 0, of: (openings || []).length };
  const good = devices.checkOpenings({ deviceId, publicKey: c.publicKey, records: c.links, openings });
  const byId = new Map((c.openings || []).map((o) => [o.grantId, o]));
  for (const o of good) byId.set(o.grantId, o);
  c.openings = [...byId.values()].sort((a, b) => a.grantId - b.grantId);
  save(home, c);
  return { kept: good.length, of: (openings || []).length };
}

/** A phone's notes (intents, receipt messages by seq), kept with its copy and merged - checked against the chain where they are shown. */
function keepNotes(home, deviceId, notes) {
  const { devices } = require('../src');
  const c = load(home, Uint8Array.from(deviceId));
  const got = devices.shapeNotes(notes);
  const was = c.notes || { reasons: {}, messages: {} };
  c.notes = { reasons: { ...was.reasons, ...got.reasons }, messages: { ...was.messages, ...got.messages }, seen: { ...(was.seen || {}), ...got.seen } };
  save(home, c);
  return { reasons: Object.keys(got.reasons).length, messages: Object.keys(got.messages).length };
}

module.exports = { sync, lines, load, copyFile, peerSigner, keepSeals, keepLog, logsToOffer, blocks, keepOpenings, keepNotes };
