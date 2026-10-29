'use strict';

/**
 * `onlykey-js edge sync` (onlykey-edge BLOCKS.md): the PC keeps its OWN copy of the key's chain. It reads the links
 * the key still holds (PICKUP - a read the key answers unlocked, R8, so no press)
 * and keeps them only after the whole copy verifies against the key (R27).
 *
 * Reading the key moves nothing anywhere else. Phase 2 (sync.js, client.js) brings
 * a phone its own links (merged at once, no press) and offers it your other
 * devices' logs (HELD on the phone until approved from a banner); until 2026-10-08
 * that took a sheet + Yes + a press and the key kept anchors. It never moves
 * budgets, debts or "yours" marks,
 * and it REPORTS problems (a gap, a fork, tampering); it never repairs them - the
 * repairs stay on the phone.
 *
 * The copy: the CLI's bucket, the home's `copies` store, key = device id (16 hex):
 *   {deviceId, links: [{link, head, reveal?}] (hex), lastSeen: {seq, head} | null,
 *    publicKey, publicKeyPq, seals: [{seq, head, signature, signaturePq?}], checkpoint?, statement?}
 * One file per device: this phone's key, and since 2026-10-08 your OTHER devices' logs too
 * (each phone synced in turn, a hard key's later), each with that device's signed checkpoint and its
 * owner statement (nametag) - what this computer offers your phones to merge.
 * publicKey is the key's Edge key as the key gave it at the last sync, publicKeyPq its
 * ML-DSA-65 twin. One hybrid anchor per copy ("B", 2026-10-10): the newest checkpoint and
 * the newest seal keep their ML-DSA-65 half and are checked with both; older seals keep
 * their P-256 half only (chain.verifyCheckpointP256); seals
 * come from the phone (it takes a seal when a budget ends) and cut the copy into
 * JSON blocks (BLOCKS.md) - each checked against that key, nothing trusted.
 */
const fs = require('fs');
const path = require('path');
const bucketHome = require('../../bucket/cli/home');
const { chain, copy: copyLib } = require('../src');
const copyfile = require('../src/copyfile');
const logblocks = require('../src/logblocks');
const { toHex, fromHex } = require('../../src/bytes');
/* a ship's progress window, when one named its file for this process: sync's parts as steps (nothing otherwise) */
const FEED = require('./progress-feed');

const PICKUP_MAX = 8;
const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const seqOf = (r) => chain.decodeLink(r.link).seq;

/*
 * The copies live in the CLI's bucket (bucket/cli/home.js): the home's `copies` store, one key
 * per device (its id, 16 hex), the copy's JSON as edge/src/copyfile.js writes it - the same
 * record every front end's bucket carries.
 */
function store(home) {
  return bucketHome.kv(bucketHome.edgeAt(home, 'copies'));
}

const keyOf = (deviceId) => toHex(deviceId).slice(0, 16);

/*
 * THE LOGS GO IN THE IDENTITY BUCKET (PROPOSAL-sync-and-identity.md Phase 1; Brad, 2026-10-29: one sync - "compare and
 * merge, newest edit time wins"): once the command knows the key's bucket identity (edge/cli/register.js, the identity
 * plugin's one read), every copy is kept in that identity's bucket, store `edge-logs` (`edge-logs-test` on the testnet),
 * as blocks (edge/src/logblocks.js) - the bucket the trade already carries to the app and the phone. Before that (a test,
 * a command that never opened a key) the copies stay where they were: the Edge home's `copies` store in bucket.json.
 * A device's log found only there is copied into the identity bucket the first time it is read - this computer's history
 * comes along; the old record is left as it was.
 */
let logs = null;
/** The identity bucket this run's Edge logs are kept in ({id, net}), or null for the Edge home's store. */
function useIdentityBucket(who) {
  logs = who && who.id ? { id: String(who.id).toLowerCase(), net: who.net === 'test' ? 'test' : 'live' } : null;
}
function logsKv() {
  const { id, net } = logs;
  if (!bucketHome.hasIdentityBucket(id, net)) bucketHome.keepIdentityBucket(id, net, require('../../bucket/src/bucket').create({ owner: id }));
  return bucketHome.kv(bucketHome.identityAt(id, net, net === 'test' ? 'edge-logs-test' : 'edge-logs'));
}
/* write a copy's blocks: only the keys that changed, in one locked write */
function saveBlocks(kv, have, json) {
  const next = logblocks.split(json);
  const changed = Object.fromEntries(Object.entries(next).filter(([k, v]) => have[k] !== v));
  if (Object.keys(changed).length) kv.setMany(changed);
}

/* where one device's copy is kept, as a person reads it: the bucket, the store and the key */
function where(home, deviceId) {
  if (logs) {
    const at = bucketHome.identityAt(logs.id, logs.net, logs.net === 'test' ? 'edge-logs-test' : 'edge-logs');
    return `${at.file} (${at.store} ${keyOf(deviceId)}.*)`;
  }
  const at = bucketHome.edgeAt(home, 'copies');
  return `${at.file} (${at.store} ${keyOf(deviceId)})`;
}

function load(home, deviceId) {
  if (logs) {
    const kv = logsKv();
    const have = kv.entries();
    const j = logblocks.join(have, toHex(deviceId));
    if (j) return copyfile.fromJSON(j, deviceId);
    const text = store(home).getItem(keyOf(deviceId));
    if (!text) return copyfile.fromJSON(null, deviceId);
    /* only in the Edge home: into the identity bucket now, so a trade carries it */
    saveBlocks(kv, have, JSON.parse(text));
    return copyfile.fromJSON(JSON.parse(text), deviceId);
  }
  const text = store(home).getItem(keyOf(deviceId));
  return copyfile.fromJSON(text ? JSON.parse(text) : null, deviceId);
}

function save(home, c) {
  if (logs) {
    const kv = logsKv();
    saveBlocks(kv, kv.entries(), copyfile.toJSON(c));
    return;
  }
  store(home).setItem(keyOf(c.deviceId), JSON.stringify(copyfile.toJSON(c)));
}

/* every copy in the home, as the JSON each was kept as - and, with the identity bucket, every log kept there */
function allJSON(home) {
  const s = store(home);
  const old = s.keys().map((k) => JSON.parse(s.getItem(k))).filter(Boolean);
  if (!logs) return old;
  const have = logsKv().entries();
  const inBucket = logblocks.devices(Object.keys(have)).map((dev) => logblocks.join(have, dev));
  const seen = new Set(inBucket.map((j) => keyOf(fromHex(j.deviceId))));
  return [...inBucket, ...old.filter((j) => j.deviceId && !seen.has(keyOf(fromHex(j.deviceId))))];
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
 * edge: the Edge plugin (head, pickup, publicKey, publicKeyPq). -> a report; changes only the
 * PC's copy file, and only when what it would store verifies (no tampering).
 */
async function sync(edge, home, { status = false, history = null } = {}) {
  /*
   * EACH PART ITS OWN STEP in a ship's progress window (progress-feed.js; Brad, 2026-10-29: "i'm trying to identify why
   * we wait, and if we can stop waiting for no reason"): what the key does (its keys, its links, its checkpoint) apart
   * from what this computer does (the check) - each with its time, so a wait shows which it is. No window: as before.
   */
  const { publicKey, deviceId, publicKeyPq, c, h } = await FEED.step('the key: its public keys and head', async () => {
    const pk = await edge.publicKey();
    /* the ML-DSA-65 twin of the checkpoint key: every checkpoint and seal of this chain is checked under both */
    const pq = await edge.publicKeyPq('checkpoint');
    return { publicKey: pk.publicKey, deviceId: pk.deviceId, publicKeyPq: pq, c: load(home, pk.deviceId), h: await edge.head() };
  });
  const keySeq = h.seq === null ? -1 : h.seq;
  const ringFrom = h.oldest === null ? keySeq + 1 : h.oldest;
  const candidate = { ...c, links: [...c.links], publicKey, publicKeyPq };
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
  /*
   * A GAP IN THE MIDDLE IS FILLED THE SAME WAY (2026-10-11, the two-phone testnet walk): a copy that
   * began at #0 and then missed links between two syncs (#4-#38 made while this computer was away)
   * kept the gap for good - the fill ran only for a copy that did not start at #0 - so the log it
   * offered to the other devices was incomplete and showed there as "not checked yet". The run
   * from the phone's history replaces the copy's own links up to where it ends; assess() still
   * judges all of it against the key.
   */
  if (history && history.length) {
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
    const start = Math.max(last + 1, ringFrom);
    const total = keySeq - start + 1;
    if (total > 0) {
      await FEED.step(`the key: reading ${total} new link(s)`, async () => {
        for (let from = start; from <= keySeq;) {
          const got = await edge.pickup(from, Math.min(PICKUP_MAX, keySeq - from + 1));
          if (!got.length) break;
          for (const r of got) {
            const prev = candidate.links[candidate.links.length - 1];
            if (follows(prev, r)) candidate.links.push(r);
            else if (!prev || seqOf(r) > seqOf(prev)) { stopped = seqOf(r); break; }
          }
          if (stopped !== null) break;
          from = seqOf(got[got.length - 1]) + 1;
          FEED.part(Math.min(total, from - start), total);
        }
      });
    }
  }
  const held = keySeq < 0 || h.oldest === null ? []
    : await FEED.step('the key: reading the links it still holds', () => edge.pickup(h.oldest, Math.min(PICKUP_MAX, keySeq - h.oldest + 1)));
  const a = await FEED.step(`this computer: checking ${candidate.links.length} link(s) - every weld, each budget's signature`, () => copyLib.assess({ links: candidate.links }, { publicKey, publicKeyPq, head: { seq: keySeq, head: h.head }, held }, {
    ringFrom, ...(candidate.lastSeen ? { lastSeen: candidate.lastSeen } : {}),
  }));
  let verdict = verdictOf(a);
  /*
   * VERIFIED NEEDS THE KEY'S SIGNATURE (Brad, 2026-10-11: "checking every field in a token means
   * nothing if we never check the signature"). The welds only prove the links lead to the head
   * the key reported over this link; its checkpoint for that head, verified with both halves
   * (P-256 + ML-DSA-65), proves the key signed it. No checkpoint, one for another head, or one
   * that does not verify: "unsigned" - reported, never "verified".
   */
  if (verdict.kind === 'verified' && keySeq >= 0) {
    const cp = await FEED.step(`the key: signing its checkpoint for #${keySeq}`, () => edge.checkpoint().catch(() => null));
    const signed = await FEED.step('this computer: checking that signature (P-256 + ML-DSA-65)', () => {
      try {
        return !!cp && cp.seq === keySeq && toHex(cp.head) === toHex(h.head)
          && chain.verifyCheckpoint({ deviceId, seq: cp.seq, head: cp.head }, cp.signature, publicKey, cp.signaturePq || null, publicKeyPq);
      } catch { return false; }
    });
    if (!signed) verdict = { kind: 'unsigned', through: verdict.through };
  }
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
    copy: { file: where(home, deviceId), count: candidate.links.length, newest, added, saved },
    verdict,
    stoppedAt: stopped,
  };
}

/** Lines for the terminal. */
function lines(r, { status = false } = {}) {
  const out = [];
  out.push(`key ${r.deviceId.slice(0, 16)}: head #${r.key.seq} (${r.key.head.slice(0, 12)}...), holds #${r.key.ringFrom}..#${r.key.seq}`);
  out.push(`PC copy: ${r.copy.count - (status ? r.copy.added : 0)} link(s)${status ? (r.copy.added ? `, ${r.copy.added} to read (onlykey-js edge sync)` : ', up to date') : `, ${r.copy.added} new${r.copy.saved ? '' : ' - NOT kept'}`}`);
  const v = r.verdict;
  if (v.kind === 'verified') out.push(`verified through #${v.through}`);
  else if (v.kind === 'unsigned') out.push(`not checked: the links weld to the key's head, but its signature (checkpoint, both halves) could not be checked - not called verified`);
  else if (v.kind === 'gap') out.push(`gap: ${v.gaps.map((g) => (g.from === g.to ? `#${g.from}` : `#${g.from}-#${g.to}`)).join(', ')} - links no copy here holds (repairs are the phone's)`);
  else out.push(`DOES NOT VERIFY at #${v.seq}: ${v.reason} - reported, nothing kept (repairs are the phone's)`);
  if (r.stoppedAt !== null && r.stoppedAt !== undefined) out.push(`stopped at #${r.stoppedAt}: a reply that does not weld onto the copy`);
  /* phase 2: what the phone took of its own chain (no sheet, no press, no link since 2026-10-08) */
  const p = r.phone;
  if (p && p.skipped) out.push(`phone: not offered - ${p.skipped}`);
  else if (p && p.refused) out.push(`phone: ${p.refused}`);
  else if (p && !p.count) out.push('phone: lacks nothing this PC holds');
  else if (p) out.push(`phone: took ${p.count} link(s)`);
  /* this phone's log, now on this computer too (keepLog) - and from here on every device of the identity */
  if (r.log) out.push(r.log.kept ? `log: this phone's log is on this computer${r.log.missing ? ` (${r.log.missing.length} use(s) without their words)` : ''}` : `log: not kept - ${r.log.why}`);
  /* the seals that cut the copy into JSON blocks (BLOCKS.md; read on their own, no press) */
  if (r.blocks) out.push(`seals: ${r.blocks.seals} kept with this copy - onlykey-js edge blocks shows the blocks`);
  else if (r.blocksError) out.push(`seals: not read - ${r.blocksError}`);
  /* your other devices' logs this PC holds, given to the phone - it files a log whose signatures check, no question asked (2026-10-24) */
  for (const o of r.offered || []) {
    const who = `"${o.nametag}" (${o.deviceId.slice(0, 16)})`;
    /* a phone that already has that checkpoint (merged, declined or kept as evidence) holds nothing again (2026-10-11) */
    out.push(o.error ? `log of ${who}: not given - ${o.error}`
      : o.held === false ? `log of ${who}: the phone already has it`
        : `log of ${who}: ${o.count} link(s) given to the phone`);
  }
  return out;
}

/*
 * This computer's own sync key: <edge home>/peer.key, P-256 (made on first use, this
 * user only). It signs every sync message, so the phone knows which
 * computer offered a log. The agent that asks for budgets has no key of its own (the
 * cli pair names the computer since 2026-10-08). No peer list on the key or the phone since 2026-10-08 (Brad:
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
  /* one hybrid anchor ("B"): the newest seal keeps its ML-DSA-65 half, older ones drop it */
  c.seals = c.seals.map((x, i) => {
    if (i === c.seals.length - 1) return x;
    const { signaturePq: _older, ...p256 } = x;
    return p256;
  });
  save(home, c);
  return { seals: c.seals.length };
}

/*
 * Every copy in this home as JSON blocks (edge/src/block.js), each block checked
 * against the key's public keys kept at the last sync - the newest block with both halves (the
 * copy's one hybrid anchor), older ones by P-256 - and against the block before
 * it. -> [{deviceId, blocks: [{block, id, ok, reason?}], open, reason?}]
 */
function blocks(home, { net }) {
  return allJSON(home).map((s) => copyfile.blocks(copyfile.fromJSON(s, fromHex(s.deviceId)), { net }));
}

/*
 * ANOTHER DEVICE'S LOG, kept on this computer (2026-10-08): its links up to its signed
 * checkpoint and its owner statement, as read from that device or its phone. Kept only
 * when its chain checks under its own key (sync.anchorCheck) and the statement names that
 * key; a newer checkpoint replaces an older one, never the other way round. Whether it is
 * YOURS is each phone's call (devices.classify, with its owner key) - this file only keeps it.
 * -> {kept: true} | {kept: false, why}
 */
function keepLog(home, { deviceId, publicKey, publicKeyPq, records, checkpoint, statement }) {
  const { sync: syncLib } = require('../src');
  const id = Uint8Array.from(deviceId);
  /* the statement names both checkpoint keys (the hybrid): one that lacks or differs in the ML-DSA-65 key names another device */
  if (!statement || toHex(statement.deviceId) !== toHex(id) || toHex(statement.publicKey) !== toHex(publicKey)
    || !publicKeyPq || !statement.publicKeyPq || toHex(statement.publicKeyPq) !== toHex(publicKeyPq)) return { kept: false, why: 'the statement does not name this device' };
  /* nothing to merge yet: a device whose key has no link is not kept or offered (an older app's check would read NO_SEQ as a seq) */
  if (checkpoint.seq === syncLib.NO_SEQ || !records.length) return { kept: false, why: 'its key has no link yet' };
  const check = syncLib.anchorCheck({ records, publicKey: Uint8Array.from(publicKey), publicKeyPq: Uint8Array.from(publicKeyPq), checkpoint, anchors: [] });
  if (!check.ok) return { kept: false, why: `its chain does not check (${check.alarm}${check.detail ? `: ${check.detail}` : ''})` };
  const c = load(home, id);
  if (c.checkpoint && c.checkpoint.seq > checkpoint.seq) return { kept: false, why: `this computer already holds it up to #${c.checkpoint.seq}` };
  /*
   * KEPT WHEN ITS SIGNATURES CHECK - NOT ONLY WHEN IT IS COMPLETE (Brad, 2026-10-24: "i should not be
   * asked to merge anything.. i should just open a log and see everything"; "if i lose my phone, i
   * should be able to see the log on my machine"). The chain and the statement above are the trust:
   * every device of the identity holds every device's log. Words that did not arrive (an intent, a
   * receipt's message) are said, not a reason to refuse - a use with no words is what the log is for.
   */
  const full = require('../src').devices.completeness({ deviceId: id, publicKey, records: records.filter((r) => seqOf(r) <= checkpoint.seq), openings: c.openings || [], notes: c.notes || null });
  c.publicKey = Uint8Array.from(publicKey);
  c.publicKeyPq = Uint8Array.from(publicKeyPq);
  c.links = records.filter((r) => seqOf(r) <= checkpoint.seq).map((r) => ({ link: Uint8Array.from(r.link), head: Uint8Array.from(r.head), ...(r.reveal ? { reveal: Uint8Array.from(r.reveal) } : {}) }));
  c.checkpoint = checkpoint;
  if (!c.statement || (statement.seq ?? -1) >= (c.statement.seq ?? -1)) c.statement = statement;
  save(home, c);
  return full.ok ? { kept: true } : { kept: true, missing: full.missing };
}

/** Every log this computer can offer, but the one of `exceptId` (the phone being synced): those with a checkpoint and a statement. */
function logsToOffer(home, exceptId) {
  const skip = exceptId ? keyOf(exceptId) : null;
  return allJSON(home)
    .filter((j) => j.v === 1 && j.checkpoint && j.statement && keyOf(fromHex(j.deviceId)) !== skip)
    .map((j) => copyfile.fromJSON(j, fromHex(j.deviceId)));
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

/*
 * KEEP UP WITH THE KEY'S RING, BETWEEN CHECKS (key 3, 2026-10-29). The key holds only its newest PICKUP_MAX links. A
 * process per use read them into this copy when it closed (sync above); one service for a whole ship (edge-control
 * shipService) made ~21 links before its single close, and #565-#577 had left the ring: a gap no copy held, and the next
 * budget was refused. So the service reads each request's new links right after it: only those after this copy's last,
 * each kept only if it welds onto the one before (follows) - no checkpoint, no full check (~0.2 s); sync() still checks
 * them all against the key's signed checkpoint at the close. An empty copy, or one the ring no longer reaches, is left
 * to sync(), which reports what it finds. -> how many links were kept.
 */
async function catchUp(edge, home, deviceId) {
  const c = load(home, deviceId);
  if (!c.links.length) return 0;
  const last = seqOf(c.links[c.links.length - 1]);
  const h = await edge.head();
  const keySeq = h.seq === null ? -1 : h.seq;
  const add = [];
  for (let from = last + 1; from <= keySeq;) {
    const got = await edge.pickup(from, Math.min(PICKUP_MAX, keySeq - from + 1));
    if (!got.length) break;
    let welded = true;
    for (const r of got) {
      /* the very next seq only, welded to it (follows alone lets a later seq through: sync's read past a gap) */
      const prev = add.length ? add[add.length - 1] : c.links[c.links.length - 1];
      if (seqOf(r) === seqOf(prev) + 1 && follows(prev, r)) add.push(r);
      else { welded = false; break; }
    }
    if (!welded) break;
    from = seqOf(got[got.length - 1]) + 1;
  }
  if (add.length) save(home, { ...c, links: [...c.links, ...add] });
  return add.length;
}

module.exports = { sync, catchUp, lines, load, store, useIdentityBucket, peerSigner, keepSeals, keepLog, logsToOffer, blocks, keepOpenings, keepNotes };
