'use strict';

/**
 * THIS COMPUTER'S COPY OF THE KEY'S CHAIN (onlykey-edge BLOCKS.md): it reads the links the key still holds (PICKUP - a
 * read the key answers unlocked, R8, so no press) and keeps them only after the whole copy verifies against the key
 * (R27). Read after every edge command with the key on USB (register.js pickUp) and when a budget opens (local-host).
 *
 * Reading the key moves nothing anywhere else: the copy reaches your other devices as the identity bucket's sealed rows,
 * through the room (bucket sync - `onlykey-js edge sync` and its phone offers were removed 2026-11-02). It never moves
 * budgets, debts or "yours" marks, and it REPORTS problems (a gap, a fork, tampering); it never repairs them.
 *
 * The copy: the CLI's bucket, the home's `copies` store, key = device id (16 hex):
 *   {deviceId, links: [{link, head, reveal?}] (hex), lastSeen: {seq, head} | null,
 *    publicKey, publicKeyPq, seals: [{seq, head, signature, signaturePq?}], checkpoint?, statement?}
 * One file per device: this key's, and your OTHER devices' logs too, each with that device's signed checkpoint and its
 * owner statement (nametag).
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
/*
 * THE AGENT CARDS, BESIDE THE CHAIN (Brad, 2026-11-03: "in storage live next to the blockchain in the edge's bucket"): the
 * identity bucket's `edge-agents` store (agents.store), next to its `edge-logs` - or null when no identity bucket is in
 * use this run (nothing is listed or kept then).
 */
function agentsKv() {
  if (!logs) return null;
  const { id, net } = logs;
  if (!bucketHome.hasIdentityBucket(id, net)) return null;
  return bucketHome.kv(bucketHome.identityAt(id, net, require('../src/agents').store(net)));
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

/*
 * EVERY LOG OF THIS IDENTITY INTO ITS BUCKET (Brad, 2026-10-29, of key 1's old live chain - its key since wiped: "stay
 * in, that log has value"). load() moves a device's log only when that device is read, and a wiped key's - or the first
 * device's, the one both later chains CONTINUE from - never is. So once a command has the identity bucket, every log in
 * this identity's Edge home that the bucket lacks is copied in, as load() copies one; a log the bucket already holds is
 * left as it is (it is the newer). The Edge home's record stays. -> how many logs were copied.
 */
function adoptAll(home) {
  if (!logs) return 0;
  const kv = logsKv();
  let have = kv.entries();
  const st = store(home);
  let n = 0;
  for (const k of st.keys()) {
    const text = st.getItem(k);
    if (!text) continue;
    let j;
    try { j = JSON.parse(text); } catch { continue; }
    if (!j || !j.deviceId || logblocks.join(have, j.deviceId)) continue;
    saveBlocks(kv, have, j);
    have = kv.entries();
    n += 1;
  }
  return n;
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
  /* a head this computer could not weld (the key never reveals it): nothing to weld from, so not this copy's next link */
  if (f.seq === p + 1 && (!prev.head || !r.head)) return false;
  return f.seq !== p + 1 || sameBytes(chain.weld(prev.head, r.link), r.head);
}

/* this key's login card's top (certify.top) in the identity bucket's edge-cards, or null */
function cardTopOf(deviceId) {
  if (!logs || !bucketHome.hasIdentityBucket(logs.id, logs.net)) return null;
  const store = logs.net === 'test' ? 'edge-cards-test' : 'edge-cards';
  const text = bucketHome.kv(bucketHome.identityAt(logs.id, logs.net, store)).entries()[toHex(deviceId).toLowerCase()];
  try { return (text && JSON.parse(text).top) || null; } catch { return null; }
}

/*
 * WARM UP FIRST (Brad, 2026-10-31: "to warm up edge, we need a checkpoint"; the Windows ship rehearsal on key 2: a
 * computer that never held the chain, the key past its 8-link ring - the ring's links came with no heads and saving the
 * copy threw "Cannot read properties of null"). A key that never reveals its head, and a computer that cannot weld it:
 * this key's login card's top from the identity bucket (the apps file it with each log) - the lib checks it against the
 * key's checkpoint keys, welds it on and proves the head, no press. Without one nothing is read or stored.
 */
async function warmIfCold(edge, deviceId, h) {
  if (h.seq === null || h.head || !(h.caps & 1) || typeof edge.warmUp !== 'function') return h;
  try {
    await edge.warmUp(cardTopOf(deviceId));
  } catch (e) {
    if (e && e.code !== 'EDGE_NO_CHECKPOINT') throw e;
    throw Object.assign(new Error(`this computer cannot follow the key's chain past its ring (${e.why}) - it needs a checkpoint: the login card's top in this identity's bucket (the app files it), or a certify to start`), { code: 'EDGE_NO_CHECKPOINT', why: e.why });
  }
  return edge.head();
}

/*
 * WHERE THIS COPY ENDS, TOLD BEFORE THE FIRST REQUEST (the ship proof on the box, 2026-11-02: `edge budget` through the
 * desktop app failed "head must be 32 bytes" - on a key that never reveals its head, the budget's opening is checked
 * against heads this computer welds from its copy, and the copy was only read at the command's close, after the
 * request). The same two steps the sync takes first: the copy's last head seeded, and a cold computer warmed up from the
 * login card's top. KEY REQUESTS: one head read (no press); the warm-up's own when the computer is cold.
 */
async function seed(edge, home, deviceId) {
  seedHead(edge, load(home, deviceId), deviceId);
  return warmIfCold(edge, deviceId, await edge.head());
}

/* the verdict, in words: verified / gap / tampered (fork, rollback, edited) */
/* keySeq: the key's head - a copy whose only gaps are accepted as lost (LOSS) is verified up to it, and says what was lost */
function verdictOf(a, keySeq) {
  const v = a.chain;
  if (v.failure || (v.failures && v.failures.length)) {
    const f = v.failure || v.failures[0];
    return { kind: 'tampered', seq: f.seq, reason: f.reason };
  }
  if (a.open && a.open.length) return { kind: 'gap', gaps: a.open };
  /* v.verifiedThrough is the first unbroken run only: after a LOSS it stopped at the gap, though the check passed */
  if (a.missing && a.missing.length) return { kind: 'verified', through: keySeq, lost: a.missing };
  return { kind: 'verified', through: v.verifiedThrough };
}

/*
 * TELL THE KEY'S CLIENT WHERE THIS COPY ENDS (the head proof, 2026-10-30): a key that never reveals its head is followed by
 * welding its newer links onto the last head this copy holds - edge.knownHead, no key request. A client without it
 * (older lib) is left as it was.
 */
function seedHead(edge, kept, deviceId) {
  const last = kept && kept.links && kept.links[kept.links.length - 1];
  if (!last || !last.head || typeof edge.knownHead !== 'function') return;
  edge.knownHead(chain.decodeLink(last.link).seq, last.head, deviceId);
}

/**
 * Bring the PC's copy up to the key's head (status: read and report only).
 * edge: the Edge plugin (head, pickup, publicKey, publicKeyPq). -> a report; changes only the
 * PC's copy file, and only when what it would store verifies (no tampering).
 */
async function sync(edge, home, { status = false } = {}) {
  /*
   * EACH PART ITS OWN STEP in a ship's progress window (progress-feed.js; Brad, 2026-10-29: "i'm trying to identify why
   * we wait, and if we can stop waiting for no reason"): what the key does (its keys, its links, its checkpoint) apart
   * from what this computer does (the check) - each with its time, so a wait shows which it is. No window: as before.
   */
  const { publicKey, deviceId, publicKeyPq, c, h: h0 } = await FEED.step('the key: its public keys and head', async () => {
    const pk = await edge.publicKey();
    /* the ML-DSA-65 twin of the checkpoint key: every checkpoint and seal of this chain is checked under both */
    const pq = await edge.publicKeyPq('checkpoint');
    const kept = load(home, pk.deviceId);
    /* where this computer's copy ends: on a key that never reveals its head, the head is welded on from there */
    seedHead(edge, kept, pk.deviceId);
    return { publicKey: pk.publicKey, deviceId: pk.deviceId, publicKeyPq: pq, c: kept, h: await edge.head() };
  });
  const h = h0.seq === null || h0.head ? h0 : await FEED.step('the key: warming up from the login card\'s top', () => warmIfCold(edge, deviceId, h0));
  const keySeq = h.seq === null ? -1 : h.seq;
  const ringFrom = h.oldest === null ? keySeq + 1 : h.oldest;
  const candidate = { ...c, links: [...c.links], publicKey, publicKeyPq };
  let stopped = null;
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
  let verdict = verdictOf(a, keySeq);
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
    /*
     * KEPT WITH THE COPY (2026-10-30: key 3's log reached the bucket with no checkpoint in its meta, and every other device's
     * reader - the phone, the desktop - left it out: nothing to verify it against). The checkpoint that just verified goes
     * into the copy (copyfile: the newer replaces the older), so the log carries the key's own signature wherever it goes.
     */
    else candidate.checkpoint = cp;
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

/*
 * A key's seals (the checkpoints that close each block), kept beside the copy. Merged by seq: a source may hold
 * fewer than this computer already kept.
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

/*
 * A DEVICE'S CERTIFIED NAMETAG (edge/cli/nametag.js; Brad, 2026-10-30: nametags are certified at a press, and the list of a
 * key's names is kept - "if a key name is changed i can see the old names it had"): onto its copy - the identity bucket's
 * `edge-logs` <dev>.statement, the one the app and every log carry (the newest by seq) - and, once, into `edge-names`
 * (<dev>.<its signature's first 16 hex>), the history the app's Your devices reads. Without an identity bucket (a test, a
 * command that never read the identity) only the copy keeps it.
 */
function namesKv() {
  const { id, net } = logs;
  return bucketHome.kv(bucketHome.identityAt(id, net, net === 'test' ? 'edge-names-test' : 'edge-names'));
}
function keepNametag(home, deviceId, statement, { now = Date.now } = {}) {
  const c = load(home, deviceId);
  c.statement = {
    deviceId: Uint8Array.from(statement.deviceId), publicKey: Uint8Array.from(statement.publicKey), publicKeyPq: Uint8Array.from(statement.publicKeyPq),
    seq: statement.seq ?? null, nametag: String(statement.nametag), signature: Uint8Array.from(statement.signature), signaturePq: Uint8Array.from(statement.signaturePq),
  };
  save(home, c);
  if (!logs) return;
  const sig = toHex(statement.signature);
  const stored = {
    deviceId: toHex(statement.deviceId), publicKey: toHex(statement.publicKey), publicKeyPq: toHex(statement.publicKeyPq),
    seq: statement.seq ?? null, nametag: String(statement.nametag), signature: sig, signaturePq: toHex(statement.signaturePq),
  };
  namesKv().setItem(`${keyOf(deviceId)}.${sig.slice(0, 16)}`, JSON.stringify({ v: 1, deviceId: stored.deviceId, statement: stored, at: now() }));
}
/** every nametag the identity bucket holds, by device: [{deviceId, statement, at}] (unchecked - the caller checks) */
function nametagHistory() {
  if (!logs) return [];
  return Object.values(namesKv().entries()).map((v) => { try { return JSON.parse(v); } catch (_) { return null; } }).filter((r) => r && r.statement);
}

module.exports = { sync, seed, catchUp, adoptAll, load, store, useIdentityBucket, agentsKv, keepSeals, keepLog, blocks, keepOpenings, keepNotes, keepNametag, nametagHistory };
