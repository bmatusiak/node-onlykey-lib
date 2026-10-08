'use strict';

/**
 * Edge copy check (firmware.md R27, Brad 2026-10-02): may this host ask the key
 * for a budget, or a resume? Only if its OWN copy of the chain verifies, up to
 * the key's live HEAD. A host whose copy does not verify sends nothing, and
 * says why (the tab's sheet, the MCP's `history_mismatch`).
 *
 * WHY: a budget lets an agent use the key without a press. Opening one on top
 * of a history the host cannot account for - a gap, a fork, a flipped byte,
 * debts the key reports that the copy does not show - would hand out presses
 * nobody can audit afterwards. The key backs the check up only partly (it
 * refuses a GRANT_CREATE / GRANT_RESUME whose head is not its current one), so
 * the full check lives here, once, for every host.
 *
 * What must hold, in order (the first failure is the answer):
 *   restoring        the key is mid-restore (R26): the restore is finished in
 *                    ok-rn, by a person, before anything else
 *   chain            every weld from genesis up to the live HEAD (chain.verify)
 *   gap              links missing anywhere from genesis to HEAD
 *   checkpoint       the latest checkpoint's signature, over a head in this copy
 *   budget-opening-missing / budget-opening
 *                    each budget's grant-create link, its G and the checkpoint
 *                    its press answered with (grants.verifyBudgetOpening)
 *   reveal-missing / reveal
 *                    every self-press's reveal hashes back to its budget's G, in
 *                    step order (grants.checkSpends)
 *   debts            the key's debt list replayed over this copy
 *                    (tickets.keyDebts) matches what HEAD reports
 *
 * GAPS (R24, R27; the spec's red banner, 2026-10-02): a range the copy cannot
 * verify blocks a budget, unless a LOSS link in the copy covers it - the
 * person's pressed acceptance that #from..#to is gone (grant_id = from,
 * subject = to, u32 LE). Then the debts are replayed from after the last
 * covered gap: what the lost range owed is unknown, so if the key still owes
 * for it the counts disagree and the copy fails `debts` - a waive settles it.
 * Never "verify from a checkpoint" alone as a way out.
 *
 * WHAT COUNTS AS VERIFIED (firmware.md R27, tab spec B2; found on the Pixel
 * 2026-10-02, where a key restart left the copy #30-#36 and #48 and the banner
 * offered #0-#47 as lost): anchors are heads the key itself stands behind - the
 * genesis, its live HEAD, and every checkpoint whose signature verifies under
 * the KEY's public key (key.publicKey, read from the key or pinned for its
 * device id; never one the copy carries, or a copy could sign for itself).
 * chain.verify welds forward and back from each, so the gap is only what no
 * anchor reaches. And a LOSS link counts only when it is itself verified and
 * later than the gap it covers: a LOSS sitting in an unverified range is as
 * unproven as the range, and counting it let an edited copy cover its own gap.
 * assess() is that one answer; the tab's banner and verifyCopy (Approve) both
 * read it.
 */
const { OP, DECISION } = require('./codes');
const chain = require('./chain');
const grants = require('./grants');
const { keyDebts } = require('./tickets');
const { H, hmacSha256, same } = require('./hash');
const { toHex, utf8ToBytes } = require('../../src/bytes');

const SEQ_NONE = 0xffffffff;

/** The LOSS links in a run of entries: [{seq, from, to}] (to = 0xFFFFFFFF: not said - covers to the LOSS itself). */
function lossesIn(entries) {
  const out = [];
  for (const e of entries) {
    const f = chain.decodeLink(e instanceof Uint8Array ? e : e.link);
    if (f.op !== OP.LOSS) continue;
    const to = (f.subject[0] | (f.subject[1] << 8) | (f.subject[2] << 16) | (f.subject[3] << 24)) >>> 0;
    /* R24: the first 28 bytes of SHA-256(link to+1), when the key held it at the LOSS; zeros otherwise */
    const next = f.subject.slice(4, 32);
    out.push({ seq: f.seq, from: f.grantId, to: to === SEQ_NONE ? f.seq - 1 : to, next: next.some((x) => x) ? next : null });
  }
  return out;
}

/*
 * Links the key handed over THIS session (its pickup ring) are the key's own
 * word, so they are not a gap even when the copy cannot weld them (the link
 * before them is gone - a key keeps only its last few, and only its latest
 * after a restart). The copy's link must equal the key's, byte for byte. What
 * remains of a gap is what is really missing: the only range a person should
 * be offered to accept as lost (spec okrn-edge-tab.md 4.3).
 */
function heldSeqs(entries, held) {
  const out = new Set();
  if (!held || !held.length) return out;
  const mine = new Map(entries.map((e) => [chain.decodeLink(e instanceof Uint8Array ? e : e.link).seq, e instanceof Uint8Array ? e : e.link]));
  for (const k of held) {
    const seq = chain.decodeLink(k.link).seq;
    const m = mine.get(seq);
    if (m && same(m, k.link)) out.add(seq);
  }
  return out;
}

/*
 * THE LINK AFTER A LOSS (firmware.md R24, Brad 2026-10-02): its predecessor is
 * gone, so its own bytes cannot be welded. A LOSS {A..B} the key wrote while it
 * held #B+1 names it - the first 28 bytes of SHA-256(link B+1), from the key's
 * memory - and a verified LOSS's word is the key's: the copy's #B+1 is kept
 * when it hashes to that. Nothing else vouches for it: a copy cannot.
 */
function keptSeqs(entries, gaps, held) {
  const keep = heldSeqs(entries, held);
  const bySeq = new Map(entries.map((e) => { const l = e instanceof Uint8Array ? e : e.link; return [chain.decodeLink(l).seq, l]; }));
  for (const l of verifiedLosses(entries, gaps, held)) {
    const link = l.next && l.to !== SEQ_NONE ? bySeq.get(l.to + 1) : null;
    if (link && same(H(link).slice(0, 28), l.next)) keep.add(l.to + 1);
  }
  return keep;
}

/** gaps (from chain.verify) minus the links the key itself vouches for - what is really missing */
function missingGaps(entries, gaps, held) {
  const keep = keptSeqs(entries, gaps, held);
  const out = [];
  for (const g of gaps) {
    let start = null;
    for (let s = g.from; s <= g.to + 1; s++) {
      const missing = s <= g.to && !keep.has(s);
      if (missing && start === null) start = s;
      if (!missing && start !== null) { out.push({ from: start, to: s - 1 }); start = null; }
    }
  }
  return out;
}

/*
 * The LOSS links that count: verified (outside every gap chain.verify left, or
 * the key's own link this session) - an unverified one proves nothing.
 */
function verifiedLosses(entries, gaps, held) {
  const keep = heldSeqs(entries, held);
  const inGap = (seq) => gaps.some((g) => g.from <= seq && seq <= g.to);
  return lossesIn(entries).filter((l) => keep.has(l.seq) || !inGap(l.seq));
}

/*
 * Whether the verified LOSS links later than a gap cover it - together: an
 * overlapping or adjoining pair counts as one range (the Pixel: #37-#47
 * accepted, then #37-#48 once #48 could not be proven).
 */
function covers(g, losses) {
  const spans = losses.filter((l) => l.seq > g.to).map((l) => [l.from, l.to]).sort((x, y) => x[0] - y[0]);
  let reach = g.from - 1;
  for (const [a, b] of spans) {
    if (a > reach + 1) break;
    if (b > reach) reach = b;
  }
  return reach >= g.to;
}

/** The really missing ranges no verified, later LOSS links cover. held: the key's own links, this session. */
function uncoveredGaps(entries, gaps, held) {
  const losses = verifiedLosses(entries, gaps, held);
  return missingGaps(entries, gaps, held).filter((g) => !covers(g, losses));
}

/*
 * The checkpoints the KEY signed, as chain.verify anchors {seq, head}: the
 * key's latest (key.checkpoint), each budget opening's (the press's answer,
 * over its grant-create link's stored head) and any the copy kept
 * (copy.checkpoints). Only signatures that verify under key.publicKey count.
 */
/*
 * SEALED (BLOCKS.md §2a; Brad, 2026-10-07: "we only need to verify the new stuff").
 * sealed = {seq, head}: a checkpoint the CALLER checked THIS session against the
 * key's public key - a seal the key signed when a budget had ended. It stands in
 * for every signature at or below it: those checks, one per budget ever opened,
 * are what makes the full check grow with the chain (10.3 s on a Galaxy A13 at
 * #572). The stored links are still welded to it by chain.verify, and gaps,
 * losses and the verdict come out exactly as in the full check.
 */
function checkpointAnchors(entries, copy, key, sealed = null) {
  if (!key.publicKey) return []; /* nothing to check a signature with: no checkpoint anchors */
  const deviceId = chain.deviceIdOf(key.publicKey);
  const out = new Map();
  if (sealed) out.set(sealed.seq, { seq: sealed.seq, head: sealed.head });
  const below = (seq) => sealed && seq <= sealed.seq;
  const take = (seq, head, signature) => {
    if (out.has(seq) || below(seq) || !head || !signature) return;
    if (chain.verifyCheckpoint({ deviceId, seq, head }, signature, key.publicKey)) out.set(seq, { seq, head });
  };
  const openings = copy.openings || {};
  for (const e of entries) {
    const f = chain.decodeLink(e.link);
    if (f.op === OP.GRANT_CREATE && openings[f.grantId]) take(f.seq, e.head, openings[f.grantId].signature);
  }
  for (const c of copy.checkpoints || []) take(c.seq, c.head, c.signature);
  if (key.checkpoint) take(key.checkpoint.seq, key.checkpoint.head, key.checkpoint.signature);
  return [...out.values()].sort((a, b) => a.seq - b.seq);
}

/**
 * The one answer to "what does this copy prove" (R27), for the banner and
 * Approve alike. key: {publicKey, head {seq, head}, held?, checkpoint?} -
 * or {deviceId, ...} with no public key (a test key that signs nothing): then
 * the anchors are the genesis and HEAD only;
 * opts.ringFrom: the oldest seq the key still holds (missing links at or
 * above it were removed, not lost); opts.lastSeen: the head this host verified
 * last session (an older one now is a rollback).
 * opts.sealed: {seq, head} the caller checked against key.publicKey THIS session (a
 * seal, BLOCKS.md 2a): it stands in for every signature at or below it.
 * -> {chain (chain.verify's result), anchors, missing, losses, open}
 *    missing: ranges no anchor reaches, minus the key's own links;
 *    losses: the verified LOSS links; open: missing ranges none of them covers.
 */
function assess(copy, key, opts = {}) {
  if (opts.from) return assessFrom(copy, key, opts);
  const entries = (copy.links || []).map((e) => (e instanceof Uint8Array ? { link: e } : e));
  const deviceId = key.publicKey ? chain.deviceIdOf(key.publicKey) : key.deviceId;
  /* opts.sealed: see checkpointAnchors - the caller checked it against key.publicKey this session */
  const anchors = checkpointAnchors(entries, copy, key, opts.sealed || null);
  const v = chain.verify(entries, {
    ...chain.chainStart(entries, deviceId), /* R28: a chain that begins with a continue starts there */
    deviceId, expectHead: { seq: key.head.seq, head: key.head.head }, anchors,
    ...(opts.ringFrom !== undefined ? { ringFrom: opts.ringFrom } : {}),
    ...(opts.lastSeen ? { lastSeen: opts.lastSeen } : {}),
  });
  const missing = missingGaps(entries, v.gaps, key.held);
  const losses = verifiedLosses(entries, v.gaps, key.held);
  return { chain: v, anchors, missing, losses, open: uncoveredGaps(entries, v.gaps, key.held) };
}

/*
 * ONLY THE NEW LINKS (Brad, 2026-10-05): opts.from = {seq, head} is a head the
 * CALLER verified in full earlier and still holds in memory - never one read
 * from storage, which anything on the phone can edit. A chain only grows, so
 * what is below it needs no second look: the links after it must weld onto it
 * and reach the key's live head, and a checkpoint the key gives past it must
 * verify (a bad one is a failure here, not just one anchor fewer). A gap among
 * the new links is reported as usual; the caller then checks in full.
 */
function assessFrom(copy, key, opts) {
  const from = opts.from;
  const entries = (copy.links || [])
    .map((e) => (e instanceof Uint8Array ? { link: e } : e))
    .filter((e) => chain.decodeLink(e.link).seq > from.seq);
  const deviceId = key.publicKey ? chain.deviceIdOf(key.publicKey) : key.deviceId;
  const cp = key.checkpoint;
  if (cp && cp.seq > from.seq && key.publicKey && !chain.verifyCheckpoint({ deviceId, seq: cp.seq, head: cp.head }, cp.signature, key.publicKey)) {
    return {
      chain: { ok: false, verifiedThrough: from.seq, gaps: [], failure: { seq: cp.seq, reason: 'bad-checkpoint' } },
      anchors: [], missing: [], losses: [], open: [],
    };
  }
  const anchors = checkpointAnchors(entries, copy, key).filter((a) => a.seq > from.seq);
  const held = (key.held || []).filter((e) => chain.decodeLink(e.link || e).seq > from.seq);
  const v = chain.verify(entries, {
    fromSeq: from.seq + 1, fromHead: from.head,
    deviceId, expectHead: { seq: key.head.seq, head: key.head.head }, anchors,
    ...(opts.ringFrom !== undefined ? { ringFrom: Math.max(opts.ringFrom, from.seq + 1) } : {}),
  });
  return { chain: v, anchors, missing: missingGaps(entries, v.gaps, held), losses: verifiedLosses(entries, v.gaps, held), open: uncoveredGaps(entries, v.gaps, held) };
}

/**
 * copy: {
 *   links:    [{link, head?, reveal?}] from seq 0, oldest first (reveal = the
 *             self-press's v_i, as PICKUP gave it),
 *   openings: {[grantId]: {scopes, reasonHash, genesis, uses, lifetime, signature}} -
 *             what the host asked for and the checkpoint signature its press
 *             answered with (edge.grant's reply),
 * }
 * key: what the host read from the key THIS session: {publicKey, head (edge.head()),
 *      held (optional: the links PICKUP gave from the key's ring - trusted as they are),
 *      checkpoint (edge.checkpoint())}
 *
 * -> {ok: true, verifiedThrough, head} or {ok: false, reason, seq?, detail?}
 */
function verifyCopy(copy, key) {
  return verifyCore(copy, key, null, {});
}

/*
 * ONLY WHAT IS NEW (Brad, 2026-10-06: every press re-verified the copy from
 * genesis - every weld, two P-256 checks per budget ever opened, every spend
 * walk). The caller keeps the last verified state IN MEMORY ONLY and hands it
 * back; it is never stored, so a restart checks in full.
 *   same key head, same copy (and openings): the result again;
 *   the head moved or the copy grew, older part unchanged: the chain from the
 *     last verified link, the key's checkpoint, and only the new links' fields,
 *     openings and spends (spends re-checked only for budgets that grew);
 *     debts recounted (a linear pass);
 *   anything else - an earlier link or opening changed, the result was not ok,
 *     the new part not clean: the full check.
 * -> {result (verifyCopy's), state (for the next call, or null), path: 'skipped' | 'new-links' | 'full',
 *     why (on 'full': which condition sent it there)}
 */
function verifyCopyKept(copy, key, prev = null) {
  const entries = (copy.links || []).map((e) => (e instanceof Uint8Array ? { link: e } : e));
  const kh = key.head;
  const hash = entriesHash(entries, entries.length);
  const okPrev = prev && prev.result && prev.result.ok && prev.openingsHash === openingsHash(copy.openings, prev.grants);
  if (okPrev && sameKeyHead(prev.keyHead, kh) && prev.hash === hash) return { result: prev.result, state: prev, path: 'skipped' };
  let why = null;
  const whyNot = () => !prev ? 'first check' : !(prev.result && prev.result.ok) ? 'last result not ok' : !okPrev ? 'openings changed' :
    kh.restoring ? 'key restoring' : kh.seq === null ? 'no key head' : !(prev.count > 0) ? 'nothing verified before' :
    prev.count > entries.length ? 'copy shrank' : !(entries.length > prev.count || kh.seq > prev.keyHead.seq) ? 'key head changed, no new links' :
    entriesHash(entries, prev.count) !== prev.prefixHash ? 'an older link changed' : 'unknown';
  if (okPrev && !kh.restoring && kh.seq !== null && prev.count > 0 && prev.count <= entries.length &&
      (entries.length > prev.count || kh.seq > prev.keyHead.seq) && entriesHash(entries, prev.count) === prev.prefixHash) {
    const out = {};
    const r = verifyCore(copy, key, prev, out);
    if (r && r.ok) return { result: r, state: { ...out.state, hash, prefixHash: hash }, path: 'new-links' };
    why = out.why || (r ? 'new part: ' + (r.reason || 'not ok') : 'new part not clean');
  }
  /* why the short path was not taken - logged by the app as "full: <why>" */
  if (!why) why = whyNot();
  const out = {};
  const r = verifyCore(copy, key, null, out);
  return { result: r, state: r.ok && out.state ? { ...out.state, hash, prefixHash: hash } : null, path: 'full', why };
}

function sameKeyHead(a, b) {
  return a && b && a.seq === b.seq && same(a.head, b.head) && (a.owed || 0) === (b.owed || 0) && Boolean(a.overflow) === Boolean(b.overflow) && Boolean(a.restoring) === Boolean(b.restoring);
}
/* what the state was verified over: every stored link with its head and reveal, in order */
function entriesHash(entries, count) {
  const parts = [];
  for (let i = 0; i < count; i++) {
    const e = entries[i];
    parts.push(e.link, e.head || new Uint8Array(0), e.reveal || new Uint8Array(0), Uint8Array.of(e.head ? 1 : 0, e.reveal ? 1 : 0));
  }
  return toHex(H('OKEDGE-COPYHASH-v1', ...parts));
}
/* the openings the state relied on - the host's own records, as untrusted as the links */
function openingsHash(openings, grantIds) {
  const o = openings || {};
  const parts = [];
  for (const g of [...(grantIds || [])].sort((x, y) => x - y)) {
    const r = o[g];
    parts.push(Uint8Array.of(g & 0xff, (g >>> 8) & 0xff, (g >>> 16) & 0xff, (g >>> 24) & 0xff));
    if (!r) { parts.push(Uint8Array.of(0)); continue; }
    parts.push(r.signature, r.genesis, r.reasonHash, utf8ToBytes(JSON.stringify([r.uses, r.lifetime || 0, r.scopes])));
  }
  return toHex(H('OKEDGE-OPENINGS-v1', ...parts));
}

function verifyCore(copy, key, prev, out) {
  const fail = (reason, extra = {}) => ({ ok: false, reason, ...extra });
  const h = key.head;
  if (h.restoring) return fail('restoring');
  const deviceId = chain.deviceIdOf(key.publicKey);
  const entries = (copy.links || []).map((e) => (e instanceof Uint8Array ? { link: e } : e));
  const raw = entries.map((e) => e.link);

  /* an empty key: nothing to account for, as long as the copy is empty too */
  if (h.seq === null) {
    if (raw.length) return fail('chain', { seq: 0, detail: { reason: 'rollback' } });
    if (!same(h.head, chain.genesis(deviceId))) return fail('chain', { seq: 0, detail: { reason: 'head-mismatch' } });
    return { ok: true, verifiedThrough: -1, head: h.head };
  }

  /* from a previous state: the chain only from the last verified link - anything short of clean goes back to the full check */
  const a = prev
    ? assess({ ...copy, links: entries }, key, { from: { seq: prev.lastSeq, head: prev.lastHead } })
    : assess({ ...copy, links: entries }, key);
  const v = a.chain;
  if (prev && (!v.ok || v.gaps.length || a.open.length || a.missing.length)) {
    out.why = !v.ok ? 'new part: ' + (v.reason || 'not ok') : v.gaps.length ? 'new part has a gap' : a.open.length ? 'new part has an open link' : 'new part has missing links';
    return null;
  }
  if (!v.ok) return fail('chain', { seq: v.failure.seq, detail: v.failure });
  if (a.open.length) return fail('gap', { seq: a.open[0].from, detail: { gaps: a.open } });
  /*
   * Checked from after the last range set aside: a gap a LOSS covers, and ALSO any range a
   * LOSS names that this copy still holds (2026-10-04: budget 166's links, written between
   * the two R3 builds, fail the exact rule; the spec's fix is a LOSS over them - your press -
   * and the copy is then checked after them, not stuck on them).
   */
  const lossEnd = lossesIn(entries).reduce((m, l) => Math.max(m, l.to), -1);
  const lastGapEnd = Math.max(a.missing.reduce((m, g) => Math.max(m, g.to), -1), lossEnd, prev ? prev.lastGapEnd : -1);
  /* a new LOSS moves where the checks start: that is the full check's job */
  if (prev && lastGapEnd !== prev.lastGapEnd) { out.why = 'a new loss or gap'; return null; }

  /*
   * Every link outside a covered gap is now verified, and so is the head the
   * copy stored with each (forward from genesis, or backward from the key's
   * live head). Heads by seq: the stored one, or welded forward.
   */
  const bySeq = new Map(entries.map((e) => [chain.decodeLink(e.link).seq, e]));
  /* the key's own links this session: their heads are the key's word */
  const keyHeld = heldSeqs(entries, key.held);
  const heldHead = new Map((key.held || []).map((k) => [chain.decodeLink(k.link).seq, k.head]));
  const start = chain.chainStart(entries, deviceId);
  const memo = new Map([[start.fromSeq - 1, start.fromHead]]);
  if (prev) memo.set(prev.lastSeq, prev.lastHead);
  const headAt = (seq) => {
    if (memo.has(seq)) return memo.get(seq);
    const e = bySeq.get(seq);
    let hd;
    if (keyHeld.has(seq) && heldHead.get(seq)) hd = heldHead.get(seq);
    else if (e && e.head) hd = e.head;
    else if (e && memo.has(seq - 1)) hd = chain.weld(memo.get(seq - 1), e.link);
    else if (e) { const prev = headAt(seq - 1); hd = prev ? chain.weld(prev, e.link) : undefined; }
    memo.set(seq, hd);
    return hd;
  };

  const cp = key.checkpoint;
  if (!cp || !same(headAt(cp.seq) || new Uint8Array(0), cp.head) ||
      !chain.verifyCheckpoint({ deviceId, seq: cp.seq, head: cp.head }, cp.signature, key.publicKey)) {
    return fail('checkpoint', { seq: cp ? cp.seq : null });
  }

  /* budgets: each opening, then its self-presses in step order */
  const fields = raw.map((l) => chain.decodeLink(l)).filter((f) => f.seq > (prev ? prev.lastSeq : lastGapEnd));
  /*
   * R3 (Brad, 2026-10-06): once the chain has a version-1 link, any LATER
   * version-0 link is red - the key never writes 0 on a new link, and replayed
   * old links keep their old, lower seqs. Over every link the copy holds on a
   * full check (a gap must not hide it), over the new ones from a kept state.
   */
  let firstV1 = prev ? prev.firstV1 : null;
  for (const f of prev ? fields : raw.map((l) => chain.decodeLink(l)).sort((a, b) => a.seq - b.seq)) {
    if (f.version >= 1) { if (firstV1 === null || f.seq < firstV1) firstV1 = f.seq; }
    else if (firstV1 !== null && f.seq > firstV1) return fail('version', { seq: f.seq, detail: { version: 0, reason: 'after-version-1', since: firstV1 } });
  }
  const openings = copy.openings || {};
  /* the budgets verified so far carry over from a previous state; only the ones new links touch are checked again */
  const spends = new Map(prev ? [...prev.spends].map(([g, l]) => [g, l.slice()]) : []);
  /* R3: what each opening in this copy says its scope count is (0 = an older budget) */
  const openingScopes = new Map(prev ? prev.openingScopes : []);
  const touched = new Set();
  for (const f of fields) {
    /* R3: a scope only on a link that spends a budget; bytes 47-63 always zero */
    const spend = (f.op === OP.SIGN || f.op === OP.DECRYPT) && f.decision === DECISION.SELF_PRESS;
    /* R3: the opening carries its scope count (0 on an older one); a spend names its scope; nothing else carries one */
    if (f.scope !== 0 && !spend && f.op !== OP.GRANT_CREATE) return fail('scope', { seq: f.seq, detail: { scope: f.scope, reason: 'not-a-spend' } });
    if (!f.versionKnown) return fail('version', { seq: f.seq, detail: { version: f.version } }); /* R3: a format this library does not know - red */
    if (!f.reservedZero) return fail('reserved', { seq: f.seq });
    if (f.op === OP.GRANT_CREATE) {
      const o = openings[f.grantId];
      if (!o) return fail('budget-opening-missing', { seq: f.seq, detail: { grantId: f.grantId } });
      const prev = headAt(f.seq - 1);
      let r;
      if (prev) {
        r = grants.verifyBudgetOpening({
          deviceId, publicKey: key.publicKey, link: bySeq.get(f.seq).link, prevHead: prev, head: headAt(f.seq),
          signature: o.signature, scopes: o.scopes, reasonHash: o.reasonHash, genesis: o.genesis, uses: o.uses, lifetime: o.lifetime || 0,
        });
      } else if (keyHeld.has(f.seq)) {
        /*
         * The key handed this grant-create over itself, but the head before it
         * is gone (a covered gap): its own head stands in for the weld. Still
         * checked: the caps add up, the subject commits to these scopes, reason,
         * G and lifetime, and the press's checkpoint signs this head.
         */
        const sum = o.scopes.reduce((n, sc) => n + sc.cap, 0) === o.uses;
        const subj = same(f.subject, grants.grantSubject({ scopes: o.scopes, reasonHash: o.reasonHash, genesis: o.genesis, lifetime: o.lifetime || 0 }));
        const sig = chain.verifyCheckpoint({ deviceId, seq: f.seq, head: headAt(f.seq) }, o.signature, key.publicKey);
        r = sum && subj && sig ? { ok: true, grantId: f.grantId } : { ok: false, reason: !sum ? 'uses-mismatch' : !subj ? 'subject-mismatch' : 'bad-signature' };
      } else {
        r = { ok: false, reason: 'prev-head-unknown' };
      }
      if (!r.ok || r.grantId !== f.grantId) return fail('budget-opening', { seq: f.seq, detail: { grantId: f.grantId, reason: r.reason || 'grant-id' } });
      if (f.scope !== 0 && f.scope !== o.scopes.length) {
        return fail('scope', { seq: f.seq, detail: { grantId: f.grantId, scope: f.scope, scopes: o.scopes.length, reason: 'opening-count' } });
      }
      openingScopes.set(f.grantId, f.scope);
      spends.set(f.grantId, []);
      touched.add(f.grantId);
    } else if ((f.op === OP.SIGN || f.op === OP.DECRYPT) && f.decision === DECISION.SELF_PRESS) {
      const list = spends.get(f.grantId);
      if (!list) return fail('budget-opening-missing', { seq: f.seq, detail: { grantId: f.grantId } });
      /*
       * R3 (2026-10-03): byte 46 names the scope that paid - in range, covering
       * this op and slot, and each scope within its cap (checked after the
       * loop). A budget's spends all carry one (written since R3) or none (an
       * older chain); a 0 among scoped spends is a forged link.
       */
      const o = openings[f.grantId];
      if (f.scope !== 0) {
        const sc = o.scopes[f.scope - 1];
        if (!sc) return fail('scope', { seq: f.seq, detail: { grantId: f.grantId, scope: f.scope, scopes: o.scopes.length, reason: 'out-of-range' } });
        if (sc.op !== f.op || sc.slot !== f.slot) return fail('scope', { seq: f.seq, detail: { grantId: f.grantId, scope: f.scope, reason: 'does-not-cover' } });
      }
      const value = bySeq.get(f.seq).reveal;
      if (!value || !value.some((x) => x)) return fail('reveal-missing', { seq: f.seq });
      list.push({ seq: f.seq, step: f.grantStep, scope: f.scope, value, subject: f.subject, mac: hmacSha256(value, f.subject) });
      touched.add(f.grantId);
    }
  }
  for (const [grantId, list] of spends) {
    if (prev && !touched.has(grantId)) continue;
    const o = openings[grantId];
    /*
     * R3, exact: the opening says N -> every spend names 1..N (range checked in
     * the loop); it says 0 -> every spend is 0 (an older budget). An opening not
     * in this copy (a LOSS range) -> all scoped or none.
     */
    const scoped = list.filter((x) => x.scope !== 0);
    const n = openingScopes.get(grantId);
    if (n > 0 && scoped.length !== list.length) {
      return fail('scope', { seq: list.find((x) => x.scope === 0).seq, detail: { grantId, reason: 'missing' } });
    }
    if (n === 0 && scoped.length) return fail('scope', { seq: scoped[0].seq, detail: { grantId, reason: 'unexpected' } });
    if (n === undefined && scoped.length && scoped.length !== list.length) {
      return fail('scope', { seq: list.find((x) => x.scope === 0).seq, detail: { grantId, reason: 'missing' } });
    }
    const per = new Map();
    for (const x of scoped) {
      per.set(x.scope, (per.get(x.scope) || 0) + 1);
      if (per.get(x.scope) > o.scopes[x.scope - 1].cap) return fail('scope', { seq: x.seq, detail: { grantId, scope: x.scope, reason: 'over-cap' } });
    }
    const r = grants.checkSpends(o.genesis, o.uses, list);
    if (!r.ok) return fail('reveal', { seq: list[r.failure.index].seq, detail: { grantId, ...r.failure } });
  }

  /* the debts the copy implies (from after the last covered gap), against the debts the key reports */
  const d = keyDebts(raw.filter((l) => chain.decodeLink(l).seq > lastGapEnd));
  if (d.owed.length !== h.owed || d.overflow !== Boolean(h.overflow)) {
    return fail('debts', { detail: { copy: { owed: d.owed, overflow: d.overflow }, key: { owed: h.owed, overflow: Boolean(h.overflow) } } });
  }
  const result = { ok: true, verifiedThrough: h.seq, head: h.head };
  const last = entries.length ? entries[entries.length - 1] : null;
  const lastSeq = last ? chain.decodeLink(last.link).seq : -1;
  const lastHead = last ? headAt(lastSeq) : null;
  if (last && lastHead) {
    out.state = {
      keyHead: { seq: h.seq, head: h.head, owed: h.owed || 0, overflow: Boolean(h.overflow), restoring: Boolean(h.restoring) },
      count: entries.length, lastSeq, lastHead, lastGapEnd, spends, openingScopes, firstV1,
      grants: [...spends.keys()], openingsHash: openingsHash(openings, [...spends.keys()]), result,
    };
  }
  return result;
}

/*
 * R28: does a new chain's first link (op CONTINUE) continue THIS old copy?
 * oldCopy: {deviceId, links: [{link, head?}]} - the copy kept for the chain it
 * names, with its checkpoint key beside it. The subject commits to the old device
 * id, the seq before the continue, the old head at that seq and the debts carried
 * (tickets.keyDebts over the old copy). A copy that starts after the chain's first
 * link may not see every debt: a match is still a match (debtsChecked false), a
 * mismatch there is "unverifiable", never "ok".
 * -> {ok: true, oldSeq, debts, debtsChecked} or {ok: false, reason}
 */
function checkContinue(link, oldCopy) {
  const f = chain.decodeLink(link instanceof Uint8Array ? link : link.link);
  if (f.op !== OP.CONTINUE) return { ok: false, reason: 'not-a-continue' };
  const oldSeq = f.seq - 1;
  const entries = (oldCopy.links || []).map((e) => (e instanceof Uint8Array ? { link: e } : e));
  const bySeq = new Map(entries.map((e) => [chain.decodeLink(e.link).seq, e]));
  const at = bySeq.get(oldSeq);
  if (!at) return { ok: false, reason: 'old-copy-lacks-the-head', oldSeq };
  /* the head at oldSeq: stored with the record, else welded from the record before it */
  let head = at.head || null;
  if (!head && bySeq.get(oldSeq - 1) && bySeq.get(oldSeq - 1).head) head = chain.weld(bySeq.get(oldSeq - 1).head, at.link);
  if (!head) return { ok: false, reason: 'old-copy-lacks-the-head', oldSeq };
  const raw = entries.map((e) => e.link).filter((l) => chain.decodeLink(l).seq <= oldSeq);
  const fromStart = raw.length > 0 && chain.decodeLink(raw[0]).seq === chain.chainStart(entries, oldCopy.deviceId).fromSeq;
  /* the debts this copy can see; from a copy that starts later they may be incomplete */
  const debts = keyDebts(raw).owed;
  if (debts.length === f.grantId && same(f.subject, chain.continueSubject({ oldDeviceId: oldCopy.deviceId, oldSeq, oldHead: head, owedSeqs: debts }))) {
    return { ok: true, oldSeq, debts, debtsChecked: fromStart };
  }
  /* never 'ok' on a subject that did not match: a copy that starts late cannot tell a lie from a debt it never saw */
  return { ok: false, reason: fromStart ? 'subject-mismatch' : 'unverifiable', oldSeq };
}

module.exports = { verifyCopy, verifyCopyKept, assess, lossesIn, uncoveredGaps, missingGaps, checkContinue };
