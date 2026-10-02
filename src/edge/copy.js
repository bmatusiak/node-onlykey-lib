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
 */
const { OP, DECISION } = require('./codes');
const chain = require('./chain');
const grants = require('./grants');
const { keyDebts } = require('./tickets');
const { hmacSha256, same } = require('./hash');

const SEQ_NONE = 0xffffffff;

/** The LOSS links in a run of entries: [{seq, from, to}] (to = 0xFFFFFFFF: not said - covers to the LOSS itself). */
function lossesIn(entries) {
  const out = [];
  for (const e of entries) {
    const f = chain.decodeLink(e instanceof Uint8Array ? e : e.link);
    if (f.op !== OP.LOSS) continue;
    const to = (f.subject[0] | (f.subject[1] << 8) | (f.subject[2] << 16) | (f.subject[3] << 24)) >>> 0;
    out.push({ seq: f.seq, from: f.grantId, to: to === SEQ_NONE ? f.seq - 1 : to });
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

/** gaps (from chain.verify) minus the links the key itself holds - what is really missing */
function missingGaps(entries, gaps, held) {
  const keep = heldSeqs(entries, held);
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

/** The really missing ranges that no LOSS link in the copy covers. held: the key's own links, this session. */
function uncoveredGaps(entries, gaps, held) {
  const losses = lossesIn(entries);
  return missingGaps(entries, gaps, held).filter((g) => !losses.some((l) => l.from <= g.from && l.to >= g.to));
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

  const v = chain.verify(entries, { deviceId, expectHead: { seq: h.seq, head: h.head } });
  if (!v.ok) return fail('chain', { seq: v.failure.seq, detail: v.failure });
  const open = uncoveredGaps(entries, v.gaps, key.held);
  if (open.length) return fail('gap', { seq: open[0].from, detail: { gaps: open } });
  const lastGapEnd = missingGaps(entries, v.gaps, key.held).reduce((m, g) => Math.max(m, g.to), -1);

  /*
   * Every link outside a covered gap is now verified, and so is the head the
   * copy stored with each (forward from genesis, or backward from the key's
   * live head). Heads by seq: the stored one, or welded forward.
   */
  const bySeq = new Map(entries.map((e) => [chain.decodeLink(e.link).seq, e]));
  /* the key's own links this session: their heads are the key's word */
  const keyHeld = heldSeqs(entries, key.held);
  const heldHead = new Map((key.held || []).map((k) => [chain.decodeLink(k.link).seq, k.head]));
  const memo = new Map([[-1, chain.genesis(deviceId)]]);
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
  const fields = raw.map((l) => chain.decodeLink(l)).filter((f) => f.seq > lastGapEnd);
  const openings = copy.openings || {};
  const spends = new Map();
  for (const f of fields) {
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
      spends.set(f.grantId, []);
    } else if ((f.op === OP.SIGN || f.op === OP.DECRYPT) && f.decision === DECISION.SELF_PRESS) {
      const list = spends.get(f.grantId);
      if (!list) return fail('budget-opening-missing', { seq: f.seq, detail: { grantId: f.grantId } });
      const value = bySeq.get(f.seq).reveal;
      if (!value || !value.some((x) => x)) return fail('reveal-missing', { seq: f.seq });
      list.push({ seq: f.seq, step: f.grantStep, value, subject: f.subject, mac: hmacSha256(value, f.subject) });
    }
  }
  for (const [grantId, list] of spends) {
    const o = openings[grantId];
    const r = grants.checkSpends(o.genesis, o.uses, list);
    if (!r.ok) return fail('reveal', { seq: list[r.failure.index].seq, detail: { grantId, ...r.failure } });
  }

  /* the debts the copy implies (from after the last covered gap), against the debts the key reports */
  const d = keyDebts(raw.filter((l) => chain.decodeLink(l).seq > lastGapEnd));
  if (d.owed.length !== h.owed || d.overflow !== Boolean(h.overflow)) {
    return fail('debts', { detail: { copy: { owed: d.owed, overflow: d.overflow }, key: { owed: h.owed, overflow: Boolean(h.overflow) } } });
  }
  return { ok: true, verifiedThrough: h.seq, head: h.head };
}

module.exports = { verifyCopy, lossesIn, uncoveredGaps, missingGaps };
