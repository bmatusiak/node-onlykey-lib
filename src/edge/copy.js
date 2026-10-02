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
 * CHOSEN: a copy starts at genesis. The debt list cannot be replayed from the
 * middle (the list it started with is unknown), so a copy rebuilt from a
 * checkpoint fails closed with `gap` until the earlier links are found or a
 * LOSS link covers them.
 */
const { OP, DECISION } = require('./codes');
const chain = require('./chain');
const grants = require('./grants');
const { keyDebts } = require('./tickets');
const { hmacSha256, same } = require('./hash');

/**
 * copy: {
 *   links:    [{link, head?, reveal?}] from seq 0, oldest first (reveal = the
 *             self-press's v_i, as PICKUP gave it),
 *   openings: {[grantId]: {scopes, reasonHash, genesis, uses, lifetime, signature}} -
 *             what the host asked for and the checkpoint signature its press
 *             answered with (edge.grant's reply),
 * }
 * key: what the host read from the key THIS session: {publicKey, head (edge.head()),
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
  if (v.gaps.length || v.verifiedThrough !== h.seq) return fail('gap', { seq: v.gaps.length ? v.gaps[0].from : v.verifiedThrough + 1, detail: { gaps: v.gaps } });

  /* every link is now verified from genesis: their heads, by seq */
  const heads = chain.heads(raw, chain.genesis(deviceId));
  const headAt = (seq) => (seq < 0 ? chain.genesis(deviceId) : heads[seq]);

  const cp = key.checkpoint;
  if (!cp || !same(headAt(cp.seq) || new Uint8Array(0), cp.head) ||
      !chain.verifyCheckpoint({ deviceId, seq: cp.seq, head: cp.head }, cp.signature, key.publicKey)) {
    return fail('checkpoint', { seq: cp ? cp.seq : null });
  }

  /* budgets: each opening, then its self-presses in step order */
  const fields = raw.map((l) => chain.decodeLink(l));
  const openings = copy.openings || {};
  const spends = new Map();
  for (const f of fields) {
    if (f.op === OP.GRANT_CREATE) {
      const o = openings[f.grantId];
      if (!o) return fail('budget-opening-missing', { seq: f.seq, detail: { grantId: f.grantId } });
      const r = grants.verifyBudgetOpening({
        deviceId, publicKey: key.publicKey, link: raw[f.seq], prevHead: headAt(f.seq - 1), head: headAt(f.seq),
        signature: o.signature, scopes: o.scopes, reasonHash: o.reasonHash, genesis: o.genesis, uses: o.uses, lifetime: o.lifetime || 0,
      });
      if (!r.ok || r.grantId !== f.grantId) return fail('budget-opening', { seq: f.seq, detail: { grantId: f.grantId, reason: r.reason || 'grant-id' } });
      spends.set(f.grantId, []);
    } else if ((f.op === OP.SIGN || f.op === OP.DECRYPT) && f.decision === DECISION.SELF_PRESS) {
      const list = spends.get(f.grantId);
      if (!list) return fail('budget-opening-missing', { seq: f.seq, detail: { grantId: f.grantId } });
      const value = entries[f.seq].reveal;
      if (!value || !value.some((x) => x)) return fail('reveal-missing', { seq: f.seq });
      list.push({ seq: f.seq, step: f.grantStep, value, subject: f.subject, mac: hmacSha256(value, f.subject) });
    }
  }
  for (const [grantId, list] of spends) {
    const o = openings[grantId];
    const r = grants.checkSpends(o.genesis, o.uses, list);
    if (!r.ok) return fail('reveal', { seq: list[r.failure.index].seq, detail: { grantId, ...r.failure } });
  }

  /* the debts the copy implies, against the debts the key reports */
  const d = keyDebts(raw);
  if (d.owed.length !== h.owed || d.overflow !== Boolean(h.overflow)) {
    return fail('debts', { detail: { copy: { owed: d.owed, overflow: d.overflow }, key: { owed: h.owed, overflow: Boolean(h.overflow) } } });
  }
  return { ok: true, verifiedThrough: h.seq, head: h.head };
}

module.exports = { verifyCopy };
