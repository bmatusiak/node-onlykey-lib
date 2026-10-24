'use strict';

/**
 * edge/src/history.js - a chain copy as BUDGET HISTORY: what was approved, what each use did, how each
 * budget ended. For any host that shows a key's history from its copy (Brad, 2026-10-24: "budget
 * history ... the block chain storage should be loaded by the desktop app") - first the ok-edge
 * desktop app for a hard key, from the CLI's records in ~/.onlykey-js; one function, so the CLI and
 * the apps say the same.
 *
 * In: a copy as edge/cli/copy.js keeps it - links [{link (hex|bytes), head?}], openings [{grantId,
 * reason, scopes, uses, lifetime, opened, from}], notes {reasons: {seq: text}, messages: {seq: text},
 * seen: {seq: ms}}. Out: newest first -
 *   budgets: [{grantId, seq, reason, scopes, uses, lifetime, opened, from,
 *              spends: [{seq, op, slot, step, intent, receipt: {seq, code, name, message} | null}],
 *              ended: {seq, how} | null}]
 *   presses: [{seq, op, slot, intent, receipt}]      uses outside a budget (a pressed sign/decrypt)
 *   losses:  [{seq, from, to}]                        ranges accepted as lost (R24)
 *
 * Nothing here verifies: it describes. Whether the copy verifies is the copy check's answer (R27),
 * shown beside it. Reasons and messages are the agent's own text: returned as text, never interpreted.
 */

const chain = require('./chain');
const codes = require('./codes');

const { OP, DECISION } = codes;
const END_HOW = { 1: 'completed', 2: 'revoked', 3: 'settled' };

const bytesOf = (l) => (l instanceof Uint8Array ? l : Uint8Array.from(Buffer.from(String(l), 'hex')));

function budgetHistory(copy) {
  const links = (copy && copy.links) || [];
  const notes = (copy && copy.notes) || {};
  const reasons = notes.reasons || {};
  const messages = notes.messages || {};
  const openings = new Map(((copy && copy.openings) || []).map((o) => [o.grantId, o]));
  const decoded = links.map((e) => chain.decodeLink(bytesOf(e.link || e)));

  /* receipts by the seq they answer */
  const receiptFor = new Map();
  for (const f of decoded) {
    if (f.op !== OP.RECEIPT) continue;
    /* the receipt's words: a note names the USE it talks about (edge/src/note.js), some hosts the receipt's own seq */
    receiptFor.set(f.refSeq, { seq: f.seq, code: f.code, name: codes.RECEIPT[f.code] || `0x${f.code.toString(16)}`, message: messages[f.seq] || messages[f.refSeq] || null });
  }

  const budgets = new Map();
  const presses = [];
  const losses = [];
  for (const f of decoded) {
    if (f.op === OP.GRANT_CREATE) {
      const o = openings.get(f.grantId) || {};
      budgets.set(f.grantId, {
        grantId: f.grantId, seq: f.seq, reason: o.reason || null, scopes: o.scopes || [], uses: o.uses || null,
        lifetime: o.lifetime || 0, opened: o.opened || null, from: o.from || null, spends: [], ended: null,
      });
    } else if ((f.op === OP.SIGN || f.op === OP.DECRYPT) && f.decision === DECISION.SELF_PRESS) {
      /* a spend of a budget whose opening is not in this copy (opened behind a loss): still listed */
      if (!budgets.has(f.grantId)) {
        const o = openings.get(f.grantId) || {};
        budgets.set(f.grantId, { grantId: f.grantId, seq: null, reason: o.reason || null, scopes: o.scopes || [], uses: o.uses || null, lifetime: o.lifetime || 0, opened: o.opened || null, from: o.from || null, spends: [], ended: null });
      }
      budgets.get(f.grantId).spends.push({ seq: f.seq, op: f.op === OP.SIGN ? 'sign' : 'decrypt', slot: f.slot, step: f.grantStep, intent: reasons[f.seq] || null, receipt: receiptFor.get(f.seq) || null });
    } else if (f.op === OP.SIGN || f.op === OP.DECRYPT) {
      presses.push({ seq: f.seq, op: f.op === OP.SIGN ? 'sign' : 'decrypt', slot: f.slot, intent: reasons[f.seq] || null, receipt: receiptFor.get(f.seq) || null });
    } else if (f.op === OP.GRANT_END) {
      const b = budgets.get(f.grantId);
      if (b) b.ended = { seq: f.seq, how: END_HOW[f.decision] || `end ${f.decision}` };
    } else if (f.op === OP.LOSS) {
      const to = (f.subject[0] | (f.subject[1] << 8) | (f.subject[2] << 16) | (f.subject[3] << 24)) >>> 0;
      losses.push({ seq: f.seq, from: f.grantId, to: to === 0xffffffff ? f.seq - 1 : to });
    }
  }
  const newest = (a, b) => (b.seq ?? b.spends[0]?.seq ?? 0) - (a.seq ?? a.spends[0]?.seq ?? 0);
  return {
    budgets: [...budgets.values()].sort(newest),
    presses: presses.reverse(),
    losses: losses.reverse(),
  };
}

module.exports = { budgetHistory, END_HOW };
