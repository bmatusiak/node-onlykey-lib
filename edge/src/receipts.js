'use strict';

/**
 * Edge receipts (spec L3): pairing each sign/decrypt with the agent's receipt.
 *
 * After every use the agent files a one-byte code and a short message
 * (RECEIPT-CODES.md). The key never sees the message: it links
 *
 *   op = receipt, decision = code, grant_id field = ref_seq,
 *   subject = SHA256("OKEDGE-RECEIPT-v1" || ref_seq (u32 LE) || head[ref_seq]
 *                    || code (u8) || msg_hash)
 *   msg_hash = SHA256(message as UTF-8)
 *
 * CHOSEN: `linkhash[ref_seq]` in SPEC.md R16 is read as head[ref_seq] (the
 * weld after that link), which commits to the whole history up to it and is
 * kept beside each link in the key's ring (R5).
 *
 * The message arrives later by sync, from an untrusted copy, so a host shows it
 * only if recomputing the subject from it matches the receipt link (spec S5); a
 * message that does not match is shown as missing, never as text.
 */
const { OP, DECISION, FLAG, TAG, receiptCode } = require('./codes');
const { decodeLink } = require('./chain');
const { H, u32le, u8, bytes32, same } = require('./hash');
const { utf8ToBytes } = require('../../src/bytes');

/*
 * A RECEIPT'S MESSAGE CHECK, KEPT WITH ITS LINK (ok-rn on a Galaxy A13, 2026-10-07:
 * pairing ~110 ms a sync - two SHA-256 per receipt, every receipt, every sync). The
 * answer depends only on the receipt link, the use's head and the message text: the
 * same three objects/text, the same answer. Keyed by the link's bytes object, so a
 * host that keeps its copy in memory (ok-rn) checks only new receipts and changed
 * messages; a copy read fresh is new objects and is checked in full. Links are
 * never changed in place.
 */
const messageChecked = new WeakMap();

function messageHash(message) {
  return H(utf8ToBytes(String(message)));
}

function receiptSubject({ refSeq, refHead, code, msgHash }) {
  return H(TAG.RECEIPT, u32le(refSeq), bytes32(refHead, 'refHead'), u8(code), bytes32(msgHash, 'msgHash'));
}

const OWES = (u) => u.status !== 'no-receipt-owed';

/**
 * Pair receipts with the uses they answer.
 *
 * entries: [{link, head}] in chain order (head = the weld stored with the
 *          link; needed to check a message against its receipt)
 * messages: {[refSeq]: text} - receipt messages from sync, untrusted
 *
 * -> {uses: [{seq, op, status, receipt?, message?}], orphans: [{seq, refSeq, reason}]}
 *    status: receipted | alarm | waiting | missing | no-receipt-owed
 *            (waiting = the latest use, still able to get its receipt)
 *    receipt: {seq, code, name, alarm}; message: the text, only when it matches,
 *            else null with messageStatus 'none' | 'mismatch' | 'unchecked'
 *    orphans: receipts for a seq that is not a use (or not one that came
 *             before), or a second receipt for the same use
 */
/*
 * SETTLE (SPEC.md R18): a person's press clears the owed receipt. The key links it as a
 * receipt (code 0x8F, the press flag, grant_id field = the settled seq) whose subject names it:
 *   SHA256("OKEDGE-SETTLE-v1" || the settled seq (u32 LE))
 */
function settleSubject(seq) {
  return H(TAG.SETTLE, u32le(seq));
}

/* a self-pressed sign/decrypt the key marked owes_receipt owes one (R16) */
const OWING = new Set([DECISION.APPROVE, DECISION.SELF_PRESS]);

/**
 * The key's debt, replayed over the chain (SPEC.md R16-R18), so a host can compare its copy
 * with what HEAD reports (R27). The key keeps ONE owed use: nothing starts while one is owed
 * (Brad, 2026-10-10: "Drop the owed list = yes").
 *   - a use the key marked owes_receipt becomes the owed use;
 *   - a receipt for it pays it;
 *   - a SETTLE (0x8F, the press flag, the subject over its seq) clears it.
 * Replay from the chain's first link; a copy that starts later cannot know what it started with.
 * -> {owed: [seq] or []}
 */
function keyDebts(entries) {
  let owed = null;
  for (const e of entries) {
    const f = decodeLink(e instanceof Uint8Array ? e : e.link);
    /* R16: the KEY decided at the sign, and wrote it into the link (owes_receipt) - the chain could not replay it */
    if ((f.op === OP.SIGN || f.op === OP.DECRYPT) && OWING.has(f.decision) && (f.flags & FLAG.OWES_RECEIPT)) owed = f.seq;
    else if (f.op === OP.RECEIPT && owed !== null) {
      const settled = f.code === 0x8f && (f.flags & FLAG.PRESS_OBSERVED) && same(f.subject, settleSubject(owed));
      if (settled || f.refSeq === owed) owed = null;
    }
  }
  return { owed: owed === null ? [] : [owed] };
}

function pairReceipts(entries, messages = {}) {
  const rows = entries.map((e) => (e instanceof Uint8Array ? { link: e, head: null } : e));
  const bySeq = new Map();
  const uses = [];
  const orphans = [];
  for (const r of rows) {
    const f = decodeLink(r.link);
    bySeq.set(f.seq, { f, head: r.head });
    if (f.op === OP.SIGN || f.op === OP.DECRYPT) {
      /* every field from the start, so the generated .d.ts knows them all */
      uses.push({
        seq: f.seq,
        op: f.op,
        /* a use owes only when the key marked it (R16) */
        status: !(f.flags & FLAG.OWES_RECEIPT) ? 'no-receipt-owed' : 'missing',
        /** @type {{seq: number, code: number, name: string | null, alarm: boolean} | null} */
        receipt: null,
        /** @type {string | null} */
        message: null,
        /** @type {'none' | 'match' | 'mismatch' | 'unchecked' | null} */
        messageStatus: null,
        /** @type {number | null} the settle link that cleared it, if a settle did */
        settledBy: null,
      });
    }
  }
  const useAt = new Map(uses.map((u) => [u.seq, u]));
  for (const r of rows) {
    const f = decodeLink(r.link);
    if (f.op !== OP.RECEIPT) continue;
    /* a SETTLE: 0x8F with the press flag, whose subject is over the use it cleared */
    if (f.code === 0x8f && (f.flags & FLAG.PRESS_OBSERVED) && same(f.subject, settleSubject(f.refSeq))) {
      const u = useAt.get(f.refSeq);
      if (u && u.seq < f.seq && !u.receipt && !u.settledBy && OWES(u)) { u.status = 'settled'; u.settledBy = f.seq; continue; }
    }
    const use = useAt.get(f.refSeq);
    if (!use || f.refSeq >= f.seq) { orphans.push({ seq: f.seq, refSeq: f.refSeq, reason: 'not-a-use' }); continue; }
    if (use.receipt) { orphans.push({ seq: f.seq, refSeq: f.refSeq, reason: 'second-receipt' }); continue; }
    const c = receiptCode(f.code);
    use.receipt = { seq: f.seq, code: c.code, name: c.name, alarm: c.alarm };
    use.status = c.alarm ? 'alarm' : 'receipted';
    const text = Object.prototype.hasOwnProperty.call(messages, f.refSeq) ? messages[f.refSeq] : undefined;
    const refHead = bySeq.get(f.refSeq).head;
    if (text === undefined) use.messageStatus = 'none';
    else if (!refHead) use.messageStatus = 'unchecked';
    else {
      const kept = messageChecked.get(r.link);
      let match;
      if (kept && kept.text === text && kept.refHead === refHead) match = kept.match;
      else {
        match = same(receiptSubject({ refSeq: f.refSeq, refHead, code: f.code, msgHash: messageHash(text) }), f.subject);
        messageChecked.set(r.link, { text, refHead, match });
      }
      if (match) { use.message = String(text); use.messageStatus = 'match'; }
      else use.messageStatus = 'mismatch';
    }
  }
  /*
   * WAITING vs MISSING (SPEC.md R16): the use the key still owes takes its receipt ("waiting");
   * any other unreceipted use that owed is "missing" - only a settle would have cleared it.
   * Nothing else - a lock, a reboot, an end - clears a debt.
   */
  const onKey = new Set(keyDebts(rows).owed);
  for (const u of uses) if (u.status === 'missing' && onKey.has(u.seq)) u.status = 'waiting';
  return { uses, orphans };
}

module.exports = { messageHash, receiptSubject, settleSubject, pairReceipts, keyDebts };
