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
 * CHOSEN: `linkhash[ref_seq]` in firmware.md R16 is read as head[ref_seq] (the
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
 * SETTLE (firmware.md R18): a human's press clears every owed receipt at once.
 * The key links it as a receipt (code 0x8F, the press flag, grant_id field =
 * the oldest seq it settles) whose subject lists what it settled:
 *   SHA256("OKEDGE-SETTLE-v1" || each settled seq (u32 LE, oldest first) || overflow (1 byte))
 */
function settleSubject(seqs, overflow) {
  return H(TAG.SETTLE, ...seqs.map((s) => u32le(s)), u8(overflow ? 1 : 0));
}

/* the key keeps up to this many owed uses (firmware R16); older ones only a settle clears */
const OWED_MAX = 4;

/* a sign/decrypt that went through owes a receipt, pressed or self-pressed (R16) */
const OWING = new Set([DECISION.APPROVE, DECISION.SELF_PRESS]);

/**
 * The key's own debt list, replayed over the chain (firmware R16-R18), so a
 * host can compare its copy with what HEAD reports (R27):
 *   - an approved sign/decrypt is pushed; past OWED_MAX the oldest falls off
 *     for good and `overflow` is set (only a settle clears it);
 *   - a receipt pays its ref_seq if that use is still on the list;
 *   - a SETTLE (0x8F, the press flag, the subject over exactly this list and
 *     this overflow) clears the list and the overflow.
 * Nothing else changes it: a deny, a timeout, a grant-end, a LOSS.
 *
 * The list does not refill: once a use fell off, a later receipt for a newer
 * one does not bring it back. (Taking "the newest 4 unpaid" instead disagrees
 * with the key after a 5th use and one receipt - 4 waiting by that count, 3
 * owed + overflow on the key.)
 *
 * Replay from the chain's first link; a copy that starts later cannot know
 * the list it started with.
 * -> {owed: [seq, oldest first], overflow, dropped: [seq] (fell off, never paid by a receipt)}
 */
function keyDebts(entries) {
  let owed = [];
  let overflow = false;
  const dropped = [];
  for (const e of entries) {
    const f = decodeLink(e instanceof Uint8Array ? e : e.link);
    /* R16: the KEY decided at the sign, and wrote it into the link (owes_receipt) - the chain could not replay it */
    if ((f.op === OP.SIGN || f.op === OP.DECRYPT) && OWING.has(f.decision) && (f.flags & FLAG.OWES_RECEIPT)) {
      if (owed.length === OWED_MAX) { dropped.push(owed.shift()); overflow = true; }
      owed.push(f.seq);
    } else if (f.op === OP.RECEIPT) {
      if (f.code === 0x8f && (f.flags & FLAG.PRESS_OBSERVED) && same(f.subject, settleSubject(owed, overflow))) {
        owed = [];
        overflow = false;
      } else {
        owed = owed.filter((q) => q !== f.refSeq);
      }
    }
  }
  return { owed, overflow, dropped };
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
    /* a SETTLE: 0x8F with the press flag, whose subject recomputes from the uses it cleared */
    if (f.code === 0x8f && (f.flags & FLAG.PRESS_OBSERVED)) {
      const owed = uses.filter((u) => u.seq < f.seq && u.seq >= f.refSeq && !u.receipt && !u.settledBy && OWES(u));
      const listed = owed.map((u) => u.seq);
      const overflow = same(f.subject, settleSubject(listed, true));
      if (overflow || same(f.subject, settleSubject(listed, false))) {
        for (const u of owed) { u.status = 'settled'; u.settledBy = f.seq; }
        if (overflow) {
          for (const u of uses) {
            if (u.seq < f.refSeq && !u.receipt && !u.settledBy && OWES(u)) { u.status = 'settled-unlisted'; u.settledBy = f.seq; }
          }
        }
        continue;
      }
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
   * WAITING vs MISSING (firmware.md R16, as the owner changed it 2026-10-02):
   * every approved use - pressed or self-pressed - owes a receipt, and the key
   * keeps the latest OWED_MAX owed uses, any of which still takes its receipt
   * ("waiting"). An older one fell off the key's list: only a settle clears it
   * ("missing"). Nothing else - a deny, a timeout, a lock - clears a debt.
   */
  const onKey = new Set(keyDebts(rows).owed);
  for (const u of uses) if (u.status === 'missing' && onKey.has(u.seq)) u.status = 'waiting';
  return { uses, orphans };
}

module.exports = { messageHash, receiptSubject, settleSubject, pairReceipts, keyDebts, OWED_MAX };
