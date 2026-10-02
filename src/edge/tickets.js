'use strict';

/**
 * Edge tickets (spec L3): pairing each sign/decrypt with the agent's ticket.
 *
 * After every use the agent files a one-byte code and a short message
 * (TICKET-CODES.md). The key never sees the message: it links
 *
 *   op = ticket, decision = code, grant_id field = ref_seq,
 *   subject = SHA256("OKEDGE-TICKET-v1" || ref_seq (u32 LE) || head[ref_seq]
 *                    || code (u8) || msg_hash)
 *   msg_hash = SHA256(message as UTF-8)
 *
 * CHOSEN: `linkhash[ref_seq]` in firmware.md R16 is read as head[ref_seq] (the
 * weld after that link), which commits to the whole history up to it and is
 * kept beside each link in the key's ring (R5).
 *
 * The message arrives later by sync, from an untrusted copy, so a host shows it
 * only if recomputing the subject from it matches the ticket link (spec S5); a
 * message that does not match is shown as missing, never as text.
 */
const { OP, DECISION, FLAG, TAG, ticketCode } = require('./codes');
const { decodeLink } = require('./chain');
const { H, u32le, u8, bytes32, same } = require('./hash');
const { utf8ToBytes } = require('../bytes');

function messageHash(message) {
  return H(utf8ToBytes(String(message)));
}

function ticketSubject({ refSeq, refHead, code, msgHash }) {
  return H(TAG.TICKET, u32le(refSeq), bytes32(refHead, 'refHead'), u8(code), bytes32(msgHash, 'msgHash'));
}

/* a decision that never reached a result owes no ticket */
const NO_TICKET_OWED = new Set([DECISION.DENY, DECISION.TIMEOUT]);
const OWES = (u) => u.status !== 'no-ticket-owed';

/**
 * Pair tickets with the uses they answer.
 *
 * entries: [{link, head}] in chain order (head = the weld stored with the
 *          link; needed to check a message against its ticket)
 * messages: {[refSeq]: text} - ticket messages from sync, untrusted
 *
 * -> {uses: [{seq, op, status, ticket?, message?}], orphans: [{seq, refSeq, reason}]}
 *    status: ticketed | alarm | waiting | missing | no-ticket-owed
 *            (waiting = the latest use, still able to get its ticket)
 *    ticket: {seq, code, name, alarm}; message: the text, only when it matches,
 *            else null with messageStatus 'none' | 'mismatch' | 'unchecked'
 *    orphans: tickets for a seq that is not a use (or not one that came
 *             before), or a second ticket for the same use
 */
/*
 * WAIVE (firmware.md R18): a human's press clears every owed ticket at once.
 * The key links it as a ticket (code 0x8F, the press flag, grant_id field =
 * the oldest seq it waives) whose subject lists what it waived:
 *   SHA256("OKEDGE-WAIVE-v1" || each waived seq (u32 LE, oldest first) || overflow (1 byte))
 */
function waiveSubject(seqs, overflow) {
  return H(TAG.WAIVE, ...seqs.map((s) => u32le(s)), u8(overflow ? 1 : 0));
}

/* the key keeps up to this many owed uses (firmware R16); older ones only a waive clears */
const OWED_MAX = 4;

/* a sign/decrypt that went through owes a ticket, pressed or self-pressed (R16) */
const OWING = new Set([DECISION.APPROVE, DECISION.SELF_PRESS]);

/**
 * The key's own debt list, replayed over the chain (firmware R16-R18), so a
 * host can compare its copy with what HEAD reports (R27):
 *   - an approved sign/decrypt is pushed; past OWED_MAX the oldest falls off
 *     for good and `overflow` is set (only a waive clears it);
 *   - a ticket pays its ref_seq if that use is still on the list;
 *   - a WAIVE (0x8F, the press flag, the subject over exactly this list and
 *     this overflow) clears the list and the overflow.
 * Nothing else changes it: a deny, a timeout, a grant-end, a LOSS.
 *
 * The list does not refill: once a use fell off, a later ticket for a newer
 * one does not bring it back. (Taking "the newest 4 unpaid" instead disagrees
 * with the key after a 5th use and one ticket - 4 waiting by that count, 3
 * owed + overflow on the key.)
 *
 * Replay from the chain's first link; a copy that starts later cannot know
 * the list it started with.
 * -> {owed: [seq, oldest first], overflow, dropped: [seq] (fell off, never paid by a ticket)}
 */
function keyDebts(entries) {
  let owed = [];
  let overflow = false;
  const dropped = [];
  for (const e of entries) {
    const f = decodeLink(e instanceof Uint8Array ? e : e.link);
    if ((f.op === OP.SIGN || f.op === OP.DECRYPT) && OWING.has(f.decision)) {
      if (owed.length === OWED_MAX) { dropped.push(owed.shift()); overflow = true; }
      owed.push(f.seq);
    } else if (f.op === OP.TICKET) {
      if (f.code === 0x8f && (f.flags & FLAG.PRESS_OBSERVED) && same(f.subject, waiveSubject(owed, overflow))) {
        owed = [];
        overflow = false;
      } else {
        owed = owed.filter((q) => q !== f.refSeq);
      }
    }
  }
  return { owed, overflow, dropped };
}

function pairTickets(entries, messages = {}) {
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
        status: NO_TICKET_OWED.has(f.decision) ? 'no-ticket-owed' : 'missing',
        /** @type {{seq: number, code: number, name: string | null, alarm: boolean} | null} */
        ticket: null,
        /** @type {string | null} */
        message: null,
        /** @type {'none' | 'match' | 'mismatch' | 'unchecked' | null} */
        messageStatus: null,
        /** @type {number | null} the waive link that cleared it, if a waive did */
        waivedBy: null,
      });
    }
  }
  const useAt = new Map(uses.map((u) => [u.seq, u]));
  for (const r of rows) {
    const f = decodeLink(r.link);
    if (f.op !== OP.TICKET) continue;
    /* a WAIVE: 0x8F with the press flag, whose subject recomputes from the uses it cleared */
    if (f.code === 0x8f && (f.flags & FLAG.PRESS_OBSERVED)) {
      const owed = uses.filter((u) => u.seq < f.seq && u.seq >= f.refSeq && !u.ticket && !u.waivedBy && OWES(u));
      const listed = owed.map((u) => u.seq);
      const overflow = same(f.subject, waiveSubject(listed, true));
      if (overflow || same(f.subject, waiveSubject(listed, false))) {
        for (const u of owed) { u.status = 'waived'; u.waivedBy = f.seq; }
        if (overflow) {
          for (const u of uses) {
            if (u.seq < f.refSeq && !u.ticket && !u.waivedBy && OWES(u)) { u.status = 'waived-unlisted'; u.waivedBy = f.seq; }
          }
        }
        continue;
      }
    }
    const use = useAt.get(f.refSeq);
    if (!use || f.refSeq >= f.seq) { orphans.push({ seq: f.seq, refSeq: f.refSeq, reason: 'not-a-use' }); continue; }
    if (use.ticket) { orphans.push({ seq: f.seq, refSeq: f.refSeq, reason: 'second-ticket' }); continue; }
    const c = ticketCode(f.code);
    use.ticket = { seq: f.seq, code: c.code, name: c.name, alarm: c.alarm };
    use.status = c.alarm ? 'alarm' : 'ticketed';
    const text = Object.prototype.hasOwnProperty.call(messages, f.refSeq) ? messages[f.refSeq] : undefined;
    const refHead = bySeq.get(f.refSeq).head;
    if (text === undefined) use.messageStatus = 'none';
    else if (!refHead) use.messageStatus = 'unchecked';
    else {
      const subject = ticketSubject({ refSeq: f.refSeq, refHead, code: f.code, msgHash: messageHash(text) });
      if (same(subject, f.subject)) { use.message = String(text); use.messageStatus = 'match'; }
      else use.messageStatus = 'mismatch';
    }
  }
  /*
   * WAITING vs MISSING (firmware.md R16, as the owner changed it 2026-10-02):
   * every approved use - pressed or self-pressed - owes a ticket, and the key
   * keeps the latest OWED_MAX owed uses, any of which still takes its ticket
   * ("waiting"). An older one fell off the key's list: only a waive clears it
   * ("missing"). Nothing else - a deny, a timeout, a lock - clears a debt.
   */
  const onKey = new Set(keyDebts(rows).owed);
  for (const u of uses) if (u.status === 'missing' && onKey.has(u.seq)) u.status = 'waiting';
  return { uses, orphans };
}

module.exports = { messageHash, ticketSubject, waiveSubject, pairTickets, keyDebts, OWED_MAX };
