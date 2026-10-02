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
const { OP, DECISION, TAG, ticketCode } = require('./codes');
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

/**
 * Pair tickets with the uses they answer.
 *
 * entries: [{link, head}] in chain order (head = the weld stored with the
 *          link; needed to check a message against its ticket)
 * messages: {[refSeq]: text} - ticket messages from sync, untrusted
 *
 * -> {uses: [{seq, op, status, ticket?, message?}], orphans: [{seq, refSeq, reason}]}
 *    status: ticketed | alarm | missing | no-ticket-owed
 *    ticket: {seq, code, name, alarm}; message: the text, only when it matches,
 *            else null with messageStatus 'none' | 'mismatch' | 'unchecked'
 *    orphans: tickets for a seq that is not a use (or not one that came
 *             before), or a second ticket for the same use
 */
function pairTickets(entries, messages = {}) {
  const rows = entries.map((e) => (e instanceof Uint8Array ? { link: e, head: null } : e));
  const bySeq = new Map();
  const uses = [];
  const orphans = [];
  for (const r of rows) {
    const f = decodeLink(r.link);
    bySeq.set(f.seq, { f, head: r.head });
    if (f.op === OP.SIGN || f.op === OP.DECRYPT) {
      uses.push({ seq: f.seq, op: f.op, status: NO_TICKET_OWED.has(f.decision) ? 'no-ticket-owed' : 'missing' });
    }
  }
  const useAt = new Map(uses.map((u) => [u.seq, u]));
  for (const r of rows) {
    const f = decodeLink(r.link);
    if (f.op !== OP.TICKET) continue;
    const use = useAt.get(f.refSeq);
    if (!use || f.refSeq >= f.seq) { orphans.push({ seq: f.seq, refSeq: f.refSeq, reason: 'not-a-use' }); continue; }
    if (use.ticket) { orphans.push({ seq: f.seq, refSeq: f.refSeq, reason: 'second-ticket' }); continue; }
    const c = ticketCode(f.code);
    use.ticket = { seq: f.seq, code: c.code, name: c.name, alarm: c.alarm };
    use.status = c.alarm ? 'alarm' : 'ticketed';
    use.message = null;
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
  return { uses, orphans };
}

module.exports = { messageHash, ticketSubject, pairTickets };
