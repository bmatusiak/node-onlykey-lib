'use strict';

/**
 * EDGE_NOTE - the agent's own words about what it did (B7 stage 2, onlykey-edge
 * build/okrn-edge-tab.md "Decided 2026-10-04"). Over the same channel as
 * EDGE_REQUEST (0xF7 on Bluetooth; the Worker mailbox later):
 *
 *   {type: 'EDGE_NOTE', v: 1, nonce, seq, reason?, receiptMsg?, txRefused?}
 *
 * from a PAIRED computer, inside its encrypted session (Brad, 2026-10-08: "so the claude key
 * thing is overkill" - no agent key, no signature). A note changes nothing - no state, no
 * debts, no budgets. The phone shows one only for a seq a budget of THAT computer paid; the
 * check is the phone's, at display time, because a note can arrive before the link it talks
 * about is synced.
 *
 *   reason      why the agent made the use (okedge exec --reason): its claim,
 *               shown quoted, plain text, at most 280 bytes
 *   receiptMsg   the receipt's message: shown only when it hashes to the receipt's
 *               msg_hash (receipts.pairReceipts does that check)
 *   txRefused  the key refused a TX start (its status name): the agent's word only;
 *               the key's own evidence is HEAD's refused-TX start counter. `seq` is
 *               the key's head when it happened.
 */
const { randomBytes } = require('../../src/vendor/exports/@noble/ciphers/utils.js');
const { utf8ToBytes, toHex } = require('../../src/bytes');

const TYPE = 'EDGE_NOTE';
const MAX_REASON = 280;
const MAX_RECEIPT_MSG = 1024;
const MAX_TX_REFUSED = 64;

const isHex = (s, n) => typeof s === 'string' && s.length === n * 2 && /^[0-9a-f]+$/i.test(s);
const isU32 = (n) => Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
/* absent, or text of at most max bytes */
const fits = (v, max) => v === undefined || (typeof v === 'string' && utf8ToBytes(v).length <= max);

/** The asking side: a note about `seq`. */
async function build({ seq, reason, receiptMsg, txRefused, nonce = randomBytes(16) }) {
  if (!isU32(seq)) throw new RangeError(`edge note: seq ${seq} is not a u32`);
  if (reason === undefined && receiptMsg === undefined && txRefused === undefined) throw new TypeError('edge note: nothing to say');
  const msg = {
    type: TYPE, v: 1, nonce: toHex(nonce), seq,
    ...(reason !== undefined ? { reason: String(reason) } : {}),
    ...(receiptMsg !== undefined ? { receiptMsg: String(receiptMsg) } : {}),
    ...(txRefused !== undefined ? { txRefused: String(txRefused) } : {}),
  };
  if (!verify(msg).ok) throw new RangeError('edge note: a field is too long');
  return msg;
}

/**
 * The app side: a note well formed and new. seen: nonces already taken. -> {ok} or {ok: false,
 * reason: 'malformed' | 'replayed'}. An app DROPS the rest. Who sent it is the paired computer.
 */
function verify(msg, { seen } = {}) {
  if (!msg || msg.type !== TYPE || msg.v !== 1 || !isHex(msg.nonce, 16) || !isU32(msg.seq)
    || !fits(msg.reason, MAX_REASON) || !fits(msg.receiptMsg, MAX_RECEIPT_MSG) || !fits(msg.txRefused, MAX_TX_REFUSED)
    || (msg.reason === undefined && msg.receiptMsg === undefined && msg.txRefused === undefined)) {
    return { ok: false, reason: 'malformed' };
  }
  if (seen && seen.has(msg.nonce.toLowerCase())) return { ok: false, reason: 'replayed' };
  return { ok: true };
}

module.exports = { TYPE, MAX_REASON, MAX_RECEIPT_MSG, MAX_TX_REFUSED, build, verify };
