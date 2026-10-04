'use strict';

/**
 * EDGE_NOTE - the agent's own words about what it did (B7 stage 2, onlykey-edge
 * build/okrn-edge-tab.md "Decided 2026-10-04"). Over the same channel as
 * EDGE_REQUEST (0xF7 on Bluetooth; the Worker mailbox later):
 *
 *   {type: 'EDGE_NOTE', v: 1, agent, nonce, seq, reason?, ticketMsg?, armRefused?, signature}
 *
 * signed by the agent's REGISTERED request key. A note changes nothing - no
 * state, no debts, no budgets. The phone drops one from a key it did not
 * register, and shows one only for a seq that is that agent's (its budget paid
 * it); the check is the phone's, at display time, because a note can arrive
 * before the link it talks about is synced.
 *
 *   reason      why the agent made the use (okedge exec --reason): its claim,
 *               shown quoted, plain text, at most 280 bytes
 *   ticketMsg   the ticket's message: shown only when it hashes to the ticket's
 *               msg_hash (tickets.pairTickets does that check)
 *   armRefused  the key refused an ARM (its status name): the agent's word only;
 *               the key's own evidence is HEAD's refused-ARM counter. `seq` is
 *               the key's head when it happened.
 */
const { ed25519 } = require('../vendor/exports/@noble/curves/ed25519.js');
const { randomBytes } = require('../vendor/exports/@noble/ciphers/utils.js');
const { utf8ToBytes, toHex, fromHex, concat } = require('../bytes');

const TYPE = 'EDGE_NOTE';
const TAG = 'OKEDGE-NOTE-v1';
const MAX_REASON = 280;
const MAX_TICKET_MSG = 1024;
const MAX_ARM_REFUSED = 64;

const isHex = (s, n) => typeof s === 'string' && s.length === n * 2 && /^[0-9a-f]+$/i.test(s);
const isU32 = (n) => Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
const u32 = (n) => Uint8Array.of(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff);
const u16 = (n) => Uint8Array.of(n & 0xff, (n >>> 8) & 0xff);

/* one field: present (1) + u16 length + bytes, or absent (0) - so "no reason" and "empty reason" differ */
function field(text, max, name) {
  if (text === undefined || text === null) return Uint8Array.of(0);
  const b = utf8ToBytes(String(text));
  if (b.length > max) throw new RangeError(`edge note: ${name} is ${b.length} bytes, at most ${max}`);
  return concat([Uint8Array.of(1), u16(b.length), b]);
}

/** The signed bytes of a note. */
function body({ agent, nonce, seq, reason, ticketMsg, armRefused }) {
  return concat([
    utf8ToBytes(TAG), fromHex(agent), fromHex(nonce), u32(seq),
    field(reason, MAX_REASON, 'reason'), field(ticketMsg, MAX_TICKET_MSG, 'ticketMsg'), field(armRefused, MAX_ARM_REFUSED, 'armRefused'),
  ]);
}

/** The agent side: a signed note about `seq`. */
async function build({ signer, seq, reason, ticketMsg, armRefused, nonce = randomBytes(16) }) {
  if (!isU32(seq)) throw new RangeError(`edge note: seq ${seq} is not a u32`);
  if (reason === undefined && ticketMsg === undefined && armRefused === undefined) throw new TypeError('edge note: nothing to say');
  const msg = {
    type: TYPE, v: 1, agent: toHex(signer.publicKey), nonce: toHex(nonce), seq,
    ...(reason !== undefined ? { reason: String(reason) } : {}),
    ...(ticketMsg !== undefined ? { ticketMsg: String(ticketMsg) } : {}),
    ...(armRefused !== undefined ? { armRefused: String(armRefused) } : {}),
  };
  msg.signature = toHex(await signer.sign(body(msg)));
  return msg;
}

/**
 * The app side: a note from a registered agent, signed, well formed and new.
 * registered: agent public keys (hex) registered with a press; seen: nonces
 * already taken. -> {ok} or {ok: false, reason: 'malformed' | 'unregistered' |
 * 'bad-signature' | 'replayed'}. An app DROPS the rest.
 */
function verify(msg, { registered, seen } = {}) {
  if (!msg || msg.type !== TYPE || !isHex(msg.agent, 32)) return { ok: false, reason: 'malformed' };
  const agent = msg.agent.toLowerCase();
  if (!(registered || []).some((k) => String(k).toLowerCase() === agent)) return { ok: false, reason: 'unregistered' };
  const str = (v) => v === undefined || typeof v === 'string';
  if (msg.v !== 1 || !isHex(msg.nonce, 16) || !isHex(msg.signature, 64) || !isU32(msg.seq)
    || !str(msg.reason) || !str(msg.ticketMsg) || !str(msg.armRefused)
    || (msg.reason === undefined && msg.ticketMsg === undefined && msg.armRefused === undefined)) {
    return { ok: false, reason: 'malformed' };
  }
  let good = false;
  try {
    good = ed25519.verify(fromHex(msg.signature), body(msg), fromHex(msg.agent));
  } catch { good = false; } /* an oversize field throws in body(): not a note we take */
  if (!good) return { ok: false, reason: 'bad-signature' };
  if (seen && seen.has(msg.nonce.toLowerCase())) return { ok: false, reason: 'replayed' };
  return { ok: true };
}

module.exports = { TYPE, MAX_REASON, MAX_TICKET_MSG, MAX_ARM_REFUSED, body, build, verify };
