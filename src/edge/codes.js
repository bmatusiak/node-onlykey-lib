'use strict';

/**
 * Edge v1 numbers: the byte values inside a 64-byte link, the domain tags the
 * hashes start with, and the ticket codes.
 *
 * WHY THIS FILE EXISTS: the Edge spec (onlykey-edge/build/firmware.md R2-R3,
 * R12-R16, TICKET-CODES.md) names the fields and their order but leaves the
 * numbers to "the plan". The library, the Python vectors
 * (onlykey-edge/vectors/) and the firmware plugin must agree on them byte for
 * byte, so they are written down ONCE, here, and the vectors repeat them from
 * the spec text rather than from this file. Every choice the spec did not make
 * is marked CHOSEN; change it here and in the vectors together, before any key
 * writes a link with it.
 */

/* R3 `op`. CHOSEN: 1-based, in the order the spec lists them; 0 is never a valid op. */
const OP = Object.freeze({
  SIGN: 1,
  DECRYPT: 2,
  FIDO_REG: 3,
  FIDO_AUTH: 4,
  HMAC: 5,
  GRANT_CREATE: 6,
  GRANT_END: 7,
  TICKET: 8,
  PEER_ADD: 9,
  PEER_REMOVE: 10,
  LOSS: 11,
  WIPE: 12,
});

/* R3 `decision` (for op = ticket the byte is the ticket code instead). CHOSEN: 1-based. */
const DECISION = Object.freeze({
  APPROVE: 1,
  DENY: 2,
  TIMEOUT: 3,
  SELF_PRESS: 4,
});

/* R3 `flags`, as the spec numbers the bits. */
const FLAG = Object.freeze({
  PRESS_OBSERVED: 0x01,
  BUDGET_SPENT: 0x02,
  PREV_NO_TICKET: 0x04,
  HISTORY_AT_RISK: 0x08,
});

/* Domain tags, ASCII, exactly as the spec spells them (R2, R7, R12, R16, R21). */
const TAG = Object.freeze({
  GENESIS: 'OKEDGE-GENESIS-v1',
  LINK: 'OKEDGE-LINK-v1',
  CHECKPOINT: 'OKEDGE-CKPT-v1',
  GRANT: 'OKEDGE-GRANT-v1',
  /* CHOSEN: device_id = SHA256(DEVICE || the Edge public key X||Y)[0..16] - the key and edge JS both derive it */
  DEVICE: 'OKEDGE-DEVICE-v1',
  TICKET: 'OKEDGE-TICKET-v1',
  RECEIPT: 'OKEDGE-RCPT-v1',
});

/*
 * TICKET-CODES.md v1. Bit 7 set = alarm, with no lookup needed; a code not in
 * this table is ALSO an alarm (fails closed: a future version or a forged mirror).
 */
const TICKET = Object.freeze({
  0x00: 'OK',
  0x01: 'OK_UNCONFIRMED',
  0x02: 'PARTIAL',
  0x10: 'NOT_USED',
  0x11: 'SUPERSEDED',
  0x20: 'TARGET_REJECTED',
  0x21: 'TARGET_UNREACHABLE',
  0x30: 'ABORTED_BY_AGENT',
  0x31: 'ABORTED_BY_HUMAN',
  0x40: 'AGENT_ERROR',
  0x80: 'USED_DIFFERENTLY',
  0x81: 'SUSPECTED_INJECTION',
  0x82: 'DATA_EXPOSED',
  0x83: 'POLICY_CONCERN',
  0x8f: 'NEEDS_REVIEW',
  0xff: 'UNKNOWN',
});

/** Name and alarm state of a ticket code: alarm = bit 7 OR not a v1 code. */
function ticketCode(code) {
  const name = Object.prototype.hasOwnProperty.call(TICKET, code) ? TICKET[code] : null;
  return {
    code,
    name,
    known: name !== null,
    alarm: (code & 0x80) !== 0 || name === null,
    /* high nibble, so the tab can colour success (0) apart from neutral/failure */
    class: (code >> 4) & 0x0f,
  };
}

/** Reverse lookup for display: OP/DECISION value -> lower-case name, or null. */
function nameOf(table, value) {
  for (const [k, v] of Object.entries(table)) if (v === value) return k.toLowerCase().replace(/_/g, '-');
  return null;
}

module.exports = { OP, DECISION, FLAG, TAG, TICKET, ticketCode, nameOf };
