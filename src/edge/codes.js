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
  /* firmware.md R15a - appended last so the numbers above never move */
  GRANT_HOLD: 13,
  GRANT_RESUME: 14,
  /* mcp-service.md 4.7a: an agent's key registered with a press (subject = grants.agentSubject) */
  AGENT_ADD: 15,
  /*
   * Assigned 2026-10-04 for the spec session (firmware.md R20/R29/R30, okedge sync),
   * appended so nothing above moves.
   * CONTINUE (R28, written by the firmware since 2026-10-04) - the FIRST link of a
   * device's own chain: the next seq after the chain it continues, welded onto the
   * new genesis, grant_id = debts carried, subject = chain.continueSubject. Not
   * written yet: SIBLING_ADD / SIBLING_REMOVE - another key with
   * its own chain, added or removed with a press, subject SHA256("OKEDGE-SIBLING-v1"
   * || pubkey || device_id) (R29); ANCHOR - written by the key only inside a sync
   * Brad approved with a press: slot = sibling index, grant_id = sibling seq,
   * subject SHA256("OKEDGE-ANCHOR-v1" || sibling device_id || seq || head ||
   * checkpoint sig) (R30). PEER_ADD / PEER_REMOVE (9, 10) are the wire's 0x30 / 0x31.
   */
  CONTINUE: 16,
  SIBLING_ADD: 17,
  SIBLING_REMOVE: 18,
  ANCHOR: 19,
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
  /* R16 (2026-10-02 evening): set by the key at the sign - this use owes a ticket (ARMed, or its op/slot covered by a budget) */
  OWES_TICKET: 0x10,
  /* R16: an arm was waiting when the request was primed (a self-press, or a mismatched ARM that was pressed) */
  ARMED: 0x20,
});

/* Domain tags, ASCII, exactly as the spec spells them (R2, R7, R12, R16, R21). */
const TAG = Object.freeze({
  GENESIS: 'OKEDGE-GENESIS-v1',
  CONTINUE: 'OKEDGE-CONTINUE-v1',
  LINK: 'OKEDGE-LINK-v1',
  CHECKPOINT: 'OKEDGE-CKPT-v1',
  GRANT: 'OKEDGE-GRANT-v1',
  /* CHOSEN: device_id = SHA256(DEVICE || the Edge public key X||Y)[0..16] - the key and edge JS both derive it */
  DEVICE: 'OKEDGE-DEVICE-v1',
  TICKET: 'OKEDGE-TICKET-v1',
  RECEIPT: 'OKEDGE-RCPT-v1',
  /* firmware.md R18: a human's press clears every owed ticket at once */
  WAIVE: 'OKEDGE-WAIVE-v1',
  /* firmware.md R13a (2026-10-02): an ARM is bound to the head AND the exact request */
  ARM: 'OKEDGE-ARM-v1',
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

/*
 * The firmware's text replies are "EDGE:xx" only (owner, 2026-10-02: "keep the
 * return strings minimal in firmware") - the words live here, on the host.
 * Must match the soft-key plugin's okplugin_edge.h.
 */
const STATUS = Object.freeze({
  0x00: { name: 'ok', text: 'Done' },
  0x01: { name: 'need-pin', text: 'This key has no PIN set yet, so it has no Edge key' },
  0x02: { name: 'bad-scopes', text: 'A budget has 1 to 4 scopes' },
  0x03: { name: 'scope-not-allowed', text: 'A budget cannot pay for that operation or slot' },
  0x04: { name: 'too-many-uses', text: 'A budget has at most 1024 uses' },
  0x05: { name: 'live-full', text: 'Four budgets are already live' },
  0x06: { name: 'sign-failed', text: 'The key could not sign' },
  0x07: { name: 'no-such-budget', text: 'No live budget has that id' },
  0x08: { name: 'no-ticket-waiting', text: 'That use owes no ticket (or nothing is owed to waive)' },
  0x09: { name: 'not-held', text: 'The key no longer holds that link' },
  0x0a: { name: 'unknown-request', text: 'This key does not know that Edge request' },
  0x0b: { name: 'stale-head', text: 'The chain moved since that head - read the head and arm again' },
  0x0c: { name: 'ticket-owed', text: 'A use is waiting for its ticket - ticket it, or waive in the app' },
  0x0d: { name: 'nothing-to-arm', text: 'No live budget (or every one is on hold)' },
  /* R26 (CHOSEN numbers, pending the spec) */
  0x0e: { name: 'restoring', text: 'The key was restored from a backup - finish the restore in the app first' },
  0x0f: { name: 'replay-mismatch', text: 'That link is not the next one, or does not weld onto the key\x27s head' },
  0x10: { name: 'replay-closed', text: 'Replay is closed: the key is not restoring, or already wrote a link of its own' },
  /* R26 (2026-10-02): replay commits only on the key's own vouch tag */
  0x11: { name: 'not-vouched', text: 'That replay is not vouched by the key - thrown away; everything since the backup is recorded as lost' },
  0x12: { name: 'bad-range', text: 'A loss is #from..#to, at or before the key\'s head' },
});

/** "EDGE:xx" -> {code, name, text}, or null when the text is not an Edge status. */
function parseStatus(text) {
  const m = /^EDGE:([0-9A-Fa-f]{2})/.exec(String(text || ''));
  if (!m) return null;
  const code = parseInt(m[1], 16);
  const s = STATUS[code];
  return { code, name: s ? s.name : 'unknown', text: s ? s.text : `Edge status 0x${m[1]}` };
}

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

module.exports = { OP, DECISION, FLAG, TAG, TICKET, STATUS, parseStatus, ticketCode, nameOf };
