'use strict';

/**
 * Edge v1 numbers: the byte values inside a 64-byte link, the domain tags the
 * hashes start with, and the receipt codes.
 *
 * WHY THIS FILE EXISTS: the Edge spec (onlykey-edge/build/firmware.md R2-R3,
 * R12-R16, RECEIPT-CODES.md) names the fields and their order but leaves the
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
  GRANT_CREATE: 6,
  GRANT_END: 7,
  RECEIPT: 8,
  LOSS: 11,
  /* firmware.md R15a - appended last so the numbers above never move */
  GRANT_HOLD: 13,
  GRANT_RESUME: 14,
  /* RETIRED 2026-10-08 (Brad: "so the claude key thing is overkill"): the key no longer writes it; kept so a chain that has one still reads; never reused */
  AGENT_ADD: 15,
  /*
   * CONTINUE (R28) - the FIRST link of a device's own chain: the next seq after the chain
   * it continues, welded onto the new genesis, grant_id = debts carried, subject =
   * chain.continueSubject. Every restore writes one (2026-10-08).
   */
  CONTINUE: 16,
  /*
   * v1 (2026-10-08): 3-5 (FIDO, HMAC - never linked), 9-10 (peers), 12 (wipe, R9 dropped)
   * and 17-20 (siblings, anchor, sync) are unused: the key writes a link only for a press
   * or a use an approved budget pays (Brad), and pairing and sync are the app's.
   */
});

/* R3 `decision` (for op = receipt the byte is the receipt code instead). CHOSEN: 1-based. */
const DECISION = Object.freeze({
  APPROVE: 1,
  DENY: 2,
  TIMEOUT: 3,
  SELF_PRESS: 4,
});

/*
 * How a budget ended: the `decision` byte of its grant-end link (firmware end_budget). Brad,
 * 2026-10-10: "budgets should auto complete once fufilled" - the key ends a budget itself when
 * its last use is receipted; a revoke or a settle ends it early, a settle flagged incomplete.
 * Expiry and a lock or reboot write no link.
 */
const END = Object.freeze({
  COMPLETED: 1,
  REVOKED: 2,
  SETTLED: 3,
});

/* R3 `flags`, as the spec numbers the bits. */
const FLAG = Object.freeze({
  PRESS_OBSERVED: 0x01,
  BUDGET_SPENT: 0x02,
  /* R16: set by the key on every budget use - it owes a receipt. (v1, 2026-10-08: bits 2, 3 and 5 are unused - no "previous use had no receipt", no receipts' "history at risk", no "started": a budget only pays a started request) */
  OWES_RECEIPT: 0x10,
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
  RECEIPT: 'OKEDGE-RECEIPT-v1',
  /* firmware.md R18: a human's press clears every owed receipt at once */
  SETTLE: 'OKEDGE-SETTLE-v1',
  /*
   * firmware.md R13a/R13b: a TX start is bound to the head, the exact request and
   * what the use is for (the intent, welded into the link). One label since the
   * rename (2026-10-07): the ARM-v1/-v2 split is gone.
   */
  TX: 'OKEDGE-TX-v1',
  INTENT: 'OKEDGE-INTENT-v1',
});

/*
 * RECEIPT-CODES.md v1. Bit 7 set = alarm, with no lookup needed; a code not in
 * this table is ALSO an alarm (fails closed: a future version or a forged mirror).
 */
const RECEIPT = Object.freeze({
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
  0x08: { name: 'no-receipt-waiting', text: 'That use owes no receipt (or nothing is owed to settle)' },
  0x09: { name: 'not-held', text: 'The key no longer holds that link' },
  0x0a: { name: 'unknown-request', text: 'This key does not know that Edge request' },
  0x0b: { name: 'stale-head', text: 'The chain moved since that head - read the head and start again' },
  0x0c: { name: 'receipt-owed', text: 'A use is waiting for its receipt - receipt it, or settle in the app' },
  0x0d: { name: 'nothing-to-pay', text: 'No live budget (or every one is on hold)' },
  /* 0x0e-0x11 (restore-then-replay) and 0x13-0x1b (peers, siblings, sync, anchors on the key) went 2026-10-08; their numbers stay unused */
  0x12: { name: 'bad-range', text: 'A loss is #from..#to, at or before the key\'s head' },
  /* R13a (2026-10-06): the sign was not the request the agent started for - refused, no link; TX start again */
  0x1c: { name: 'tx-mismatch', text: 'That request was not the one the agent started for - refused (the TX start is used up)' },
});

/** "EDGE:xx" -> {code, name, text}, or null when the text is not an Edge status. */
function parseStatus(text) {
  const m = /^EDGE:([0-9A-Fa-f]{2})/.exec(String(text || ''));
  if (!m) return null;
  const code = parseInt(m[1], 16);
  const s = STATUS[code];
  return { code, name: s ? s.name : 'unknown', text: s ? s.text : `Edge status 0x${m[1]}` };
}

/** Name and alarm state of a receipt code: alarm = bit 7 OR not a v1 code. */
/*
 * A RECEIPT CODE AS ITS BYTE (Brad, 2026-10-07: a failed push's receipt showed OK).
 * Every receipt was filed with receiptCode(code) - the DISPLAY record, an object - and
 * the plugin wrote Uint8Array.of(object): 0, OK, whatever was asked for. This turns
 * a name (TARGET_UNREACHABLE), a number (0x21) or its hex text ("0x21") into the
 * byte, and refuses anything else - never a silent OK.
 */
function receiptByte(code) {
  if (typeof code === 'number') {
    if (Number.isInteger(code) && code >= 0 && code <= 0xff) return code;
  } else if (typeof code === 'string') {
    const t = code.trim();
    if (/^0x[0-9a-f]{1,2}$/i.test(t)) return parseInt(t, 16);
    if (/^[0-9]{1,3}$/.test(t) && Number(t) <= 0xff) return Number(t);
    const hit = Object.entries(RECEIPT).find(([, name]) => name === t.toUpperCase());
    if (hit) return Number(hit[0]);
  }
  throw new RangeError(`edge: not a receipt code: ${JSON.stringify(code)} (one of ${Object.values(RECEIPT).join(', ')}, or a byte)`);
}

function receiptCode(code) {
  const name = Object.prototype.hasOwnProperty.call(RECEIPT, code) ? RECEIPT[code] : null;
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

module.exports = { OP, DECISION, END, FLAG, TAG, RECEIPT, STATUS, parseStatus, receiptCode, receiptByte, nameOf };
