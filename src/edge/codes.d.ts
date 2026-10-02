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
export const OP: Readonly<{
    SIGN: 1;
    DECRYPT: 2;
    FIDO_REG: 3;
    FIDO_AUTH: 4;
    HMAC: 5;
    GRANT_CREATE: 6;
    GRANT_END: 7;
    TICKET: 8;
    PEER_ADD: 9;
    PEER_REMOVE: 10;
    LOSS: 11;
    WIPE: 12;
}>;
export const DECISION: Readonly<{
    APPROVE: 1;
    DENY: 2;
    TIMEOUT: 3;
    SELF_PRESS: 4;
}>;
export const FLAG: Readonly<{
    PRESS_OBSERVED: 1;
    BUDGET_SPENT: 2;
    PREV_NO_TICKET: 4;
    HISTORY_AT_RISK: 8;
}>;
export const TAG: Readonly<{
    GENESIS: "OKEDGE-GENESIS-v1";
    LINK: "OKEDGE-LINK-v1";
    CHECKPOINT: "OKEDGE-CKPT-v1";
    GRANT: "OKEDGE-GRANT-v1";
    TICKET: "OKEDGE-TICKET-v1";
    RECEIPT: "OKEDGE-RCPT-v1";
}>;
export const TICKET: Readonly<{
    0: "OK";
    1: "OK_UNCONFIRMED";
    2: "PARTIAL";
    16: "NOT_USED";
    17: "SUPERSEDED";
    32: "TARGET_REJECTED";
    33: "TARGET_UNREACHABLE";
    48: "ABORTED_BY_AGENT";
    49: "ABORTED_BY_HUMAN";
    64: "AGENT_ERROR";
    128: "USED_DIFFERENTLY";
    129: "SUSPECTED_INJECTION";
    130: "DATA_EXPOSED";
    131: "POLICY_CONCERN";
    143: "NEEDS_REVIEW";
    255: "UNKNOWN";
}>;
/** Name and alarm state of a ticket code: alarm = bit 7 OR not a v1 code. */
export function ticketCode(code: any): {
    code: any;
    name: any;
    known: boolean;
    alarm: boolean;
    class: number;
};
/** Reverse lookup for display: OP/DECISION value -> lower-case name, or null. */
export function nameOf(table: any, value: any): string | null;
