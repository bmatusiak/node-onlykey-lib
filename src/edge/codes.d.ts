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
    GRANT_HOLD: 13;
    GRANT_RESUME: 14;
    AGENT_ADD: 15;
    CONTINUE: 16;
    SIBLING_ADD: 17;
    SIBLING_REMOVE: 18;
    ANCHOR: 19;
    SYNC: 20;
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
    OWES_TICKET: 16;
    ARMED: 32;
}>;
export const TAG: Readonly<{
    GENESIS: "OKEDGE-GENESIS-v1";
    CONTINUE: "OKEDGE-CONTINUE-v1";
    LINK: "OKEDGE-LINK-v1";
    CHECKPOINT: "OKEDGE-CKPT-v1";
    GRANT: "OKEDGE-GRANT-v1";
    DEVICE: "OKEDGE-DEVICE-v1";
    TICKET: "OKEDGE-TICKET-v1";
    RECEIPT: "OKEDGE-RCPT-v1";
    WAIVE: "OKEDGE-WAIVE-v1";
    ARM: "OKEDGE-ARM-v1";
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
export const STATUS: Readonly<{
    0: {
        name: string;
        text: string;
    };
    1: {
        name: string;
        text: string;
    };
    2: {
        name: string;
        text: string;
    };
    3: {
        name: string;
        text: string;
    };
    4: {
        name: string;
        text: string;
    };
    5: {
        name: string;
        text: string;
    };
    6: {
        name: string;
        text: string;
    };
    7: {
        name: string;
        text: string;
    };
    8: {
        name: string;
        text: string;
    };
    9: {
        name: string;
        text: string;
    };
    10: {
        name: string;
        text: string;
    };
    11: {
        name: string;
        text: string;
    };
    12: {
        name: string;
        text: string;
    };
    13: {
        name: string;
        text: string;
    };
    14: {
        name: string;
        text: string;
    };
    15: {
        name: string;
        text: string;
    };
    16: {
        name: string;
        text: string;
    };
    17: {
        name: string;
        text: string;
    };
    18: {
        name: string;
        text: string;
    };
    19: {
        name: string;
        text: string;
    };
    20: {
        name: string;
        text: string;
    };
    21: {
        name: string;
        text: string;
    };
    22: {
        name: string;
        text: string;
    };
    23: {
        name: string;
        text: string;
    };
    24: {
        name: string;
        text: string;
    };
    25: {
        name: string;
        text: string;
    };
    26: {
        name: string;
        text: string;
    };
    27: {
        name: string;
        text: string;
    };
}>;
/** "EDGE:xx" -> {code, name, text}, or null when the text is not an Edge status. */
export function parseStatus(text: any): {
    code: number;
    name: any;
    text: any;
} | null;
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
