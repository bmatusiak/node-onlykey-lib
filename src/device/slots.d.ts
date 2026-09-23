export namespace DEVICE_TYPE {
    let CLASSIC: string;
    let DUO: string;
}
/** Classic has 6 pairs; DUO has 4 profiles of 6. */
export const SLOT_COUNT: {
    [DEVICE_TYPE.CLASSIC]: number;
    [DEVICE_TYPE.DUO]: number;
};
/**
 * The device-global pseudo-slot.
 *
 * The original reaches 0 by accident: it passes the string 'XX' through
 * strPad() into a Uint8Array, where it becomes NaN and stores as 0. Relying on
 * that coercion is how a refactor silently changes which slot gets written, so
 * it is named here instead.
 */
/**
 * The two HMAC-SHA1 key slots.
 *
 * okcore.h:215-216 - RESERVED_KEY_HMACSHA1_1 is 130 and _2 is 129. Named here
 * because writing either one has a side effect the device does not report: it
 * clears that slot's button-press requirement. See
 * onlykey-testing/FINDING-hmac-press-free-on-write.md.
 */
export const HMAC_SLOTS: number[];
/**
 * The web-and-agent derivation key, okcore.h's RESERVED_KEY_WEB_AGENT_DERIVATION.
 *
 * Every label-derived key is expanded from this one, and from firmware 3.0.5 it
 * is also the slot a derived X-Wing DECAPSULATION is addressed to: the derive
 * tunnel cannot carry the 1120-byte ciphertext, so that operation is a chunked
 * OKDECRYPT here instead. See okcrypto.deviceAge.decrypt().
 */
export const WEB_AGENT_DERIVATION_SLOT: 128;
export const GLOBAL_SLOT: 0;
export const GLOBAL_SLOT_ID: "XX";
/**
 * The label-list slot tokens, and they are NOT hex.
 *
 * The device numbers 1..19 as decimal text and then continues with the literal
 * tokens '1a'..'1e' for 20..24. Reading them as hex gives 26..30, which is
 * wrong and lands inside no valid range - so it fails as "labels stop at 19"
 * rather than as a parse error.
 */
export const LABEL_TOKENS: {
    '1a': number;
    '1b': number;
    '1c': number;
    '1d': number;
    '1e': number;
};
/**
 * Slot id ('3a', '12b', 'XX') to the number the firmware uses.
 *
 * Classic is one +0/+6 split over six pairs. DUO interleaves a and b WITHIN
 * each three-slot band, so that consecutive profiles occupy contiguous runs of
 * six - which is why it cannot be expressed as one offset.
 */
export function slotNumber(slotId: any, deviceType?: string): number;
/**
 * Which button types a slot, how long to hold it, and what it will type.
 *
 * The INVERSE of gen_press() and gen_hold(), which is where every number here
 * comes from. Both compute the slot the same way:
 *
 *     slot = button + profileOffset            gen_press, a tap
 *     slot = button + profileOffset + span     gen_hold, a hold
 *
 * ## THE PROFILE IS DEVICE STATE, AND NO MESSAGE SETS IT
 *
 * `profileOffset` is read from the device's own `profilemode` / `Duo_config[1]`
 * at the moment of the press. A classic reaches its second profile by being
 * unlocked with the SECOND PIN; a DUO cycles through its four by holding
 * button 3 for 72..179 iterations (OnlyKey.ino:886-901), which on a classic is
 * the gesture that locks the key instead. Neither is a command, and the
 * desktop app's profile switcher sends the device nothing at all - it is a
 * display filter over labels it already has.
 *
 * So a press reads the profile the device is ALREADY on, and nothing in the
 * reply says which one that was. `profile` is therefore an argument rather than
 * an assumption: a caller that does not know is about to read someone else's
 * credential and should find that out here.
 *
 * ## THE TWO MODELS PUT THE PROFILE IN DIFFERENT PLACES
 *
 * A DUO's slot ids span all 24 - '5a' IS profile 1, and slotNumber() already
 * folds the offset in. A classic's ids only span 12 and the profile is a
 * separate axis on top, so classic '3a' is physical slot 3 or 15 depending on
 * which PIN was used. Both are returned as `slot`, the number process_slot()
 * actually receives, because that is the one a caller can check a label against.
 *
 * @param {string|number} slotId  '3a', '12b'
 * @param {object} opts
 * @param {string} [opts.deviceType] 'classic' or 'duo'
 * @param {number} [opts.profile]    the profile the DEVICE is on, 0-based
 * @returns {{button: number, band: 'tap'|'hold', slot: number, profile: number}}
 */
export function pressForSlot(slotId: string | number, { deviceType, profile }?: {
    deviceType?: string | undefined;
    profile?: number | undefined;
}): {
    button: number;
    band: "tap" | "hold";
    slot: number;
    profile: number;
};
/**
 * How many profiles the device has, and what each one ADDS to a slot number.
 *
 * From the four branches gen_press() and gen_hold() share (OnlyKey.ino:998-1006
 * and :1013-1021). They are written as a chain of literal comparisons rather
 * than as arithmetic, so this is a table for the same reason: the firmware's
 * order is not the obvious one and a formula that happens to agree today would
 * not say where it came from.
 *
 *   if (profilemode || Duo_config[1] == 2)  slot = button + 12
 *   else if (Duo_config[1] == 1)            slot = button + 6
 *   else if (Duo_config[1] == 3)            slot = button + 18
 *   else                                    slot = button
 *
 * A CLASSIC reaches +12 through `profilemode`, which is STDPROFILE2 (1) or
 * NONENCRYPTEDPROFILE (2); STDPROFILE1 is 0 and therefore falsy, which is why
 * the first profile falls all the way through to the else. So a classic has
 * exactly two, at +0 and +12, and the travel edition shares the second one.
 */
export const PROFILE_OFFSETS: {
    [DEVICE_TYPE.CLASSIC]: number[];
    [DEVICE_TYPE.DUO]: number[];
};
export function labelSlotNumber(token: any): any;
/**
 * Accumulates OKGETLABELS responses.
 *
 * Three things the original gets right and one it does not.
 *
 * The FIRST response is discarded. The device sends a priming message before
 * the list proper; consuming it as a label drops label #1 and shifts every
 * subsequent one. (OnlyKeyComm.js:478-481 does this by flipping `labels` from
 * "" to [], which is easy to read as an initialisation rather than a rule.)
 *
 * A response is only a label when the pipe is at index 2 - the token is
 * exactly two characters.
 *
 * The read ends at slot 12 or 24 by device type.
 *
 * What it does not do is time out. There is no deadline anywhere in the
 * original, so a lost terminal message hangs the caller forever with no error;
 * that is added here.
 */
export class LabelReader {
    constructor(deviceType?: string);
    deviceType: string;
    total: number;
    labels: any[];
    primed: boolean;
    done: boolean;
    error: string | null;
    statusReports: number;
    /**
     * Feed one vendor report.
     * @returns {'primed'|'stored'|'ignored'|'done'|'error'}
     */
    push(report: any): "primed" | "stored" | "ignored" | "done" | "error";
    /** Labels by slot number, with nulls for slots that never reported. */
    result(): {
        labels: any[];
        complete: boolean;
        error: string | null;
    };
}
/**
 * Read every label.
 *
 * @param {object} transport  must provide on() and write()
 * @param {object} [opts] {deviceType, timeoutMs}
 */
export function readLabels(transport: object, opts?: object): Promise<any>;
export const KEY_LABEL_FIRST: 25;
export const KEY_LABEL_LAST: 44;
/** The slot byte that asks for KEY labels rather than slot labels: 'k'. */
export const KEY_LABELS_SLOT_BYTE: 107;
/** Label index (25..44) -> key slot (1..4, 101..116), or null. */
export function keySlotForLabelIndex(index: any): any;
/** Key slot (1..4, 101..116) -> label index (25..44), or null. */
export function labelIndexForKeySlot(slot: any): any;
/**
 * Accumulates the KEY label list.
 *
 * Simpler than LabelReader because this list has no string form to support:
 * no client ever reconstructed it as hex the way OnlyKey-App does for slot
 * labels, so only the wire layout exists.
 *
 *     [0]    the LABEL INDEX as a raw byte, 25..44
 *     [1]    0x7C, a pipe
 *     [2..]  up to EElen_label (16) bytes of text, NUL-terminated
 *
 * The RSA rows are sent as 21 bytes and the ECC rows as 22
 * (okcore.cpp:1445 vs :1491). Nothing turns on the difference - both carry
 * the same two header bytes and the same 16 bytes of label - but it is the
 * sort of thing that looks like a bug when you meet it, so: it is not.
 */
export class KeyLabelReader {
    labels: Map<any, any>;
    done: boolean;
    error: string | null;
    statusReports: number;
    /** Feed one vendor report. @returns {'stored'|'ignored'|'done'|'error'} */
    push(report: any): "stored" | "ignored" | "done" | "error";
    /** One row per key slot, in firmware order, with '' for an unlabelled slot. */
    result(): {
        keys: {
            slot: any;
            kind: string;
            label: any;
        }[];
        complete: boolean;
        error: string | null;
    };
}
/**
 * Read every KEY label.
 *
 * @param {object} transport  must provide on() and write()
 * @param {object} [opts] {timeoutMs, settleMs}
 */
export function readKeyLabels(transport: object, opts?: object): Promise<any>;
