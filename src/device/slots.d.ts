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
