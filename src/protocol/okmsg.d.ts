export const REPORT_SIZE: 64;
export const HEADER: number[];
/**
 * Build one 64-byte report.
 *
 * @param {object} spec
 * @param {number|string} spec.msg          MSG.* or its name
 * @param {number}        [spec.slot]       slot id, when the message takes one
 * @param {number|string} [spec.field]      FIELD.* or its name
 * @param {Uint8Array|number[]|string} [spec.payload]  string is taken as latin1
 * @returns {Uint8Array} exactly REPORT_SIZE bytes
 */
export function build({ msg, slot, field, payload }: {
    msg: number | string;
    slot?: number | undefined;
    field?: string | number | undefined;
    payload?: string | number[] | Uint8Array<ArrayBufferLike> | undefined;
}): Uint8Array;
/**
 * OKCONNECT's payload: the epoch seconds as hex digit PAIRS, one byte each.
 *
 * Not the integer. python-onlykey's set_time() encodes 0x68bd1f40 as the four
 * bytes 0x68 0xBD 0x1F 0x40 by way of its hex STRING, and the firmware parses
 * it that way. Passing the number would be silently wrong rather than
 * rejected, which is why this is a named function and not an inline expression.
 *
 * @param {Date|number} [when]
 */
export function setTimePayload(when?: Date | number): number[];
/**
 * A device response as text.
 *
 * hidprint() memsets its buffer and writes only the string, so everything after
 * it is NUL padding - which is not part of the message and must not end up in
 * an assertion. Trailing NULs only: an interior one is the device's own byte.
 *
 * @param {Uint8Array} bytes
 */
export function text(bytes: Uint8Array): string;
/**
 * Split a response into its lock state and the rest.
 *
 * The device broadcasts its state on the vendor interface about once a second,
 * so a reply and a broadcast can arrive interleaved. Callers that want "is it
 * unlocked" should prefer the newest UNLOCKED in a window over the first match
 * - see the note in onlykey-testing's Device.status().
 *
 * @param {Uint8Array|string} response
 */
export function parseState(response: Uint8Array | string): {
    state: string;
    raw: string;
};
