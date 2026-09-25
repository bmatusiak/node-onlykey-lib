/**
 * 57 * 4. One vendor report holds 57 payload bytes, the keyhandle header is
 * 10, and the whole keyhandle must fit a byte - so 228 is the largest useful
 * multiple. Every implementation agrees on this number.
 */
export const REQUEST_CHUNK: 228;
/**
 * MAX_LARGE_RESP_CHUNK from ok_extension.cpp:116. Unrelated to REQUEST_CHUNK -
 * requests are limited by the keyhandle, responses by the device's staging
 * buffer.
 */
export const RESPONSE_CHUNK: 512;
/** Answered by OKPING during the legitimate window between the last challenge
 *  digit being consumed and the result being computed. Treating it as terminal
 *  aborts an operation that was about to succeed. */
export const TRANSIENT_ERROR: RegExp;
/** The firmware's own spelling of "occurred". Matched loosely so a fix upstream
 *  does not silently stop matching. */
export const TERMINAL_ERROR: RegExp;
export const POLL_INTERVAL_MS: 1000;
export const NO_PROGRESS_BUDGET_MS: 30000;
export function nextPacketNum(): number;
/**
 * Classify a payload that might be an ASCII status message rather than data.
 *
 * The firmware reports status and failure through the SAME response path as
 * real data, so a payload has to be classified rather than measured. A genuine
 * 64-byte Ed25519 signature being entirely printable has probability
 * (95/256)^64, which is not a risk worth engineering around.
 */
export function asDeviceMessage(data: any): string | null;
/**
 * Send a payload as 228-byte chunks.
 *
 * @param {object}   spec
 * @param {number}   spec.cmd       vendor message id
 * @param {number}   spec.slot      opt1, already resolved by the caller
 * @param {Uint8Array} spec.payload
 * @param {function} spec.send      async ({cmd, opt1, opt2, opt3, data}) => reply
 * @param {function} [spec.seal]    per-chunk transit box; omit to send in the clear
 * @param {number}   [spec.interChunkDelayMs]  1000 for the legacy PGP path,
 *                                             4000 on 'Original' hardware, 0 otherwise
 * @param {function} [spec.onProgress]
 */
export function sendChunked({ cmd, slot, payload, send, seal, interChunkDelayMs, onProgress, }: {
    cmd: number;
    slot: number;
    payload: Uint8Array;
    send: Function;
    seal?: Function | undefined;
    interChunkDelayMs?: number | undefined;
    onProgress?: Function | undefined;
}): Promise<any>;
/**
 * Poll until a complete response has been reassembled.
 *
 * @param {object}   spec
 * @param {function} spec.poll      async () => decoded assertion
 * @param {number}   [spec.expected]  the exact expected length. ALWAYS pass it
 *                   when known: without it both the shape guard and the length
 *                   check are disabled and the first binary reply of any size
 *                   wins.
 * @param {boolean}  [spec.untilShortChunk]  complete when a chunk shorter than
 *                   RESPONSE_CHUNK arrives, which is the firmware's own rule.
 *                   For a response whose length cannot be known in advance.
 *                   Ignored when `expected` is given.
 * @param {function} [spec.open]    applied ONCE to the concatenation, not per
 *                   chunk - see below
 * @param {number}   [spec.intervalMs]
 * @param {number}   [spec.noProgressBudgetMs]
 * @param {function} [spec.onProgress]
 * @param {boolean}  [spec.challengeErrorIsFinal]  treat "incorrect challenge
 *                   was entered" as the end of the operation rather than a
 *                   state to poll through. Pass
 *                   `capabilities().challengeErrorIsFinal` - true from 3.0.5,
 *                   where the device only says it with nothing left to give.
 */
export function pollForResponse({ poll, expected, untilShortChunk, open, intervalMs, noProgressBudgetMs, onProgress, challengeErrorIsFinal, }: {
    poll: Function;
    expected?: number | undefined;
    untilShortChunk?: boolean | undefined;
    open?: Function | undefined;
    intervalMs?: number | undefined;
    noProgressBudgetMs?: number | undefined;
    onProgress?: Function | undefined;
    challengeErrorIsFinal?: boolean | undefined;
}): Promise<{
    data: null;
    message: string;
} | {
    data: Uint8Array<ArrayBuffer>;
    message: string | null;
}>;
/** Test seam only. Production code must never reset this. */
export function _resetPacketCounter(to?: number): void;
