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
/** One vendor packet's payload - the unit the firmware splits a keyhandle into. */
export const PACKET_DATA: 57;
export function nextPacketNum(): number;
/**
 * Make sure the next `count` packet numbers do not WRAP inside one operation.
 *
 * The wrap is the one case the monotonic counter above cannot cover, and it is
 * not hypothetical: an ML-KEM-768 ciphertext is seven sealed keyhandles, so an
 * operation starting at 252 would number its chunks 252..255, 1, 2, 3 - and the
 * duplicate guard reads that 1 as `opt3 <= last` and DROPS the rest silently.
 *
 * Restarting at 1 is safe at an operation boundary and nowhere else. From
 * 3.0.5 the high-water mark is cleared by the final chunk of the previous
 * operation (`if (opt2) last_request_opt3 = 0`, ok_extension.cpp:701); on
 * 3.0.4 and earlier it is cleared by wipetasks(), which the tunnel path waits
 * out before a stored-key operation anyway (see okcrypto's staged-reply
 * settle). So this is called once, before the first chunk, never between
 * chunks.
 */
export function reservePacketRun(count: any): void;
/**
 * Chunk lengths for a payload that will be SEALED into keyhandles.
 *
 * Two rules from bridge_to_onlykey() (ok_extension.cpp:666-698), neither of
 * which a plain 228-byte slicing honours once a seal changes the lengths:
 *
 *   EVERY CHUNK BUT THE LAST IS WHOLE 57-BYTE PACKETS. The device splits a
 *   keyhandle's plaintext into 57-byte packets and marks every one of them
 *   "full" (recv_buffer[6] = 0xFF) unless it is the last packet of the final
 *   keyhandle. A non-final chunk ending in a short packet has that packet read
 *   as 57 bytes, trailing zeros and all, and the payload the device hashes is
 *   no longer the one the host sent.
 *
 *   THE SEALED CHUNK MUST NOT BE PADDED. The device authenticates (v2) or
 *   decrypts (v1) the whole data region, padding included - see
 *   ctap.dataRegionLength. So a final chunk whose sealed length would be padded
 *   is refused here or reshaped: 57 bytes move from the previous chunk into it,
 *   which keeps both rules.
 *
 * `overhead` is what the seal adds: transit.OVERHEAD (20) for v2, which leaves
 * 225 bytes of a 245-byte keyhandle and therefore 171 = 3 * 57 per chunk; 0 for
 * v1, whose box is length-preserving and keeps the historical 228 = 4 * 57.
 *
 * @param {number} length   plaintext bytes to send
 * @param {object} [opts]
 * @param {number} [opts.overhead]  bytes the seal adds to each chunk
 * @returns {number[]} chunk lengths, in order, summing to `length`
 */
export function planKeyhandleChunks(length: number, { overhead }?: {
    overhead?: number | undefined;
}): number[];
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
 * @param {number[]} [spec.sizes]  the chunk lengths to use, in order - from
 *                   planKeyhandleChunks when the chunks are sealed. Omitted,
 *                   every chunk is REQUEST_CHUNK, as it always was.
 * @param {function} [spec.onReply]  (reply, {chunk, chunks, isFinal}) called
 *                   with the device's answer to EACH chunk before the next one
 *                   goes out. Throwing stops the send - which is the point: a
 *                   chunk the device did not accept makes every later chunk
 *                   part of a message it will never complete.
 */
export function sendChunked({ cmd, slot, payload, send, seal, interChunkDelayMs, onProgress, sizes, onReply, }: {
    cmd: number;
    slot: number;
    payload: Uint8Array;
    send: Function;
    seal?: Function | undefined;
    interChunkDelayMs?: number | undefined;
    onProgress?: Function | undefined;
    sizes?: number[] | undefined;
    onReply?: Function | undefined;
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
