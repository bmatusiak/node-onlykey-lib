/*
 * chunk.js - chunked request send and multi-chunk response polling.
 *
 * This replaces two near-duplicate implementations that had drifted apart:
 * onlykey-pgp.js:216-275 (classic RSA over kbpgp) and
 * onlykey-3rd-party.js:818-911 (composite PGP-PQC). Where they disagree, the
 * newer one is right on control flow and the older one is right on the
 * challenge PIN and the hardware pacing; both are noted at each site.
 *
 * The behaviours below are not tunables. Each one was measured, and each one
 * fails in a way that does not look like its cause.
 */
'use strict';

const { concat } = require('../bytes');
const { SUCCESS } = require('./ctap');
const { deviceError } = require('./okmsg');

/**
 * 57 * 4. One vendor report holds 57 payload bytes, the keyhandle header is
 * 10, and the whole keyhandle must fit a byte - so 228 is the largest useful
 * multiple. Every implementation agrees on this number.
 */
const REQUEST_CHUNK = 228;

/**
 * MAX_LARGE_RESP_CHUNK from ok_extension.cpp:116. Unrelated to REQUEST_CHUNK -
 * requests are limited by the keyhandle, responses by the device's staging
 * buffer.
 */
const RESPONSE_CHUNK = 512;

/** Answered by OKPING during the legitimate window between the last challenge
 *  digit being consumed and the result being computed. Treating it as terminal
 *  aborts an operation that was about to succeed. */
const TRANSIENT_ERROR = /incorrect challenge was entered/i;

/** The firmware's own spelling of "occurred". Matched loosely so a fix upstream
 *  does not silently stop matching. */
const TERMINAL_ERROR = /Timeout occur\w* while waiting for confirmation/i;

const POLL_INTERVAL_MS = 1000;
const NO_PROGRESS_BUDGET_MS = 30000;

/**
 * ONE monotonic counter for the whole process. Never reset, wraps 255 -> 1.
 *
 * The firmware's duplicate guard is:
 *
 *     if (!packet_buffer_details[3]) packet_buffer_details[3] = opt3;
 *     else if (opt3 <= packet_buffer_details[3]) return 0;   // SILENTLY dropped
 *
 * and that high-water mark is cleared only by wipetasks(), on a 5-second
 * timer - wipedata(), which runs after a response is stored, leaves it alone.
 * So an operation that restarts numbering at 1 within 5 seconds of the last
 * one has its first chunks discarded with no error whatsoever. It surfaces
 * later and elsewhere, as "Error incorrect challenge was entered", because the
 * device hashed a short payload and is asking for digits computed over bytes
 * that never arrived.
 *
 * onlykey-pgp.js:250 resets to 0 on the final packet and is the bug. This is
 * the single highest-value correction in this file.
 *
 * Wrapping to 1 rather than 0 is deliberate: 0 is falsy, so the firmware reads
 * it as "unset" - which is exactly why polls can safely use opt3 = 0 forever.
 */
let packetCounter = 0;

function nextPacketNum() {
  packetCounter = packetCounter >= 255 ? 1 : packetCounter + 1;
  return packetCounter;
}

/** Test seam only. Production code must never reset this. */
function _resetPacketCounter(to = 0) {
  packetCounter = to;
}

const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

/**
 * Classify a payload that might be an ASCII status message rather than data.
 *
 * The firmware reports status and failure through the SAME response path as
 * real data, so a payload has to be classified rather than measured. A genuine
 * 64-byte Ed25519 signature being entirely printable has probability
 * (95/256)^64, which is not a risk worth engineering around.
 */
function asDeviceMessage(data) {
  if (!data || !data.length) return null;
  let text = '';
  for (let i = 0; i < data.length; i++) text += String.fromCharCode(data[i]);
  text = text.replace(/\0+$/, '');
  return /^[\x20-\x7e]+$/.test(text) ? text : null;
}

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
async function sendChunked({
  cmd,
  slot = 0,
  payload,
  send,
  seal = null,
  interChunkDelayMs = 0,
  onProgress = null,
}) {
  const bytes = Uint8Array.from(payload);
  let offset = 0;
  let last = null;
  let index = 0;

  // A zero-length payload is still one chunk: the device needs the final flag
  // to prime the challenge, and never gets it if the loop never runs.
  do {
    const chunk = bytes.subarray(offset, offset + REQUEST_CHUNK);
    offset += chunk.length;
    const isFinal = offset >= bytes.length;

    last = await send({
      cmd,
      opt1: slot,
      // opt2 is what tells the firmware the input is complete. Without it the
      // device never primes the challenge and never sets the real length.
      opt2: isFinal ? 1 : 0,
      opt3: nextPacketNum(),
      data: seal ? seal(chunk) : chunk,
    });

    index += 1;
    if (onProgress) onProgress({ sent: offset, total: bytes.length, chunk: index });
    if (!isFinal && interChunkDelayMs) await sleep(interChunkDelayMs);
  } while (offset < bytes.length);

  return last;
}

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
 */
async function pollForResponse({
  poll,
  expected = null,
  untilShortChunk = false,
  open = null,
  intervalMs = POLL_INTERVAL_MS,
  noProgressBudgetMs = NO_PROGRESS_BUDGET_MS,
  onProgress = null,
}) {
  const chunks = [];
  let total = 0;
  let message = null;

  /*
   * The budget is NO-PROGRESS, re-armed on every accepted chunk - never a
   * total. A total cap cannot work: a degraded device serves 64 bytes per
   * poll, so a 3309-byte ML-DSA-65 signature needs ~52 WebAuthn ceremonies,
   * around 36s of entirely healthy progress. Two measured runs against a 30s
   * total cap stopped at 2944 and 3008 bytes - a moving number is a clock
   * expiring, not a limit being reached.
   */
  let deadline = Date.now() + noProgressBudgetMs;

  while (Date.now() < deadline) {
    const reply = await poll();

    if (reply.error) {
      if (TERMINAL_ERROR.test(reply.error)) throw deviceError(reply.error);
      if (!TRANSIENT_ERROR.test(reply.error)) throw deviceError(reply.error);
      // Transient: the device is mid-challenge. Keep going.
    }

    /*
     * THE GATE. A payload is only real when the status says so.
     *
     * A poll made while the device is still waiting on the button challenge is
     * answered CTAP2_ERR_USER_ACTION_PENDING with no extension_writeback(), so
     * ctap.cpp falls through to its default sigder_sz = 72 and ships 71 bytes
     * of UNINITIALISED STACK after the status byte. Measured on an idle
     * device: a decrypt nobody had confirmed "succeeded" in 1.4s with 71 bytes
     * whose tail was the ASCII "OCKEDv3.0.4-test" left over from an earlier
     * UNLOCKED response. Classifying by content alone accepts that as an
     * answer.
     */
    if (reply.status === SUCCESS && reply.data && reply.data.length) {
      const text = asDeviceMessage(reply.data);
      if (text) {
        if (chunks.length) {
          // Chunks had started and the device has moved on: the staging buffer
          // is gone. Report rather than return a truncated signature.
          message = text;
          break;
        }
        if (TERMINAL_ERROR.test(text)) throw new Error(text);
        message = text;
        if (!expected) break;
      } else {
        /*
         * Shape guard. Every chunk but the last is exactly RESPONSE_CHUNK and
         * the last lands exactly on `expected`; anything else did not come off
         * the cursor. This existed because the firmware once advanced its
         * cursor a full 512 while shipping only 71 bytes per assertion - the
         * reassembled signature was real bytes in the wrong places, which no
         * length check would have caught.
         */
        const len = reply.data.length;
        const plausible =
          !expected || len === RESPONSE_CHUNK || total + len === expected;

        if (plausible) {
          chunks.push(Uint8Array.from(reply.data));
          total += len;
          deadline = Date.now() + noProgressBudgetMs; // progress: re-arm
          if (onProgress) onProgress({ received: total, expected });
          /*
           * TERMINATION, three ways, in order of how much the caller knows.
           *
           * `untilShortChunk` is the firmware's OWN rule, for a response whose
           * length cannot be computed in advance:
           *
           *     chunk_len = remaining > MAX_LARGE_RESP_CHUNK
           *               ? MAX_LARGE_RESP_CHUNK : remaining;
           *
           * so a chunk shorter than RESPONSE_CHUNK is by definition the last
           * one. Nothing has to be predicted, which matters for the transit-v2
           * derive: its framed length depends on the status string the device
           * embeds, and that string is INSIDE the ciphertext - knowable only
           * after opening, which needs every chunk first.
           *
           * A response that is an exact multiple of RESPONSE_CHUNK costs one
           * extra poll, which the device answers with a zero-length chunk; that
           * fails the `reply.data.length` gate above and falls through to the
           * budget, so it ends rather than spinning.
           *
           * `expected` stays the stronger rule where a caller does know the
           * length, because it also drives the shape guard. Neither set keeps
           * the original behaviour: the first chunk wins.
           */
          if (untilShortChunk && !expected) {
            if (len < RESPONSE_CHUNK) break;
            continue;
          }
          if (!expected || total >= expected) break;
          continue; // more expected: poll again without sleeping
        }
      }
    }

    await sleep(intervalMs);
  }

  if (!chunks.length) {
    if (message) return { data: null, message };
    throw new Error(
      `no response within the no-progress budget of ${noProgressBudgetMs}ms` +
        (expected ? ` (expected ${expected} bytes, got ${total})` : ''),
    );
  }

  /*
   * Open ONCE over the concatenation.
   *
   * The box is a single keystream from offset 0, so opening chunk N on its own
   * XORs it against the keystream's beginning instead of its own offset -
   * everything past the first 512 bytes comes out corrupt. onlykey-pgp.js:192
   * opens per response and is correct only because an RSA answer never exceeds
   * one chunk.
   *
   * Whether to open at all is per COMMAND, not per transport: the tunnelled
   * RSA path passes encrypt=1 in okcrypto_rsasign(), the composite PQC path
   * passes 0.
   */
  let data = concat(chunks);
  if (expected && data.length > expected) data = data.subarray(0, expected);
  if (open) data = open(data);

  return { data, message };
}

module.exports = {
  REQUEST_CHUNK,
  RESPONSE_CHUNK,
  TRANSIENT_ERROR,
  TERMINAL_ERROR,
  POLL_INTERVAL_MS,
  NO_PROGRESS_BUDGET_MS,
  nextPacketNum,
  asDeviceMessage,
  sendChunked,
  pollForResponse,
  _resetPacketCounter,
};
