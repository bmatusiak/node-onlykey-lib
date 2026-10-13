'use strict';

/**
 * Splitting a swap message into Bluetooth writes and putting it back together.
 *
 * A Bluetooth LE write or notification carries one ATT payload (MTU - 3 bytes: 20 on a link
 * that never asked for more, 244 after the scanner asks for 247), and a swap message is up to
 * ~60 KB (a card with a quantum-safe PGP certificate). The same shape as CTAP-BLE, which this
 * project already speaks: the first fragment says the whole length, the rest are numbered.
 *
 *   first:         [0x80][len hi][len lo][data...]
 *   continuation:  [seq 0..0x7f][data...]       (seq counts up from 0 and wraps)
 *
 * The link is one reliable, ordered channel (GATT write-with-response one way, notifications
 * paced by onNotificationSent the other), so a gap or a wrong sequence number is a broken
 * link, and the assembler says so instead of guessing.
 */

const FIRST = 0x80;
const MAX_MESSAGE = 0xffff;

/** @returns {Uint8Array[]} the writes for one message, each at most `size` bytes */
function fragment(msg, size) {
  if (!(msg instanceof Uint8Array)) throw new Error('a message is bytes');
  if (msg.length > MAX_MESSAGE) throw new Error(`a message is at most ${MAX_MESSAGE} bytes; this one is ${msg.length}`);
  if (!Number.isInteger(size) || size < 4) throw new Error(`a fragment of ${size} bytes cannot carry anything`);
  const out = [];
  const first = msg.slice(0, size - 3);
  out.push(Uint8Array.of(FIRST, msg.length >> 8, msg.length & 0xff, ...first));
  let seq = 0;
  for (let o = first.length; o < msg.length; o += size - 1) {
    out.push(Uint8Array.of(seq, ...msg.slice(o, o + size - 1)));
    seq = (seq + 1) & 0x7f;
  }
  return out;
}

/**
 * Feed fragments as they arrive; `push` returns the whole message when its last fragment
 * lands, otherwise null. Throws on a fragment out of place.
 */
function createAssembler() {
  let want = -1;
  let parts = [];
  let have = 0;
  let seq = 0;
  return {
    push(frag) {
      if (!(frag instanceof Uint8Array) || frag.length < 1) throw new Error('an empty fragment');
      if (want < 0) {
        if (frag[0] !== FIRST || frag.length < 3) throw new Error('the link sent a continuation before a message began');
        want = (frag[1] << 8) | frag[2];
        parts = [frag.slice(3)];
        have = frag.length - 3;
        seq = 0;
      } else {
        if (frag[0] !== seq) throw new Error(`fragment ${frag[0]} arrived where ${seq} was expected - the link broke`);
        parts.push(frag.slice(1));
        have += frag.length - 1;
        seq = (seq + 1) & 0x7f;
      }
      if (have > want) throw new Error('the link sent more than the message said');
      if (have < want) return null;
      const msg = new Uint8Array(want);
      let o = 0;
      for (const p of parts) { msg.set(p, o); o += p.length; }
      want = -1;
      parts = [];
      return msg;
    },
  };
}

module.exports = { fragment, createAssembler, MAX_MESSAGE };
