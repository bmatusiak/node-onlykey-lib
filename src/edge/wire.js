'use strict';

/**
 * EDGE_REQUEST ON THE WIRE: the Bluetooth channel of mcp-service.md 4.7a.
 *
 * A budget request goes to the APP, never to the key. Over the soft key's
 * Bluetooth vendor channel it travels as its own message code, OKEDGE_REQUEST
 * (0xF7 - used by neither the firmware nor its plugins: OKEDGE is 0xF8,
 * OKGETCONFIG 0xF9, OKSETCONFIG 0xFA), which the phone's vendor bridge KEEPS
 * for the app: the key never sees it. The app's answer comes back the same way.
 *
 * One 64-byte report per piece:
 *   [0..3] FF FF FF FF   the vendor header every OnlyKey message has
 *   [4]    0xF7          OKEDGE_REQUEST
 *   [5]    kind          1 = request, 2 = answer
 *   [6]    index         0.. (a new index 0 starts a new message)
 *   [7]    last          1 on the final piece
 *   [8]    length        bytes of payload in this piece (<= 55)
 *   [9..]  payload       UTF-8 JSON of the whole message, cut in pieces
 * Pure: no device, no Node built-ins.
 */

const { utf8ToBytes, bytesToUtf8 } = require('../bytes');
const { inLane } = require('../transport/lane');

const OKEDGE_REQUEST = 0xf7;
const KIND = Object.freeze({ REQUEST: 1, ANSWER: 2 });
const PIECE = 55;
const MAX_PIECES = 255;

/** a whole message -> its 64-byte reports */
function encode(kind, obj) {
  const data = utf8ToBytes(JSON.stringify(obj));
  const n = Math.max(1, Math.ceil(data.length / PIECE));
  if (n > MAX_PIECES) throw new RangeError(`edge wire: a message of ${data.length} bytes is too long`);
  const out = [];
  for (let i = 0; i < n; i++) {
    const part = data.subarray(i * PIECE, (i + 1) * PIECE);
    const r = new Uint8Array(64);
    r.set([0xff, 0xff, 0xff, 0xff, OKEDGE_REQUEST, kind, i, i === n - 1 ? 1 : 0, part.length]);
    r.set(part, 9);
    out.push(r);
  }
  return out;
}

/** is this report an OKEDGE_REQUEST piece (either direction)? */
function isEdgeRequestFrame(frame) {
  return frame && frame.length >= 9 && frame[0] === 0xff && frame[1] === 0xff && frame[2] === 0xff && frame[3] === 0xff
    && frame[4] === OKEDGE_REQUEST;
}

/**
 * Pieces in, whole messages out. push(frame) -> {kind, message} when a message
 * is complete, null otherwise. A piece out of order, or JSON that does not
 * parse, drops what was gathered (and push returns {error}).
 */
function createAssembler() {
  let parts = [];
  let kind = 0;
  return {
    push(frame) {
      if (!isEdgeRequestFrame(frame)) return null;
      const [k, index, last, len] = [frame[5], frame[6], frame[7], frame[8]];
      if (index === 0) { parts = []; kind = k; }
      if (index !== parts.length || k !== kind || len > PIECE) { parts = []; return { error: 'out-of-order' }; }
      parts.push(frame.slice(9, 9 + len));
      if (!last) return null;
      const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
      let at = 0;
      for (const p of parts) { all.set(p, at); at += p.length; }
      parts = [];
      try {
        return { kind, message: JSON.parse(bytesToUtf8(all)) };
      } catch {
        return { error: 'not-json' };
      }
    },
  };
}

/**
 * The PC side of the Bluetooth channel: send(EDGE_REQUEST) -> the app's
 * answer, or null when nothing comes back in time (an app DROPS an unsigned,
 * unregistered or replayed request without answering). The person approves
 * in between, so the wait is long. Held as one conversation in the key's lane
 * (transport/lane.js), so no other request from this host lands in it.
 */
function createWireChannel(transport, { timeoutMs = 120000, iface = 2 } = {}) {
  return {
    send(message) {
      return inLane(transport, () => new Promise((resolve, reject) => {
        const asm = createAssembler();
        let timer = null;
        let off = () => {};
        off = transport.on('report', (event) => {
          if (event.iface !== iface) return;
          const got = asm.push(event.data instanceof Uint8Array ? event.data : Uint8Array.from(event.data));
          if (!got || got.error || got.kind !== KIND.ANSWER) return;
          clearTimeout(timer);
          off();
          resolve(got.message);
        });
        timer = setTimeout(() => { off(); resolve(null); }, timeoutMs);
        /*
         * A wait nobody is still awaiting must not keep the process alive: a ticket's
         * note gives up after 4 s (client sendNote), and `onlykey-js edge ticket` then
         * sat until this 120 s timer ran out (Pixel, 2026-10-06).
         */
        if (timer && typeof timer.unref === 'function') timer.unref();
        (async () => {
          /* one request's frames together: the Bluetooth pipe puts several in one write (cli/transport-ble.js KIND_REPORTS) */
          const frames = encode(KIND.REQUEST, message);
          if (typeof transport.writeMany === 'function') await transport.writeMany(iface, frames);
          else for (const frame of frames) await transport.write(iface, frame);
        })().catch((e) => { clearTimeout(timer); off(); reject(e); });
      }));
    },
  };
}

module.exports = { OKEDGE_REQUEST, KIND, PIECE, encode, isEdgeRequestFrame, createAssembler, createWireChannel };
