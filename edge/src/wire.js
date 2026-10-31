'use strict';

/**
 * EDGE_REQUEST ON THE WIRE: the Bluetooth channel of APP.md.
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
 *   [6..7] index         u16 LE, 0.. (a new index 0 starts a new message)
 *   [8]    last          1 on the final piece
 *   [9]    length        bytes of payload in this piece (<= 54)
 *   [10..] payload       UTF-8 JSON of the whole message, cut in pieces
 * WHY A u16 INDEX (Brad, 2026-10-10: the hybrid checkpoint, "B + a wider wire"): a one-byte
 * index capped a message at 255 x 55 = 14,025 bytes, and one ML-DSA-65 signature is 6,618
 * hex characters - an OFFER with its hybrid checkpoint and statement no longer fit. Two
 * bytes allow 65,535 pieces of 54 (about 3.5 MB). No compatibility mode: Edge is unreleased.
 * Pure: no device, no Node built-ins.
 */

const { utf8ToBytes, bytesToUtf8, toHex } = require('../../src/bytes');
const { randomBytes } = require('../../src/vendor/exports/@noble/ciphers/utils.js');

/*
 * THE ENVELOPE (Brad, 2026-10-06): every message names its sender and itself -
 * wire: {dev, id, ts} - and an answer names the request it answers - re: {dev,
 * id}. The wire has no request ids otherwise, so a late answer to a request that
 * already gave up was taken by the NEXT request (seen with onlykey-js edge ping: "a
 * different id came back"). An answer whose re is not the request waiting is
 * dropped. Outside every signature (they cover named fields only) and inside the
 * encrypted session: it sorts answers, it proves nothing - nonces and the session
 * counters still do that. ts is for the log only; two clocks never decide.
 * An older app answers with no envelope: taken, as before.
 */
const newId = () => toHex(randomBytes(8));
/** the phone's answer to `request`, stamped (unchanged when the request had no envelope - an older computer) */
/**
 * @param {any} request
 * @param {any} answer
 * @param {{dev?: string, net?: string, now?: () => number}} [opts]  net: the chain the phone is on (BLOCKS.md)
 */
function answerEnvelope(request, answer, { dev, net, now = Date.now } = {}) {
  const w = request && request.wire;
  if (!w || typeof w.id !== 'string' || !answer || typeof answer !== 'object') return answer;
  return { ...answer, wire: { dev: String(dev || ''), id: newId(), ts: now(), re: { dev: String(w.dev || ''), id: w.id }, ...(net ? { net } : {}) } };
}
const { inLane } = require('../../src/transport/lane');

const OKEDGE_REQUEST = 0xf7;
const KIND = Object.freeze({ REQUEST: 1, ANSWER: 2 });
const PIECE = 54;
const MAX_PIECES = 0xffff;
/* the longest quiet gap inside one answer before it counts as lost */
const PIECE_GAP_MS = 10000;
const HEADER = 10; /* FF FF FF FF, 0xF7, kind, index u16 LE, last, length */

/** a whole message -> its 64-byte reports */
function encode(kind, obj) {
  const data = utf8ToBytes(JSON.stringify(obj));
  const n = Math.max(1, Math.ceil(data.length / PIECE));
  if (n > MAX_PIECES) throw new RangeError(`edge wire: a message of ${data.length} bytes is too long`);
  const out = [];
  for (let i = 0; i < n; i++) {
    const part = data.subarray(i * PIECE, (i + 1) * PIECE);
    const r = new Uint8Array(64);
    r.set([0xff, 0xff, 0xff, 0xff, OKEDGE_REQUEST, kind, i & 0xff, i >>> 8, i === n - 1 ? 1 : 0, part.length]);
    r.set(part, HEADER);
    out.push(r);
  }
  return out;
}

/** is this report an OKEDGE_REQUEST piece (either direction)? */
function isEdgeRequestFrame(frame) {
  return frame && frame.length >= HEADER && frame[0] === 0xff && frame[1] === 0xff && frame[2] === 0xff && frame[3] === 0xff
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
      const [k, index, last, len] = [frame[5], frame[6] | (frame[7] << 8), frame[8], frame[9]];
      if (index === 0) { parts = []; kind = k; }
      /* the u16 index must be the next one: a lost, repeated or reordered piece drops the message */
      if (index !== parts.length || k !== kind || len > PIECE) { parts = []; return { error: 'out-of-order' }; }
      parts.push(frame.slice(HEADER, HEADER + len));
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
/*
 * THE CHAIN (BLOCKS.md; Brad, 2026-10-07: live and test "seperated ... like how bitcoin
 * does it"): every request names the net this computer is on (onlykey-js edge
 * --test-mode = test), and an answer from a phone on the other chain is turned into a
 * refusal here - a testnet budget can never be asked of, or taken from, the live
 * chain. The phone refuses the request too (ok-rn vendorBridge). An answer with no
 * net is an older app's: live.
 */
function createWireChannel(transport, { timeoutMs = 120000, iface = 2, device = null, log = () => {}, net = 'live' } = {}) {
  /* this computer's id on the wire: given, else one per run */
  const runId = newId();
  const devOf = () => String((typeof device === 'function' ? device() : device) || runId);
  return {
    /*
     * opts.timeoutMs: this message's own wait (a ping waits seconds, not the sheet's minutes).
     * opts.times: filled with this computer's own clock - start, written (the last write
     * acknowledged), firstIn (the answer's first piece), done - for onlykey-js edge ping - and lane
     * (when it got the key's lane: start..lane is queue time, not the radio).
     * opts.oneWay: nothing comes back (a ping's receipt): resolves null once written.
     */
    send(message, opts = {}) {
      const waitMs = opts && opts.timeoutMs ? opts.timeoutMs : timeoutMs;
      const dev = devOf();
      const id = newId();
      const times = (opts && opts.times) || {};
      times.start = Date.now();
      const stamped = { ...message, wire: { dev, id, ts: times.start, net } };
      return inLane(transport, () => new Promise((resolve, reject) => {
        times.lane = Date.now();
        if (opts && opts.oneWay) {
          (async () => {
            const frames = encode(KIND.REQUEST, stamped);
            if (typeof transport.writeMany === 'function') await transport.writeMany(iface, frames);
            else for (const frame of frames) await transport.write(iface, frame);
            times.written = Date.now();
          })().then(() => resolve(null), reject);
          return;
        }
        const asm = createAssembler();
        /* what arrived while waiting, for the timeout's line: no pieces at all, or an answer cut short */
        const heard = { pieces: 0, last: -1 };
        let timer = null;
        /*
         * AN ANSWER STILL ARRIVING IS NOT LATE (Windows desktop + A13, 2026-10-25): the wait is sized by what is SENT,
         * and a 1.6 KB HAVE drew a GIVE of over 100 KB - 1854 pieces had come at 3 KB/s when the 31 s ran out. So each
         * answer piece moves the deadline to at least PIECE_GAP_MS ahead; the first wait is still waitMs.
         */
        let deadline = Date.now() + waitMs;
        let off = () => {};
        off = transport.on('report', (event) => {
          if (event.iface !== iface) return;
          if (times.firstIn === undefined) times.firstIn = Date.now();
          const data = event.data instanceof Uint8Array ? event.data : Uint8Array.from(event.data);
          if (isEdgeRequestFrame(data)) {
            heard.pieces += 1;
            heard.last = data[6] | (data[7] << 8);
            deadline = Math.max(deadline, Date.now() + PIECE_GAP_MS);
          }
          const got = asm.push(data);
          /* a dropped answer is said, not silent: otherwise it reads as "no answer" once the timer runs out */
          if (got && got.error) log(`edge wire: dropped an answer being gathered (${got.error} at piece ${data[6] | (data[7] << 8)})`);
          if (!got || got.error || got.kind !== KIND.ANSWER) return;
          const re = got.message && got.message.wire && got.message.wire.re;
          if (re && (re.id !== id || re.dev !== dev)) {
            log(`edge wire: dropped a stale answer (to ${re.id}, waiting for ${id})`);
            return;
          }
          clearTimeout(timer);
          off();
          times.done = Date.now();
          const theirs = (got.message && got.message.wire && got.message.wire.net) || 'live';
          if (theirs !== net) {
            resolve({ ok: false, refusal: 'net', detail: theirs === 'test' ? 'the host is on the testnet - add --test-mode' : 'the host is on the live chain - drop --test-mode' });
            return;
          }
          resolve(got.message);
        });
        const expire = () => {
          const left = deadline - Date.now();
          if (left > 0) { timer = setTimeout(expire, left); if (typeof timer.unref === 'function') timer.unref(); return; }
          off();
          log(`edge wire: no whole answer to ${message.type} after ${Math.round((Date.now() - times.lane) / 1000)} s (${heard.pieces ? `${heard.pieces} piece(s) came, the last index ${heard.last}` : 'no piece came'})`);
          resolve(null);
        };
        timer = setTimeout(expire, waitMs);
        /*
         * A wait nobody is still awaiting must not keep the process alive: a receipt's
         * note gives up after 4 s (client sendNote), and `onlykey-js edge receipt` then
         * sat until this 120 s timer ran out (Pixel, 2026-10-06).
         */
        if (timer && typeof timer.unref === 'function') timer.unref();
        (async () => {
          /* one request's frames together: a pipe with writeMany puts several in one write (pipeTransport.writeMany) */
          const frames = encode(KIND.REQUEST, stamped);
          if (typeof transport.writeMany === 'function') await transport.writeMany(iface, frames);
          else for (const frame of frames) await transport.write(iface, frame);
          times.written = Date.now();
        })().catch((e) => { clearTimeout(timer); off(); reject(e); });
      }));
    },
  };
}

module.exports = { OKEDGE_REQUEST, KIND, PIECE, MAX_PIECES, encode, isEdgeRequestFrame, createAssembler, createWireChannel, answerEnvelope };
