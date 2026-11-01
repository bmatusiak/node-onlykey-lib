/*
 * THE ROOM'S SOCKET OVER BLUETOOTH - the messages, both ends (Brad, 2026-11-01: "the mcp server should make
 * communication with ble transparent - the phone asks over ble to talk to the mcp-server like it was connected to it
 * over websockets").
 *
 * A websocket carries the room's messages (bucket/src/room-client.js <-> the mcp-server's RoomCore): text, one message
 * at a time, opened to /ws/<room>, closed with a code. Over Bluetooth the same messages travel as framed messages with
 * frame command 0x86 (cli/ble-link.js fragments them to the link's MTU; the phone's native GATT layer passes the
 * command through unread). Each 0x86 message starts with a KIND byte:
 *
 *   HERE    server -> phone   {host}: the server's name - sent when the link comes up, and asked for with WHERE. The
 *                             login proof signs the host its challenge is for (room.js joinBytes, room-client takes it
 *                             from the url), so the phone dials ble://<host>, the server's own name.
 *   WHERE   phone -> server   {open}: say HERE again (the app restarted while the link stayed up, or the target was
 *                             set); `open` is whether the phone has a socket open - false, the server's socket for
 *                             this link is a dead one (the app's JS started over under a link that stayed up) and goes
 *   OPEN    phone -> server   {room}: dial /ws/<room>, as `new WebSocket(url)` does
 *   OPENED  server -> phone   {host}: the socket is up
 *   TEXT    both ways         one whole message (UTF-8)
 *   PART    both ways         a piece of a message too long for one frame; the pieces, in order, then a TEXT with
 *                             the rest make the message
 *   CLOSE   both ways         {code, reason}: the socket is gone, as a websocket close
 *
 * One socket per link: the phone opens its identity's room, and a second OPEN replaces the first. No gate here - the
 * room's own join (challenge, login proof, checkJoin) is the gate, exactly as over a websocket.
 *
 * Hermes-clean (the phone runs this): no Buffer, no TextEncoder - src/bytes.js's UTF-8.
 */
'use strict';

const { utf8ToBytes, bytesToUtf8 } = require('../bytes');

/** The frame command every socket message travels under (cli/ble-link.js, the phone's src/bleRoom.ts). */
const CMD_SOCKET = 0x86;
const KIND = Object.freeze({ OPEN: 1, OPENED: 2, TEXT: 3, PART: 4, CLOSE: 5, HERE: 6, WHERE: 7 });
/*
 * HOW MUCH ONE FRAME CARRIES: CTAP-over-BLE allows 128 continuations (sequence 0x00-0x7f) - the phone's framer
 * (CtapBleFramer.kt) refuses to send more and drops a message that has more. At the smallest MTU (23: a 20-byte
 * fragment) that is 17 + 128 x 19 = 2449 bytes, so a piece of 2400 (plus its kind byte) fits any link. More pieces cost
 * nothing that matters: a write per fragment is the cost, and the fragments are the same either way.
 */
const PART_MAX = 2400;

function withKind(kind, body) {
  const out = new Uint8Array(1 + body.length);
  out[0] = kind;
  out.set(body, 1);
  return out;
}
const json = (kind, value) => withKind(kind, utf8ToBytes(JSON.stringify(value)));

/** HERE: the server's name, for the phone's url and its login proof. */
const encodeHere = ({ host }) => json(KIND.HERE, { host: String(host) });
/** WHERE: the phone asks for HERE again, saying whether it has a socket open. */
const encodeWhere = ({ open = false } = {}) => json(KIND.WHERE, { open: Boolean(open) });
/** OPEN: the phone dials its identity's room. */
const encodeOpen = ({ room }) => json(KIND.OPEN, { room: String(room) });
/** OPENED: the server's answer - the socket is up. */
const encodeOpened = ({ host }) => json(KIND.OPENED, { host: String(host) });
/** CLOSE: either end; a websocket close's code and reason. */
const encodeClose = ({ code = 1000, reason = '' } = {}) => json(KIND.CLOSE, { code: Number(code) || 1000, reason: String(reason || '') });

/** TEXT (and PARTs first when it is long): one room message -> the 0x86 payloads to send, in order. */
function encodeText(text) {
  const bytes = utf8ToBytes(String(text));
  const out = [];
  let at = 0;
  for (; bytes.length - at > PART_MAX; at += PART_MAX) out.push(withKind(KIND.PART, bytes.subarray(at, at + PART_MAX)));
  out.push(withKind(KIND.TEXT, bytes.subarray(at)));
  return out;
}

/**
 * The receiving end: 0x86 payloads in, socket events out -
 *   {kind:'here', host} | {kind:'where', open} | {kind:'open', room} | {kind:'opened', host} | {kind:'text', text} |
 *   {kind:'close', code, reason} | null (a PART held, or a payload that is not one of these: dropped, as noise is on any
 *   link).
 */
function createDecoder() {
  let parts = [];
  let held = 0;
  const parse = (body) => { try { return JSON.parse(bytesToUtf8(body)); } catch { return null; } };
  return {
    push(payload) {
      const p = Uint8Array.from(payload || []);
      if (!p.length) return null;
      const body = p.subarray(1);
      switch (p[0]) {
        case KIND.PART:
          /* a runaway sender cannot grow this without end: 16 MB, then the pieces are dropped */
          if (held + body.length > 16 * 1024 * 1024) { parts = []; held = 0; return null; }
          parts.push(Uint8Array.from(body));
          held += body.length;
          return null;
        case KIND.TEXT: {
          const whole = new Uint8Array(held + body.length);
          let at = 0;
          for (const x of parts) { whole.set(x, at); at += x.length; }
          whole.set(body, at);
          parts = [];
          held = 0;
          return { kind: 'text', text: bytesToUtf8(whole) };
        }
        case KIND.HERE: { const v = parse(body); return v && typeof v.host === 'string' ? { kind: 'here', host: v.host } : null; }
        case KIND.WHERE: { const v = parse(body) || {}; return { kind: 'where', open: v.open !== false }; }
        case KIND.OPEN: { const v = parse(body); return v && typeof v.room === 'string' ? { kind: 'open', room: v.room } : null; }
        case KIND.OPENED: { const v = parse(body); return v && typeof v.host === 'string' ? { kind: 'opened', host: v.host } : null; }
        case KIND.CLOSE: { const v = parse(body) || {}; parts = []; held = 0; return { kind: 'close', code: Number(v.code) || 1000, reason: String(v.reason || '') }; }
        default: return null;
      }
    },
  };
}

/**
 * THE PHONE'S END: a WebSocket-shaped class for room-client's connectRoom ({WebSocket}), over one Bluetooth link's 0x86
 * messages - so the room client runs unchanged over the radio. The holder sends with `sendFrame(payload)` (one 0x86
 * payload) and feeds every 0x86 payload that arrives to `push(payload)`, and `down(reason)` when the link goes.
 *
 *   const s = createSocketLink({ sendFrame });
 *   s.host                       the server's name once HERE came (null before); onHere(fn) tells when
 *   connectRoom({ url: `ble://${s.host}`, WebSocket: s.WebSocket, ... })
 *
 * @param {{sendFrame: (payload: Uint8Array) => any}} o
 */
function createSocketLink({ sendFrame }) {
  const dec = createDecoder();
  let current = null;
  let host = null;
  const hereListeners = new Set();
  const out = (payload) => { try { const r = sendFrame(payload); if (r && r.catch) r.catch(() => {}); } catch { /* the link says it went */ } };

  class BleWebSocket {
    constructor(url) {
      this.url = String(url);
      this.readyState = 0;
      this.onopen = null;
      this.onmessage = null;
      this.onclose = null;
      this.onerror = null;
      const room = this.url.split('/ws/')[1] || '';
      /* one socket per link: a new one replaces the one before (its close told here, the server closes its side) */
      if (current) current.closed(1000, 'replaced');
      current = this;
      out(encodeOpen({ room }));
    }

    send(text) {
      if (this.readyState !== 1) throw new Error('the Bluetooth socket is not open');
      for (const p of encodeText(text)) out(p);
    }

    close(code = 1000, reason = '') {
      if (this.readyState >= 2) return;
      out(encodeClose({ code, reason }));
      this.closed(code, reason);
    }

    /* the socket is gone (its own close, the server's, or the link): once, as a websocket's close event */
    closed(code, reason) {
      if (this.readyState === 3) return;
      this.readyState = 3;
      if (current === this) current = null;
      if (this.onclose) this.onclose({ code, reason });
    }
  }

  return {
    WebSocket: BleWebSocket,
    get host() { return host; },
    /** fn(host) each time the server says its name (HERE) */
    onHere(fn) { hereListeners.add(fn); return () => hereListeners.delete(fn); },
    /** ask the server for HERE again (and say whether a socket is open on this side) */
    where() { out(encodeWhere({ open: Boolean(current) })); },
    /** one 0x86 payload from the link */
    push(payload) {
      const ev = dec.push(payload);
      if (!ev) return;
      if (ev.kind === 'here') {
        host = ev.host;
        for (const fn of [...hereListeners]) { try { fn(host); } catch { /* a listener's own trouble */ } }
        return;
      }
      const s = current;
      if (!s) return;
      if (ev.kind === 'opened') { s.readyState = 1; if (s.onopen) s.onopen({}); }
      else if (ev.kind === 'text') { if (s.readyState === 1 && s.onmessage) s.onmessage({ data: ev.text }); }
      else if (ev.kind === 'close') s.closed(ev.code, ev.reason);
    },
    /** the link went: the socket closes as a dropped websocket does (1006), and the server's name is forgotten */
    down(reason = 'the Bluetooth link went') {
      host = null;
      if (current) current.closed(1006, reason);
    },
  };
}

module.exports = {
  CMD_SOCKET, KIND, PART_MAX, encodeHere, encodeWhere, encodeOpen, encodeOpened, encodeText, encodeClose, createDecoder,
  createSocketLink,
};
