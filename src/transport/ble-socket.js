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
 *   OPEN    phone -> server   {room}: dial /ws/<room>, as `new WebSocket(url)` does
 *   OPENED  server -> phone   {host}: the socket is up; `host` is the name the server's challenge is for - the login
 *                             proof signs it (room.js joinBytes), so the phone must use the server's own
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

/** The frame command every socket message travels under (cli/ble-link.js, the phone's src/bleSocket.ts). */
const CMD_SOCKET = 0x86;
const KIND = Object.freeze({ OPEN: 1, OPENED: 2, TEXT: 3, PART: 4, CLOSE: 5 });
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

/** OPEN: the phone dials its identity's room. */
const encodeOpen = ({ room }) => json(KIND.OPEN, { room: String(room) });
/** OPENED: the server's answer - the host its challenge is for. */
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
 *   {kind:'open', room} | {kind:'opened', host} | {kind:'text', text} | {kind:'close', code, reason} | null (a PART
 *   held, or a payload that is not one of these: dropped, as noise is on any link).
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
        case KIND.OPEN: { const v = parse(body); return v && typeof v.room === 'string' ? { kind: 'open', room: v.room } : null; }
        case KIND.OPENED: { const v = parse(body); return v && typeof v.host === 'string' ? { kind: 'opened', host: v.host } : null; }
        case KIND.CLOSE: { const v = parse(body) || {}; parts = []; held = 0; return { kind: 'close', code: Number(v.code) || 1000, reason: String(v.reason || '') }; }
        default: return null;
      }
    },
  };
}

module.exports = { CMD_SOCKET, KIND, PART_MAX, encodeOpen, encodeOpened, encodeText, encodeClose, createDecoder };
