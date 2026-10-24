'use strict';

/**
 * desktop/protocol.js - the line protocol between the CLI and the ok-edge desktop app on one machine:
 * one JSON object per line, report bytes in base64. Both ends use these two helpers, so the framing
 * is written once.
 *
 *   CLI -> app   { t: 'hello', v, token }          first, within HELLO_MS
 *                { t: 'write', iface, b64 }       a report for the key - or, an 0xF7 piece, for the host
 *   app -> CLI   { t: 'ready', device, interfaces } the hello was accepted
 *                { t: 'refused', why }             it was not (and the socket closes)
 *                { t: 'report', iface, b64 }      a report from the key - or a piece of the host's answer
 *                { t: 'error', why }              a write the key did not take
 *                { t: 'close', why }              the key went away
 */

const HELLO_MS = 5000;
const MAX_LINE = 1 << 20; /* a line longer than this is not ours */

const send = (socket, obj) => { if (!socket.destroyed) socket.write(`${JSON.stringify(obj)}\n`); };

/** calls onMessage(obj) per line; a line that is not JSON, or too long, ends the socket */
function readLines(socket, onMessage) {
  let buffered = '';
  socket.setEncoding('utf8');
  socket.on('data', (chunk) => {
    buffered += chunk;
    if (buffered.length > MAX_LINE) { socket.destroy(); return; }
    for (let at = buffered.indexOf('\n'); at !== -1; at = buffered.indexOf('\n')) {
      const line = buffered.slice(0, at);
      buffered = buffered.slice(at + 1);
      if (!line.trim()) continue;
      let obj;
      try { obj = JSON.parse(line); } catch (_) { socket.destroy(); return; }
      onMessage(obj);
    }
  });
}

const toB64 = (bytes) => Buffer.from(bytes).toString('base64');
const fromB64 = (s) => new Uint8Array(Buffer.from(String(s || ''), 'base64'));

module.exports = { HELLO_MS, send, readLines, toB64, fromB64 };
