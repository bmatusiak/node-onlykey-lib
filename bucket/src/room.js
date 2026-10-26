'use strict';

/**
 * JOINING THE IDENTITY'S ROOM ON THE USER'S SERVER (ok-edge plan M1; Brad, 2026-10-26: "the webapp communicates to the
 * mcp over websockets"; "when a key gets plugged into the webapp, its a blank bucket, and we need to get remote buckets
 * from other devices that are connected to the same service").
 *
 * The server (ok-edge mcp-server/, a Cloudflare Worker) keeps one ROOM per bucket identity: the devices of that
 * identity online now. A device enters with the key alone - no code, no account:
 *   1. server -> {t: 'challenge', nonce}                     a fresh nonce for this connection
 *   2. device -> {t: 'join', identityPublicKey, bucketPublicKey, certificate, signature, device}
 *      the device's BUCKET KEY signs (purpose 'join') the server's host and the nonce, with the certificate the bucket
 *      identity made for that key ON THE KEY (bucket-identity.js) - so only a device that held the key of this
 *      identity can enter, and the proof is good for this server and this connection only: another server cannot
 *      relay it, a recorded one is never asked for again.
 *   3. server -> {t: 'joined', you, peers} or {t: 'refused'} and the connection ends.
 * The room's name is the identity id (identityIdOf of the public key): a join whose key does not hash to the room it
 * asked for is refused like any other bad proof - the same plain refusal, which says nothing about who else is there.
 *
 * WHAT THE SERVER LEARNS: which identity's devices are online, and their names - never a bucket byte. Frames between
 * devices are passed as they come; the trade (trade.js) seals and proves end to end over them (M2).
 *
 * Pure: no device, no wire, no Node built-ins - the same file runs in the Worker, the web app and the CLI.
 */

const bid = require('./bucket-identity');
const { toHex, fromHex } = require('../../src/bytes');

const NONCE = 32;
const KINDS = new Set(['webapp', 'desktop', 'android', 'cli', 'agent']);
const REFUSED = { ok: false };

const utf8 = (s) => new TextEncoder().encode(s);
const hex = (s, n) => typeof s === 'string' && (n ? s.length === n * 2 : s.length > 0) && /^[0-9a-f]+$/.test(s);

/* what a join signs: the server's host and its nonce - never valid on another server or another connection */
const joinBytes = (host, nonce) => new Uint8Array([...utf8(`${String(host).toLowerCase()}|`), ...nonce]);

/**
 * The server's challenge for one connection.
 * @param {(n: number) => Uint8Array} randomBytes
 */
function challenge(randomBytes) {
  const nonce = Uint8Array.from(randomBytes(NONCE));
  return { nonce, message: { t: 'challenge', nonce: toHex(nonce) } };
}

/**
 * A device's join, answering a server's challenge.
 * @param {{identityPublicKey: Uint8Array, bucketKey: {secretKey: Uint8Array, publicKey: Uint8Array}, certificate: Uint8Array}} me
 * @param {{nonce: string, host: string}} asked the challenge's nonce (hex) and the server's host as the device reached it
 * @param {{id: string, name: string, kind: string}} device how this device shows in the room
 */
function join(me, asked, device) {
  return {
    t: 'join',
    identityPublicKey: toHex(me.identityPublicKey),
    bucketPublicKey: toHex(me.bucketKey.publicKey),
    certificate: toHex(me.certificate),
    signature: toHex(bid.sign(me.bucketKey, 'join', joinBytes(asked.host, fromHex(asked.nonce)))),
    device,
  };
}

/** A device as a room shows it: id 16-64 hex, a name up to 64 characters, one of KINDS - or null. */
function deviceOf(d) {
  if (!d || !hex(d.id) || d.id.length < 16 || d.id.length > 64) return null;
  if (typeof d.name !== 'string' || !d.name.trim() || d.name.length > 64 || !KINDS.has(d.kind)) return null;
  return { id: d.id, name: d.name.trim(), kind: d.kind };
}

/**
 * The server checks a join. Never throws.
 * @param {string} room the identity id the connection asked for
 * @param {object} msg the device's join
 * @param {{nonce: Uint8Array, host: string}} asked this connection's challenge and the server's own host
 * @returns {{ok: true, identity: string, device: {id: string, name: string, kind: string}} | {ok: false}}
 */
function checkJoin(room, msg, asked) {
  try {
    if (!msg || msg.t !== 'join' || !hex(msg.identityPublicKey, 32) || !hex(msg.bucketPublicKey, 32)) return REFUSED;
    if (!hex(msg.certificate, 64) || !hex(msg.signature, 64)) return REFUSED;
    const device = deviceOf(msg.device);
    const identityPublicKey = fromHex(msg.identityPublicKey);
    if (!device || bid.identityIdOf(identityPublicKey) !== room) return REFUSED;
    const ok = bid.verify({
      identityPublicKey, bucketPublicKey: fromHex(msg.bucketPublicKey), certificate: fromHex(msg.certificate),
      purpose: 'join', bytes: joinBytes(asked.host, asked.nonce), signature: fromHex(msg.signature),
    });
    return ok ? { ok: true, identity: room, device } : REFUSED;
  } catch {
    return REFUSED;
  }
}

module.exports = { NONCE, KINDS, challenge, join, checkJoin, deviceOf };
