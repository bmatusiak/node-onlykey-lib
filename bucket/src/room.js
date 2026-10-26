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
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { hkdf } = require('../../src/vendor/exports/@noble/hashes/hkdf.js');
const { xchacha20poly1305 } = require('../../src/vendor/exports/@noble/ciphers/chacha.js');

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

/*
 * FRAMES BETWEEN THE ROOM'S DEVICES ARE SEALED (ok-edge plan: "the server sees ciphertext"). Every device of one bucket
 * identity derives the same BUCKET KEY (the same backup gives the same key - bucket-identity.js), so a frame key
 * derived from it is shared by exactly the devices that could join the room, and by nothing else - the server
 * included. XChaCha20-Poly1305 with a random 24-byte nonce; the associated data names the room, the sender and the
 * receiver, so the server can neither read a frame nor hand one device's frame to another as if it came from a third.
 * Replays are the protocol's own business above this (the trade's fresh nonces refuse them).
 */
const FRAME_NONCE = 24;
const utf8bytes = (s) => new TextEncoder().encode(s);

/** The frame key of a room: the bucket key's secret, through HKDF, bound to the room. */
function frameKey(bucketKey, roomId) {
  return hkdf(sha256, Uint8Array.from(bucketKey.secretKey), utf8bytes('OKSERVER-FRAME-v1'), utf8bytes(String(roomId)), 32);
}

const frameAad = (roomId, from, to) => utf8bytes(`okroom|${roomId}|${from}|${to}`);

/**
 * Seal one frame body for the server to pass on.
 * @param {Uint8Array} key frameKey()
 * @param {{room: string, from: string, to: string}} who
 * @param {object} payload anything JSON
 * @param {(n: number) => Uint8Array} randomBytes
 * @returns {string} hex of nonce | ciphertext
 */
function sealFrame(key, who, payload, randomBytes) {
  const nonce = Uint8Array.from(randomBytes(FRAME_NONCE));
  const ct = xchacha20poly1305(key, nonce, frameAad(who.room, who.from, who.to)).encrypt(utf8bytes(JSON.stringify(payload)));
  return toHex(nonce) + toHex(ct);
}

/** Open a frame body, or null when it is not one sealed for this room, from that sender, to this receiver. */
function openFrame(key, who, body) {
  try {
    if (typeof body !== 'string' || !/^[0-9a-f]+$/.test(body) || body.length < (FRAME_NONCE + 16) * 2) return null;
    const bytes = fromHex(body);
    const pt = xchacha20poly1305(key, bytes.subarray(0, FRAME_NONCE), frameAad(who.room, who.from, who.to)).decrypt(bytes.subarray(FRAME_NONCE));
    return JSON.parse(new TextDecoder().decode(pt));
  } catch {
    return null;
  }
}

module.exports = { NONCE, KINDS, challenge, join, checkJoin, deviceOf, frameKey, sealFrame, openFrame };
