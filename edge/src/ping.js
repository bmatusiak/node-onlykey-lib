'use strict';

/*
 * PING-PONG: a pure Bluetooth link test (Brad, 2026-10-06; TESTING MODE ONLY on
 * the phone). The computer makes `size` random bytes, names them by their
 * SHA-256 and sends {type: 'ping', id, data}; the phone sends the same id and
 * data straight back and does nothing else - no key, no screen, no storage. The
 * computer checks the answer's id is its own hash AND that the returned data
 * hashes to it, so a test says both how fast and that every byte came back.
 *
 * The data rides the Edge wire (wire.js: at most 255 pieces of 55 bytes of
 * JSON), so one ping carries at most PING_MAX random bytes (base64 inside).
 * Plain bytes and @noble only: Hermes-clean (the phone answers with it too).
 */

const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { toHex, toBase64, fromBase64 } = require('../../src/bytes');

const PING_TYPE = 'ping';
const PONG_TYPE = 'pong';
/* the computer's verdict, back to the phone (one-way): both logs end with it */
const RECEIPT_TYPE = 'ping-receipt';
const PING_MAX = 8192;

/** the computer's message for these bytes */
function buildPing(data) {
  if (!(data instanceof Uint8Array)) throw new TypeError('ping: data must be bytes');
  if (data.length > PING_MAX) throw new RangeError(`ping: at most ${PING_MAX} bytes, not ${data.length}`);
  return { type: PING_TYPE, id: toHex(sha256(data)), data: toBase64(data) };
}

/**
 * The phone's answer: the same id and data, nothing looked at but the shape -
 * or null (not a ping, or not one this phone sends back).
 */
/**
 * @param {any} message
 * @param {{firstAt?: number|null, rxAt?: number|null, now?: () => number}} [times]
 */
function answerPing(message, { firstAt = null, rxAt = null, now = Date.now } = {}) {
  if (!message || message.type !== PING_TYPE) return null;
  if (typeof message.id !== 'string' || !/^[0-9a-f]{64}$/.test(message.id)) return null;
  if (typeof message.data !== 'string' || message.data.length > Math.ceil(PING_MAX / 3) * 4) return null;
  /* the phone's own clock (Brad): the first piece in, the whole ping in, and just before the echo goes out */
  return { type: PONG_TYPE, id: message.id, data: message.data, firstAt, rxAt, txAt: now() };
}

/** -> {ok: true} when the answer is our id and its data hashes to it; else {ok: false, why} */
function checkPong(sent, answer) {
  if (!answer || answer.type !== PONG_TYPE) return { ok: false, why: 'no pong' };
  if (answer.id !== sent.id) return { ok: false, why: 'a different id came back' };
  let back;
  try {
    back = fromBase64(String(answer.data));
  } catch {
    return { ok: false, why: 'the data came back unreadable' };
  }
  if (toHex(sha256(back)) !== sent.id) return { ok: false, why: 'the data came back changed (its hash is not the id)' };
  return { ok: true, bytes: back.length };
}

module.exports = { PING_TYPE, PONG_TYPE, RECEIPT_TYPE, PING_MAX, buildPing, answerPing, checkPong };
