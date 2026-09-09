/*
 * chunker.js - the vendor-interface upload paths.
 *
 * These are NOT the same as protocol/chunk.js. That one chunks a request
 * across the WebAuthn tunnel in 228-byte pieces with a monotonic packet
 * number; these move bulk data over the raw vendor interface, 57 bytes at a
 * time, with a completely different framing.
 *
 * There are two distinct algorithms here, and conflating them is the mistake
 * this file exists to prevent.
 *
 *   restore and firmware  a length-or-FF header byte, hex string input
 *   RSA private keys      no header at all, byte array input
 *
 * They look similar enough to unify and must not be.
 */
'use strict';

const okmsg = require('../protocol/okmsg');
const { MSG } = require('../protocol/msg');
const { fromHex } = require('../bytes');

/**
 * 57 payload bytes per report.
 *
 * The frame is 4 header + 1 msg + 1 packet-header byte = 6, leaving 57 of the
 * 64. For OKSETPRIV it is 4 + msg + slot + type = 7, leaving 57 as well - the
 * numbers coincide, which is part of why these look interchangeable.
 */
const CHUNK_BYTES = 57;

/** 57 bytes as hex characters. */
const CHUNK_HEX = CHUNK_BYTES * 2;

/**
 * The header byte that means "a full chunk, more follow".
 *
 * Any value <= 57 means "this is the last chunk and it holds this many bytes".
 * So an input that divides exactly by 57 ends with a header of 0x39 (57), NOT
 * 0xFF - the `<= 0` test in the original is inclusive, and the final full
 * chunk is still final.
 */
const MORE_FOLLOW = 0xff;

/**
 * Split a hex string into restore/firmware packets.
 *
 * Each packet is [header][up to 57 data bytes], where the header is 0xFF for
 * every chunk but the last and the byte count for the last.
 *
 * @param {string} hex  an even-length hex string
 * @returns {Array<{header: number, data: Uint8Array, final: boolean}>}
 */
function hexPackets(hex) {
  const clean = String(hex).replace(/\s/g, '');
  if (clean.length === 0) return [];
  if (clean.length % 2 !== 0) {
    /*
     * The original computes its header as (length/2).toString(16), so an
     * odd-length input yields something like "1c.8", which Number('0x1c.8')
     * turns into NaN and then into a zero byte. A silently zero-length final
     * packet is worse than a refusal.
     */
    throw new Error(`hex payload has odd length ${clean.length}; each byte needs two chars`);
  }

  const packets = [];
  for (let at = 0; at < clean.length; at += CHUNK_HEX) {
    const slice = clean.slice(at, at + CHUNK_HEX);
    const isFinal = at + CHUNK_HEX >= clean.length;
    packets.push({
      header: isFinal ? slice.length / 2 : MORE_FOLLOW,
      data: fromHex(slice),
      final: isFinal,
    });
  }
  return packets;
}

/** One 64-byte frame for a restore/firmware packet. */
function buildHexPacket(msg, packet) {
  const payload = new Uint8Array(1 + packet.data.length);
  payload[0] = packet.header;
  payload.set(packet.data, 1);
  return okmsg.build({ msg, payload });
}

/**
 * Split raw bytes into crypto packets.
 *
 * Same 57-byte chunking as hexPackets, over bytes rather than hex, because
 * what gets signed is a digest and what gets decrypted is ciphertext - neither
 * arrives as a hex string.
 */
function bytePackets(bytes) {
  const data = Uint8Array.from(bytes);
  if (!data.length) return [];

  const packets = [];
  for (let at = 0; at < data.length; at += CHUNK_BYTES) {
    const slice = data.subarray(at, at + CHUNK_BYTES);
    const isFinal = at + CHUNK_BYTES >= data.length;
    packets.push({
      header: isFinal ? slice.length : MORE_FOLLOW,
      data: slice,
      final: isFinal,
    });
  }
  return packets;
}

/**
 * One 64-byte frame for a crypto packet.
 *
 * THE SLOT BYTE IS THE WHOLE DIFFERENCE, and it is one byte in a place that
 * makes the two framings look interchangeable:
 *
 *     restore/firmware   [header|msg     |0xFF-or-len|57 bytes]
 *     sign/decrypt       [header|msg|slot|0xFF-or-len|57 bytes]
 *
 * process_packets() reads buffer[4] as the command, buffer[5] as the SLOT,
 * buffer[6] as 0xFF-or-length and buffer[7..] as the data
 * (okcore.cpp:7472-7519). Reusing buildHexPacket here would put the length
 * byte where the firmware reads the slot and start the data one byte early -
 * so the device would look up a key in whatever slot the length happened to
 * name, and sign the wrong bytes with it. Both halves fail silently.
 *
 * The 57 is not a coincidence between the two: 4 header + msg + chunk-header
 * is 6, and 4 + msg + slot + chunk-header is 7 - but OKSETPRIV also spends
 * its seventh byte on a type, so all three leave 57. That is exactly why the
 * wrong frame is the same length as the right one and passes every check
 * except the device.
 */
function buildSlotPacket(msg, slot, packet) {
  const payload = new Uint8Array(1 + packet.data.length);
  payload[0] = packet.header;
  payload.set(packet.data, 1);
  return okmsg.build({ msg, slot, payload });
}

/**
 * Stream bytes to a slot-addressed command: OKSIGN, OKDECRYPT.
 *
 * Returns the packets sent, because the CHALLENGE the device then asks for is
 * derived from exactly these bytes - sha256 over the accumulated payload
 * (okcore.cpp:7577-7587) - and the caller has to be able to compute the same
 * digits to know which buttons to press.
 *
 * @param {object}   spec
 * @param {number}   spec.msg    MSG.OKSIGN or MSG.OKDECRYPT
 * @param {number}   spec.slot
 * @param {Uint8Array} spec.data
 * @param {function} spec.send   async (frame) => void
 * @param {function} [spec.onProgress]
 */
async function sendSlotStream({ msg, slot, data, send, onProgress = null }) {
  const packets = bytePackets(data);
  if (!packets.length) {
    throw new Error('nothing to send: the payload is empty');
  }

  for (let i = 0; i < packets.length; i++) {
    await send(buildSlotPacket(msg, slot, packets[i]));
    if (onProgress) onProgress({ packet: i + 1, of: packets.length });
  }
  return { packets: packets.length, bytes: Uint8Array.from(data) };
}

/**
 * Send a hex payload as restore or firmware packets.
 *
 * @param {object}   spec
 * @param {number}   spec.msg      MSG.OKRESTORE or MSG.OKFWUPDATE
 * @param {string}   spec.hex
 * @param {function} spec.send     async (frame) => void
 * @param {function} [spec.awaitAck]  async (packet) => void, awaited between
 *                   packets. Firmware update gates on "RECEIVED OKFWUPDATE";
 *                   restore fires back-to-back with no acknowledgement.
 * @param {function} [spec.onProgress]
 */
async function sendHexStream({ msg, hex, send, awaitAck = null, onProgress = null }) {
  const packets = hexPackets(hex);
  if (!packets.length) {
    throw new Error('nothing to send: the payload is empty');
  }

  for (let i = 0; i < packets.length; i++) {
    await send(buildHexPacket(msg, packets[i]));
    if (onProgress) onProgress({ packet: i + 1, of: packets.length });
    if (awaitAck && !packets[i].final) await awaitAck(packets[i]);
  }
  return packets.length;
}

/**
 * Split an RSA private key for OKSETPRIV.
 *
 * Deliberately separate from the above, because the framing is different in
 * every respect: the input is bytes rather than hex, there is NO length header
 * on any packet, and slot and type are repeated identically on every one.
 *
 * TERMINATION IS DEVICE-SIDE. Nothing on the wire says "last packet". The
 * device knows the total because `type` encodes the key size and it counts to
 * 128 * type - so a key whose length is an exact multiple of 57 ends with a
 * full packet that is indistinguishable from a middle one, and that is fine
 * only because of the counting. Do not "improve" this into a length-headed
 * format; the device would stop understanding it.
 */
function rsaPackets(key) {
  const bytes = Uint8Array.from(key);
  const packets = [];
  for (let at = 0; at < bytes.length; at += CHUNK_BYTES) {
    packets.push(bytes.subarray(at, at + CHUNK_BYTES));
  }
  return packets;
}

/**
 * @param {object}   spec
 * @param {number}   spec.slot
 * @param {number}   spec.type   1-4 for RSA 1024/2048/3072/4096, plus modifiers
 * @param {Uint8Array} spec.key  p || q
 * @param {function} spec.send
 */
async function sendRsaKey({ slot, type, key, send, onProgress = null }) {
  const packets = rsaPackets(key);
  if (!packets.length) throw new Error('nothing to send: the key is empty');

  for (let i = 0; i < packets.length; i++) {
    await send(okmsg.build({
      msg: MSG.OKSETPRIV,
      slot,
      field: type,
      payload: packets[i],
    }));
    if (onProgress) onProgress({ packet: i + 1, of: packets.length });
  }
  return packets.length;
}

/**
 * The RSA key length the device will expect for a given type.
 *
 * Exposed so a caller can check its key before sending: a mismatch is not
 * reported by the device, it simply waits for bytes that never arrive.
 */
function rsaKeyLength(type) {
  const size = type & 0x0f;
  if (size < 1 || size > 4) throw new RangeError(`RSA type must be 1-4, got ${size}`);
  return 128 * size;
}

module.exports = {
  CHUNK_BYTES,
  bytePackets,
  buildSlotPacket,
  sendSlotStream,
  CHUNK_HEX,
  MORE_FOLLOW,
  hexPackets,
  buildHexPacket,
  sendHexStream,
  rsaPackets,
  sendRsaKey,
  rsaKeyLength,
};
