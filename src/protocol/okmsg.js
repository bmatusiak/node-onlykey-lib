/*
 * okmsg.js - the OnlyKey client protocol frame.
 *
 * This is the vendor RawHID2 interface (usage page 0xFFAB, emulator iface 2) -
 * the one the app, the CLI and lib-agent all speak.
 *
 * Frame layout, from the firmware's own dispatch (okcore.cpp: recv_buffer[4] is
 * the message type) and confirmed against python-onlykey's send_message():
 *
 *   0..3  FF FF FF FF     header
 *   4     message type
 *   5     slot id         (only for messages that take one)
 *   6     field id        (only for OKSETSLOT-style messages)
 *   7..   payload
 *   pad to 64 with 0x00
 *
 * There is deliberately NO report ID here. The proven hardware client always
 * prepends a zero byte, but an in-process bus pads to 64 and does not strip a
 * leading report ID - so identical code would put different bytes on the wire
 * in each mode. Payloads carry no report ID; the transport adds one if its
 * platform needs it.
 *
 * Ported from onlykey-testing/lib/device/okmsg.js, which is the best-documented
 * version of this frame. Rewritten off Buffer onto Uint8Array - see ../bytes.js
 * for why - and extended with the slot/field arguments the app's sendMessage()
 * has and that version does not.
 */
'use strict';

const { fromLatin1, toLatin1 } = require('../bytes');
const { messageId, fieldId } = require('./msg');

const REPORT_SIZE = 64;
const HEADER = [0xff, 0xff, 0xff, 0xff];

/**
 * Build one 64-byte report.
 *
 * @param {object} spec
 * @param {number|string} spec.msg          MSG.* or its name
 * @param {number}        [spec.slot]       slot id, when the message takes one
 * @param {number|string} [spec.field]      FIELD.* or its name
 * @param {Uint8Array|number[]|string} [spec.payload]  string is taken as latin1
 * @returns {Uint8Array} exactly REPORT_SIZE bytes
 */
function build({ msg, slot, field, payload }) {
  if (msg === undefined) throw new Error('okmsg.build needs a msg');

  const parts = [...HEADER, messageId(msg) & 0xff];
  if (slot !== undefined && slot !== null) parts.push(slot & 0xff);
  if (field !== undefined && field !== null) parts.push(fieldId(field) & 0xff);

  let body;
  if (payload === undefined || payload === null) {
    body = new Uint8Array(0);
  } else if (typeof payload === 'string') {
    body = fromLatin1(payload);
  } else {
    body = Uint8Array.from(payload);
  }

  /*
   * Checked before the copy. A silent truncation would put a half-message on
   * the wire and leave the firmware looking like it ignored a valid one.
   */
  if (parts.length + body.length > REPORT_SIZE) {
    throw new RangeError(
      `message is ${parts.length + body.length} bytes, one report holds ${REPORT_SIZE}`,
    );
  }

  const frame = new Uint8Array(REPORT_SIZE);
  frame.set(parts, 0);
  frame.set(body, parts.length);
  return frame;
}

/**
 * OKCONNECT's payload: the epoch seconds as hex digit PAIRS, one byte each.
 *
 * Not the integer. python-onlykey's set_time() encodes 0x68bd1f40 as the four
 * bytes 0x68 0xBD 0x1F 0x40 by way of its hex STRING, and the firmware parses
 * it that way. Passing the number would be silently wrong rather than
 * rejected, which is why this is a named function and not an inline expression.
 *
 * @param {Date|number} [when]
 */
function setTimePayload(when = Date.now()) {
  const secs = Math.floor((when instanceof Date ? when.getTime() : when) / 1000);
  let hex = secs.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const out = [];
  for (let i = 0; i < hex.length; i += 2) out.push(parseInt(hex.slice(i, i + 2), 16));
  return out;
}

/**
 * A device response as text.
 *
 * hidprint() memsets its buffer and writes only the string, so everything after
 * it is NUL padding - which is not part of the message and must not end up in
 * an assertion. Trailing NULs only: an interior one is the device's own byte.
 *
 * @param {Uint8Array} bytes
 */
function text(bytes) {
  let end = bytes.length;
  while (end > 0 && bytes[end - 1] === 0x00) end--;
  return toLatin1(bytes.subarray(0, end));
}

/**
 * Split a response into its lock state and the rest.
 *
 * The device broadcasts its state on the vendor interface about once a second,
 * so a reply and a broadcast can arrive interleaved. Callers that want "is it
 * unlocked" should prefer the newest UNLOCKED in a window over the first match
 * - see the note in onlykey-testing's Device.status().
 *
 * @param {Uint8Array|string} response
 */
function parseState(response) {
  const raw = typeof response === 'string' ? response : text(response);
  if (/^UNLOCKED/.test(raw)) return { state: 'unlocked', raw };
  if (/^UNINITIALIZED/.test(raw)) return { state: 'uninitialized', raw };
  if (/^INITIALIZED/.test(raw)) return { state: 'locked', raw };
  if (/^Error/i.test(raw)) return { state: 'error', raw };
  return { state: 'unknown', raw };
}

module.exports = {
  REPORT_SIZE,
  HEADER,
  build,
  setTimePayload,
  text,
  parseState,
};
