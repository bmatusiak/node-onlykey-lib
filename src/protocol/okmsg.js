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
 * ## This is not how the session sends the time
 *
 * `session.connect()` does not call this. It builds the whole 43-byte OKCONNECT
 * payload in one go - `transit.connectPayload()`, which writes the same seconds
 * as a fixed big-endian uint32 at bytes [5..8] and appends the transit public
 * key. The firmware dispatches `case OKCONNECT: set_time(recv_buffer)`, so the
 * time IS set on every connect; it just does not come from here.
 *
 * What this is for is a caller building the frame ITSELF - which is what
 * ok-rn's soft-key suite does to prove the firmware answers OKCONNECT at all,
 * without a session in the way.
 *
 * ## The two encoders agree, and only by arithmetic
 *
 * For any epoch that fits in four bytes these produce identical bytes, which is
 * why nothing has ever noticed there are two. They diverge past 0xFFFFFFFF -
 * February 2106 - where this grows a fifth byte and connectPayload cannot.
 * test/okmsg.test.js pins that agreement so it cannot drift quietly.
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
  /*
   * A key that has taken the OKFWUPDATE kick re-enumerates saying
   * BOOTLOADER (the desktop keys isBootloader off the same word,
   * OnlyKeyComm.js:1447). It was 'unknown' here, which a host cannot tell
   * from a garbled reply; the firmware update path needs to know.
   */
  if (/BOOTLOADER/.test(raw)) return { state: 'bootloader', raw };
  return { state: 'unknown', raw };
}

/**
 * What KIND of refusal the device just gave.
 *
 * The firmware has 113 distinct `hidprint()` sentences and a host that wants
 * to behave differently for "the slot is empty" than for "you are not in
 * config mode" has been matching them with regexes at each call site -
 * `/no ECC Private Key/` in one place, `/not set as decryption key/` in
 * another, `/out of range/` in a third. python-onlykey does the same thing
 * with a thirteen-branch if-chain (client.py:404-433) and re-raises each
 * sentence as itself, which classifies nothing.
 *
 * This groups them instead. The kind is for BRANCHING; the device's own
 * words stay the message, because they say which slot and which field and
 * no summary of mine will. Transcribing all 113 as constants would be a
 * second copy of the firmware's strings to keep in step with it - the
 * groups are the part that is stable.
 *
 * Returns null for anything that is not a refusal, including the success
 * sentences and the status broadcasts.
 *
 * @param {string} message  the device's text
 * @returns {string|null}
 */
function errorKind(message) {
  const said = String(message || '').trim();
  if (!said) return null;

  /*
   * TWO refusals do not begin with "Error", and both were missed by a
   * leading-Error test: "No PIN set, You must set a PIN first"
   * (okcore.cpp:576) and "Timeout occured while waiting for confirmation on
   * OnlyKey", which is the answer to an unanswered button challenge and the
   * most ordinary failure a signing caller will ever see. The firmware's
   * spelling of "occured" is its own; matched as written.
   */
  if (/^No PIN set/i.test(said) || /must be initialized first/i.test(said)) {
    return 'uninitialized';
  }
  if (/^Timeout occured/i.test(said)) return 'challenge';
  if (!/^Error/i.test(said)) return null;

  if (/device locked/i.test(said)) return 'locked';
  if (/not in config mode/i.test(said)) return 'configMode';
  if (/may not be changed|may only be changed/i.test(said)) return 'refused';
  if (/no (ECC |RSA )?(Private )?[Kk]ey set in this slot/i.test(said)) return 'emptySlot';
  if (/not set as (signature|decryption) key/i.test(said)) return 'wrongRole';
  /*
   * "invalid derived key slot" since libraries 80cacfe: the derived decrypt
   * path whitelists its codes like the sign path, and refuses anything else -
   * an Ed25519 code, or a code outside its derivation's table - with this.
   */
  if (/invalid (ECC|RSA|derived key) slot|reserved slot/i.test(said)) return 'badSlot';
  if (/no backup key set|backup key mode|incorrect backup key|backup file|backup does not match/i.test(said)) {
    return 'backup';
  }
  /*
   * THREE confirmation failures on v3.0.5, where earlier firmware reported one.
   * Up to v3.0.4 every failed button confirmation printed "Error incorrect
   * challenge was entered", including a window that simply closed and a press
   * the firmware refused. OnlyKey-Firmware 8b3d5c0 ("Stop calling every failed
   * confirmation an incorrect challenge") gives those two their own sentences,
   * and python-onlykey raises each by name (protocol.py CONFIRMATION_WINDOW_
   * CLOSED and PRESS_NOT_ACCEPTED), so they get their own kinds here. Before
   * this they matched nothing and fell through to the generic 'error'.
   *
   * 'challenge' keeps meaning what the firmware says it means: the digits were
   * wrong, or the confirmation timed out.
   */
  if (/confirmation window closed/i.test(said)) return 'confirmationClosed';
  if (/button press was not accepted/i.test(said)) return 'pressNotAccepted';
  if (/incorrect challenge|Timeout occured/i.test(said)) return 'challenge';
  if (/already enabled on this slot/i.test(said)) return 'needsPin';
  /*
   * The 3.0.5 caller errors, checked BEFORE the crypto rule below because
   * several of them name a decaps or X-Wing and would otherwise read as the
   * device's crypto failing. Each one is the host sending the wrong thing:
   * a value the enum does not have (or this build does not allow), a policy
   * bit that is not defined, the wrong opcode for the key type, a decaps
   * chunk of the wrong size, or a decaps continuation with nothing primed.
   * Read from the hidprint() strings added between libraries c8804e3 and
   * b412e78; none exists on v3.0.4.
   */
  if (/(invalid|unsupported) user input mode|invalid webcrypt policy|use OKGETPUBKEY PQC|use OKDECRYPT for derived|derived decaps (chunk|payload) size|no derived decaps request pending/i.test(said)) {
    return 'badInput';
  }
  if (/invalid size|wrong size|bad input size|exceeded size limit|not between|out of range|invalid RSA type|ECC type incorrect|key check failed|does not match key|use (ML-KEM|X-Wing) decaps/i.test(said)) {
    return 'badInput';
  }
  if (/ML-KEM|ML-DSA|X-Wing|X25519|RSA (signing|decryption|Encryption)|generating RSA|ECC Shared Secret|keygen|decaps|expansion/i.test(said)) {
    return 'cryptoFailed';
  }
  return 'error';
}

/**
 * An Error carrying the device's words and the kind they fall into.
 *
 * `context` prefixes the message the way a caller would anyway ("wipeKey
 * slot 101"), and is left off the `deviceText` so a caller that wants to
 * compare or re-display the raw sentence still can.
 */
function deviceError(message, context = '') {
  const said = String(message || '').trim();
  const err = new Error(context ? `${context}: ${said}` : said);
  err.deviceText = said;
  err.kind = errorKind(said);
  return err;
}

module.exports = {
  REPORT_SIZE,
  HEADER,
  build,
  setTimePayload,
  text,
  parseState,
  errorKind,
  deviceError,
};
