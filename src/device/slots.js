/*
 * slots.js - slot numbering, and reading the label list back.
 *
 * Extracted from OnlyKey-App's OnlyKeyComm.js (getSlotNum:632,
 * handleGetLabels:471). The numbering is pure arithmetic; the label read is a
 * small state machine that the original ran directly out of a HID callback
 * with a DOM call in the middle of it.
 */
'use strict';

const { MSG, IFACE } = require('../protocol/msg');
const okmsg = require('../protocol/okmsg');

const DEVICE_TYPE = { CLASSIC: 'classic', DUO: 'duo' };

/** Classic has 6 pairs; DUO has 4 profiles of 6. */
const SLOT_COUNT = { [DEVICE_TYPE.CLASSIC]: 12, [DEVICE_TYPE.DUO]: 24 };

/**
 * The device-global pseudo-slot.
 *
 * The original reaches 0 by accident: it passes the string 'XX' through
 * strPad() into a Uint8Array, where it becomes NaN and stores as 0. Relying on
 * that coercion is how a refactor silently changes which slot gets written, so
 * it is named here instead.
 */
const GLOBAL_SLOT = 0;
const GLOBAL_SLOT_ID = 'XX';

/**
 * Slot id ('3a', '12b', 'XX') to the number the firmware uses.
 *
 * Classic is one +0/+6 split over six pairs. DUO interleaves a and b WITHIN
 * each three-slot band, so that consecutive profiles occupy contiguous runs of
 * six - which is why it cannot be expressed as one offset.
 */
function slotNumber(slotId, deviceType = DEVICE_TYPE.CLASSIC) {
  if (slotId === GLOBAL_SLOT_ID) return GLOBAL_SLOT;
  if (typeof slotId === 'number') return slotId;

  const n = parseInt(slotId, 10);
  const side = String(slotId).match(/[ab]/);
  if (!Number.isInteger(n) || !side) {
    throw new Error(`unrecognised slot id: ${slotId}`);
  }
  const isA = side[0] === 'a';

  if (deviceType === DEVICE_TYPE.DUO) {
    // Bands of three. The original has no else branch past 12 and returns
    // undefined; here it is an error.
    if (n <= 3) return n + (isA ? 0 : 3);
    if (n <= 6) return n + (isA ? 3 : 6);
    if (n <= 9) return n + (isA ? 6 : 9);
    if (n <= 12) return n + (isA ? 9 : 12);
    throw new RangeError(`DUO slot ${slotId} is out of range (1-12 a/b)`);
  }

  if (n < 1 || n > 6) throw new RangeError(`classic slot ${slotId} is out of range (1-6 a/b)`);
  return n + (isA ? 0 : 6);
}

/**
 * The label-list slot tokens, and they are NOT hex.
 *
 * The device numbers 1..19 as decimal text and then continues with the literal
 * tokens '1a'..'1e' for 20..24. Reading them as hex gives 26..30, which is
 * wrong and lands inside no valid range - so it fails as "labels stop at 19"
 * rather than as a parse error.
 */
const LABEL_TOKENS = { '1a': 20, '1b': 21, '1c': 22, '1d': 23, '1e': 24 };

/** The pipe the firmware puts between the slot byte and the label. */
const PIPE = 0x7c;

/**
 * Slots above 9 are sent as `i + 6`.
 *
 * Which is also why the app's tokens look like "1a".."1e": slot 20 is byte 26,
 * and 26 in hex is 1a. They are not a lookup table at all - they are the hex of
 * a byte, reconstructed by a client that could not print it.
 */
const LABEL_CODE_OFFSET = 6;

function labelSlotNumber(token) {
  if (Object.prototype.hasOwnProperty.call(LABEL_TOKENS, token)) {
    return LABEL_TOKENS[token];
  }
  // Base 10 explicitly. parseInt stops at the first non-digit, so an unknown
  // letter-suffixed token would otherwise degrade silently ('2a' -> 2).
  if (!/^\d{1,2}$/.test(token)) return null;
  return parseInt(token, 10);
}

/**
 * Accumulates OKGETLABELS responses.
 *
 * Three things the original gets right and one it does not.
 *
 * The FIRST response is discarded. The device sends a priming message before
 * the list proper; consuming it as a label drops label #1 and shifts every
 * subsequent one. (OnlyKeyComm.js:478-481 does this by flipping `labels` from
 * "" to [], which is easy to read as an initialisation rather than a rule.)
 *
 * A response is only a label when the pipe is at index 2 - the token is
 * exactly two characters.
 *
 * The read ends at slot 12 or 24 by device type.
 *
 * What it does not do is time out. There is no deadline anywhere in the
 * original, so a lost terminal message hangs the caller forever with no error;
 * that is added here.
 */
class LabelReader {
  constructor(deviceType = DEVICE_TYPE.CLASSIC) {
    this.deviceType = deviceType;
    this.total = SLOT_COUNT[deviceType];
    this.labels = new Array(this.total).fill(null);
    this.primed = false;
    this.done = false;
    this.error = null;
    /*
     * Counted so a timeout can say something useful. Measured on the device: a
     * LOCKED OnlyKey answers OKGETLABELS with nothing at all - only its
     * once-a-second status broadcast keeps arriving. The firmware source has an
     * `else { hidprint("Error device locked"); }` for this case and it does not
     * reach the wire, so from the host "locked" and "not listening" look
     * identical unless the broadcasts are noticed.
     */
    this.statusReports = 0;
  }

  /**
   * Feed one vendor report.
   * @returns {'primed'|'stored'|'ignored'|'done'|'error'}
   */
  push(report) {
    if (this.done) return 'done';

    /*
     * PARSED FROM BYTES, not from a decoded string, and that distinction is
     * the whole of this method.
     *
     * get_slot_labels() sends 18 bytes per slot on the HID path
     * (okcore.cpp, the `output != 1` branch):
     *
     *     [0]    the slot, as a RAW BYTE - i for 1..9, i+6 for 10 and above
     *     [1]    0x7C, a pipe
     *     [2..]  the label text
     *
     * OnlyKey-App never sees that layout. Its readBytes() drops every
     * non-printable byte EXCEPT at index 0, where it substitutes two hex
     * characters - so by the time its parser runs, slot 20 (byte 0x1A) has
     * become the string "1a" and the pipe has moved to index 2. Its whole
     * parse, the "1a".."1e" table included, describes that reconstruction
     * rather than the wire.
     *
     * Porting the string form without the conversion that produces it is why
     * this timed out against a real device: the pipe was at index 1, no line
     * ever matched, and the read waited out its deadline while the firmware
     * sent all twelve labels correctly.
     */
    if (typeof report !== 'string') {
      const bytes = report;

      // An error arrives as text INSTEAD of the list, so it has no slot byte
      // and must be recognised before anything else - see the note below.
      const asText = okmsg.text(bytes);
      if (/^Error/i.test(asText)) {
        this.error = asText;
        this.done = true;
        return 'error';
      }

      if (/^(UNINITIALIZED|INITIALIZED|UNLOCKED)/.test(asText)) {
        this.statusReports += 1;
        return 'ignored';
      }

      if (bytes.length < 3 || bytes[1] !== PIPE) return 'ignored';

      const code = bytes[0];
      const slot = code <= 9 ? code : code - LABEL_CODE_OFFSET;
      if (slot < 1 || slot > this.total) return 'ignored';

      let label = '';
      for (let i = 2; i < bytes.length; i++) {
        const b = bytes[i];
        if (b === 0x00) break;
        if (b >= 0x20 && b <= 0x7e) label += String.fromCharCode(b);
      }

      this.labels[slot - 1] = label;
      if (slot >= this.total) this.done = true;
      return this.done ? 'done' : 'stored';
    }

    /*
     * The string form is still accepted, because that is what a caller has if
     * it took the app's route - and because the priming rule below only makes
     * sense there.
     */
    const text = report;

    /*
     * Errors are checked BEFORE the priming discard. The device's refusals
     * arrive INSTEAD of the list, not after it, so a refusal IS the first
     * response; discarding it as priming swallows the one message that
     * explains the failure and leaves the caller to time out.
     */
    if (/^Error/i.test(text)) {
      this.error = text;
      this.done = true;
      return 'error';
    }

    if (!this.primed) {
      this.primed = true;
      return 'primed';
    }

    if (text.indexOf('|') !== 2) return 'ignored';

    const slot = labelSlotNumber(text.slice(0, 2));
    if (slot === null || slot < 1 || slot > this.total) return 'ignored';

    this.labels[slot - 1] = text.slice(3);
    if (slot >= this.total) this.done = true;
    return this.done ? 'done' : 'stored';
  }

  /** Labels by slot number, with nulls for slots that never reported. */
  result() {
    return { labels: this.labels.slice(), complete: this.done, error: this.error };
  }
}

/**
 * Read every label.
 *
 * @param {object} transport  must provide on() and write()
 * @param {object} [opts] {deviceType, timeoutMs}
 */
async function readLabels(transport, opts = {}) {
  const { deviceType = DEVICE_TYPE.CLASSIC, timeoutMs = 15000 } = opts;
  const reader = new LabelReader(deviceType);

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      off();
      // Partial results rather than nothing: knowing which slots answered is
      // more useful than a bare timeout when a device is misbehaving.
      const partial = reader.result();
      /*
       * If the ONLY thing that arrived was the status broadcast, the device is
       * almost certainly locked - it answers this message with silence, not
       * with the refusal its source suggests. Saying so turns a bare timeout
       * into the actual diagnosis.
       */
      const looksLocked = reader.statusReports > 0 && !partial.labels.some(Boolean);
      reject(Object.assign(
        new Error(
          `label read timed out after ${timeoutMs}ms` +
          (looksLocked
            ? ` - the device sent only status broadcasts (${reader.statusReports}), so it is probably locked; call unlock() first`
            : ''),
        ),
        { partial, looksLocked },
      ));
    }, timeoutMs);

    const off = transport.on('report', (event) => {
      if (event.iface !== IFACE.VENDOR) return;
      const state = reader.push(event.data);
      if (state === 'done' || state === 'error') {
        clearTimeout(timer);
        off();
        const out = reader.result();
        if (out.error) reject(new Error(out.error));
        else resolve(out);
      }
    });

    transport.write(IFACE.VENDOR, okmsg.build({ msg: MSG.OKGETLABELS }))
      .catch((err) => { clearTimeout(timer); off(); reject(err); });
  });
}

module.exports = {
  DEVICE_TYPE,
  SLOT_COUNT,
  GLOBAL_SLOT,
  GLOBAL_SLOT_ID,
  LABEL_TOKENS,
  slotNumber,
  labelSlotNumber,
  LabelReader,
  readLabels,
};
