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
/**
 * The two HMAC-SHA1 key slots.
 *
 * okcore.h:215-216 - RESERVED_KEY_HMACSHA1_1 is 130 and _2 is 129. Named here
 * because writing either one has a side effect the device does not report: it
 * clears that slot's button-press requirement. See
 * onlykey-testing/FINDING-hmac-press-free-on-write.md.
 */
const HMAC_SLOTS = [129, 130];

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
 * How many profiles the device has, and what each one ADDS to a slot number.
 *
 * From the four branches gen_press() and gen_hold() share (OnlyKey.ino:998-1006
 * and :1013-1021). They are written as a chain of literal comparisons rather
 * than as arithmetic, so this is a table for the same reason: the firmware's
 * order is not the obvious one and a formula that happens to agree today would
 * not say where it came from.
 *
 *   if (profilemode || Duo_config[1] == 2)  slot = button + 12
 *   else if (Duo_config[1] == 1)            slot = button + 6
 *   else if (Duo_config[1] == 3)            slot = button + 18
 *   else                                    slot = button
 *
 * A CLASSIC reaches +12 through `profilemode`, which is STDPROFILE2 (1) or
 * NONENCRYPTEDPROFILE (2); STDPROFILE1 is 0 and therefore falsy, which is why
 * the first profile falls all the way through to the else. So a classic has
 * exactly two, at +0 and +12, and the travel edition shares the second one.
 */
const PROFILE_OFFSETS = {
  [DEVICE_TYPE.CLASSIC]: [0, 12],
  [DEVICE_TYPE.DUO]: [0, 6, 12, 18],
};

/** Buttons, and the gap a HOLD adds. Classic 6 and +6, DUO 3 and +3. */
const BUTTONS = { [DEVICE_TYPE.CLASSIC]: 6, [DEVICE_TYPE.DUO]: 3 };

/**
 * Which button types a slot, how long to hold it, and what it will type.
 *
 * The INVERSE of gen_press() and gen_hold(), which is where every number here
 * comes from. Both compute the slot the same way:
 *
 *     slot = button + profileOffset            gen_press, a tap
 *     slot = button + profileOffset + span     gen_hold, a hold
 *
 * ## THE PROFILE IS DEVICE STATE, AND NO MESSAGE SETS IT
 *
 * `profileOffset` is read from the device's own `profilemode` / `Duo_config[1]`
 * at the moment of the press. A classic reaches its second profile by being
 * unlocked with the SECOND PIN; a DUO cycles through its four by holding
 * button 3 for 72..179 iterations (OnlyKey.ino:886-901), which on a classic is
 * the gesture that locks the key instead. Neither is a command, and the
 * desktop app's profile switcher sends the device nothing at all - it is a
 * display filter over labels it already has.
 *
 * So a press reads the profile the device is ALREADY on, and nothing in the
 * reply says which one that was. `profile` is therefore an argument rather than
 * an assumption: a caller that does not know is about to read someone else's
 * credential and should find that out here.
 *
 * ## THE TWO MODELS PUT THE PROFILE IN DIFFERENT PLACES
 *
 * A DUO's slot ids span all 24 - '5a' IS profile 1, and slotNumber() already
 * folds the offset in. A classic's ids only span 12 and the profile is a
 * separate axis on top, so classic '3a' is physical slot 3 or 15 depending on
 * which PIN was used. Both are returned as `slot`, the number process_slot()
 * actually receives, because that is the one a caller can check a label against.
 *
 * @param {string|number} slotId  '3a', '12b'
 * @param {object} opts
 * @param {string} [opts.deviceType] 'classic' or 'duo'
 * @param {number} [opts.profile]    the profile the DEVICE is on, 0-based
 * @returns {{button: number, band: 'tap'|'hold', slot: number, profile: number}}
 */
function pressForSlot(slotId, { deviceType = DEVICE_TYPE.CLASSIC, profile = 0 } = {}) {
  if (slotId === GLOBAL_SLOT_ID) {
    throw new Error(
      'the global pseudo-slot holds preferences, not a credential; no button '
      + 'types it',
    );
  }

  const offsets = PROFILE_OFFSETS[deviceType];
  const buttons = BUTTONS[deviceType];
  if (!offsets) throw new Error(`unknown device type "${deviceType}"`);

  if (!Number.isInteger(profile) || profile < 0 || profile >= offsets.length) {
    throw new RangeError(
      `profile ${profile} is out of range - a ${deviceType} has `
      + `${offsets.length} (0-based)`,
    );
  }

  /* slotNumber() already knows both layouts, so the parsing is not repeated. */
  const numbered = slotNumber(slotId, deviceType);

  /*
   * On a DUO the id carries the profile, so the offset has to come back OFF
   * before the button is visible. On a classic it never went on.
   */
  const within = deviceType === DEVICE_TYPE.DUO
    ? numbered - offsets[profile]
    : numbered;

  if (within < 1 || within > buttons * 2) {
    throw new RangeError(
      `slot ${slotId} is slot ${numbered}, which is not in profile ${profile} `
      + `(slots ${offsets[profile] + 1}-${offsets[profile] + buttons * 2}). `
      + 'The profile cannot be changed by a message - see pressForSlot.',
    );
  }

  const isHold = within > buttons;
  return {
    button: isHold ? within - buttons : within,
    band: isHold ? 'hold' : 'tap',
    /* What process_slot() will be handed: the button, the profile, the hold. */
    slot: (isHold ? within - buttons : within) + offsets[profile] + (isHold ? buttons : 0),
    profile,
  };
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
  const { deviceType = DEVICE_TYPE.CLASSIC, timeoutMs = 15000, settleMs = 60 } = opts;
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
        if (out.error) { reject(new Error(out.error)); return; }
        /*
         * Resolve a beat AFTER the last label, not on it.
         *
         * The last report is not the end of the operation. get_slot_labels()
         * still owes a delay(20) and the walk back out of recvmsg()
         * (okcore.cpp:1578-1583) before the main loop services HID again, and a
         * caller that writes into that window gets NOTHING back - no
         * acknowledgement, no status broadcast, not even a debug line, because
         * the frame is never looked at. Measured at roughly 40% of writes issued
         * about 12ms after this resolved.
         *
         * setSlot() retries an unacknowledged frame and so recovers anyway, but
         * it recovers by waiting out a full timeout. Not creating the window is
         * cheaper than surviving it. See
         * ok-rn/FINDING-slot-write-after-a-label-read-is-lost.md.
         */
        if (settleMs > 0) setTimeout(() => resolve(out), settleMs);
        else resolve(out);
      }
    });

    transport.write(IFACE.VENDOR, okmsg.build({ msg: MSG.OKGETLABELS }))
      .catch((err) => { clearTimeout(timer); off(); reject(err); });
  });
}

/* ------------------------------------------------------------ key labels */

/*
 * KEY labels are a SECOND list, read with the same message and a different
 * slot byte, and nothing here could read it.
 *
 * OKGETLABELS with slot byte 'k' (0x6B, 107) runs get_key_labels() instead
 * of get_slot_labels() (okcore.cpp:387). python-onlykey has had it as
 * `getkeylabels` since the beginning (client.py:484-498); the desktop app
 * has no control for it, which is why a table copied from that app does not
 * mention it.
 *
 * The labels live at their own indices, contiguous across two key ranges:
 *
 *     25..28   RSA slots 1..4        (okcore.cpp:1427, `label[0] = i`)
 *     29..44   ECC slots 101..116    (okcore.cpp:1455)
 *
 * The firmware comment beside the second loop says "101-132" and the loop
 * runs 29..44, which is 101..116 - the reserved ECC slots above 116 have no
 * label of their own. Trust the loop.
 */
const KEY_LABEL_FIRST = 25;
const KEY_LABEL_LAST = 44;
const KEY_LABEL_COUNT = KEY_LABEL_LAST - KEY_LABEL_FIRST + 1;
const RSA_LABEL_LAST = 28;

/** Label index (25..44) -> key slot (1..4, 101..116), or null. */
function keySlotForLabelIndex(index) {
  if (index >= KEY_LABEL_FIRST && index <= RSA_LABEL_LAST) return index - 24;
  if (index > RSA_LABEL_LAST && index <= KEY_LABEL_LAST) return index + 72;
  return null;
}

/** Key slot (1..4, 101..116) -> label index (25..44), or null. */
function labelIndexForKeySlot(slot) {
  if (slot >= 1 && slot <= 4) return slot + 24;
  if (slot >= 101 && slot <= 116) return slot - 72;
  return null;
}

/**
 * Accumulates the KEY label list.
 *
 * Simpler than LabelReader because this list has no string form to support:
 * no client ever reconstructed it as hex the way OnlyKey-App does for slot
 * labels, so only the wire layout exists.
 *
 *     [0]    the LABEL INDEX as a raw byte, 25..44
 *     [1]    0x7C, a pipe
 *     [2..]  up to EElen_label (16) bytes of text, NUL-terminated
 *
 * The RSA rows are sent as 21 bytes and the ECC rows as 22
 * (okcore.cpp:1445 vs :1491). Nothing turns on the difference - both carry
 * the same two header bytes and the same 16 bytes of label - but it is the
 * sort of thing that looks like a bug when you meet it, so: it is not.
 */
class KeyLabelReader {
  constructor() {
    this.labels = new Map();
    this.done = false;
    this.error = null;
    this.statusReports = 0;
  }

  /** Feed one vendor report. @returns {'stored'|'ignored'|'done'|'error'} */
  push(report) {
    if (this.done) return 'done';
    const bytes = report instanceof Uint8Array ? report : Uint8Array.from(report || []);
    if (!bytes.length) return 'ignored';

    /* A refusal arrives INSTEAD of the list, so it is checked first. */
    const text = okmsg.text(bytes);
    if (/^Error/i.test(text)) {
      this.error = text.trim();
      this.done = true;
      return 'error';
    }
    if (/^(UNLOCKED|INITIALIZED|UNINITIALIZED)/.test(text)) {
      this.statusReports += 1;
      return 'ignored';
    }

    if (bytes.length < 3 || bytes[1] !== PIPE) return 'ignored';
    const slot = keySlotForLabelIndex(bytes[0]);
    if (slot === null) return 'ignored';

    let label = '';
    for (let i = 2; i < bytes.length && i < 2 + 16; i += 1) {
      const b = bytes[i];
      if (b === 0x00) break;
      if (b >= 0x20 && b <= 0x7e) label += String.fromCharCode(b);
    }
    this.labels.set(slot, label);
    if (bytes[0] >= KEY_LABEL_LAST) this.done = true;
    return this.done ? 'done' : 'stored';
  }

  /** One row per key slot, in firmware order, with '' for an unlabelled slot. */
  result() {
    const rows = [];
    for (let index = KEY_LABEL_FIRST; index <= KEY_LABEL_LAST; index += 1) {
      const slot = keySlotForLabelIndex(index);
      rows.push({
        slot,
        kind: slot <= 4 ? 'rsa' : 'ecc',
        label: this.labels.has(slot) ? this.labels.get(slot) : null,
      });
    }
    return { keys: rows, complete: this.done, error: this.error };
  }
}

/**
 * Read every KEY label.
 *
 * @param {object} transport  must provide on() and write()
 * @param {object} [opts] {timeoutMs, settleMs}
 */
async function readKeyLabels(transport, opts = {}) {
  const { timeoutMs = 15000, settleMs = 60 } = opts;
  const reader = new KeyLabelReader();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      off();
      const partial = reader.result();
      /*
       * A locked device answers this with silence, not with the refusal its
       * source suggests - the same measurement readLabels records. If the
       * only thing that arrived was the status broadcast, say so.
       */
      const looksLocked = reader.statusReports > 0 && !partial.keys.some((k) => k.label !== null);
      reject(new Error(
        looksLocked
          ? `no key labels within ${timeoutMs}ms; the device sent only its status broadcast, `
            + 'which is what a LOCKED device does with this message'
          : `no key labels within ${timeoutMs}ms (${partial.keys.filter((k) => k.label !== null).length} of ${KEY_LABEL_COUNT} arrived)`,
      ));
    }, timeoutMs);

    const off = transport.on('report', (event) => {
      if (event.iface !== IFACE.VENDOR) return;
      const state = reader.push(event.data);
      if (state !== 'done' && state !== 'error') return;
      clearTimeout(timer);
      off();
      const out = reader.result();
      if (out.error) { reject(new Error(out.error)); return; }
      /* The same settle readLabels takes, and for the same reason. */
      if (settleMs > 0) setTimeout(() => resolve(out), settleMs);
      else resolve(out);
    });

    transport.write(IFACE.VENDOR, okmsg.build({ msg: MSG.OKGETLABELS, slot: KEY_LABELS_SLOT_BYTE }))
      .catch((err) => { clearTimeout(timer); off(); reject(err); });
  });
}

/** The slot byte that asks for KEY labels rather than slot labels: 'k'. */
const KEY_LABELS_SLOT_BYTE = 0x6b;

module.exports = {
  DEVICE_TYPE,
  SLOT_COUNT,
  HMAC_SLOTS,
  GLOBAL_SLOT,
  GLOBAL_SLOT_ID,
  LABEL_TOKENS,
  slotNumber,
  pressForSlot,
  PROFILE_OFFSETS,
  pressForSlot,
  labelSlotNumber,
  LabelReader,
  readLabels,
  KEY_LABEL_FIRST,
  KEY_LABEL_LAST,
  KEY_LABELS_SLOT_BYTE,
  keySlotForLabelIndex,
  labelIndexForKeySlot,
  KeyLabelReader,
  readKeyLabels,
};
