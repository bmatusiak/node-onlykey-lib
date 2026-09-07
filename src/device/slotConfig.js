/*
 * slotConfig.js - writing the fields of a slot.
 *
 * From OnlyKeyWizard.js:906-1142 (`setSlot`), which is the densest piece of
 * DOM-and-protocol interleaving in OnlyKey-App and the one place its field
 * encodings are decided.
 *
 * REWRITTEN, NOT PORTED, and the reason matters. The original uses DOM
 * mutation as its loop cursor: setSlot() scans the field map, finds the first
 * "dirty" input, CLEARS that input, sends one message and returns - and the
 * send callback re-enters setSlot() from the top, which re-scans and finds the
 * next one. Termination is "a full scan found nothing dirty". The sequence
 * exists only as a side effect of emptying form fields, so there is nothing to
 * lift; what it *means* is an ordered list of writes, which is what this
 * module produces.
 *
 * The original also does not wait for the device. Its callback is the HID
 * write's callback plus a fixed 100 ms sleep - there is no listenforvalue on
 * this path, unlike setYubiAuth or setLockout - so a device-side `Error ...`
 * is discarded AFTER the field has been cleared from the form. The user is
 * shown success and the slot is wrong. Writes here are awaited properly.
 */
'use strict';

const okmsg = require('../protocol/okmsg');
const { MSG, FIELD } = require('../protocol/msg');
const { fromLatin1, fromHex } = require('../bytes');
const { base32ToHex, yubiCredential, TFA_TYPE } = require('./encoders');

/**
 * How a field's value reaches the wire.
 *
 * Three encodings, and the split between them is NOT tidy - it follows from
 * what the original happened to have in a DOM value at each point, and the
 * firmware parses each field the way it was historically sent. Changing one is
 * a silent protocol change, so they are named rather than inferred.
 *
 *   text   ASCII string. Label, URL, username, password, and the TFA type -
 *          which is a literal word, not a code.
 *   digit  A SINGLE ASCII DIGIT: '2' is 0x32, not 2. The original reads these
 *          from radio buttons and text inputs, so they were always strings.
 *          Sending the numeric value writes a control byte and the firmware
 *          reads a keypress that was never configured.
 *   byte   A raw byte. TYPESPEED alone, because it is the only field the
 *          original runs through parseInt before sending.
 *   hex    Bytes given as hex, already assembled by an encoder.
 */
const ENCODING = { TEXT: 'text', DIGIT: 'digit', BYTE: 'byte', HEX: 'hex' };

/**
 * Whether the value is trimmed before it is sent.
 *
 * Asymmetric on purpose (OnlyKeyWizard.js:991-997): URL, password and username
 * keep their surrounding whitespace because a leading or trailing space can be
 * significant in a credential; everything else is trimmed. Getting this
 * backwards silently changes a stored password.
 */
const KEEP_WHITESPACE = new Set(['url', 'username', 'password']);

/**
 * The fields of a slot, IN WIRE ORDER.
 *
 * The order is data, not decoration. The original's insertion order into
 * `fieldMap` is the order its scan finds them, and one dependency rides on it:
 * TFATYPE must be written before TFAUSERNAME, because the device needs to know
 * which kind of second factor it is being given before it is given the seed.
 * The original arranges this with a `currentSlot.mode` flag set on a previous
 * pass; here the order alone is sufficient, which is one fewer thing to keep
 * in step.
 */
const SLOT_FIELDS = [
  { name: 'label', field: FIELD.LABEL, encoding: ENCODING.TEXT, maxLength: 16 },
  { name: 'url', field: FIELD.URL, encoding: ENCODING.TEXT, maxLength: 56 },
  { name: 'nextKey4', field: FIELD.NEXTKEY4, encoding: ENCODING.DIGIT },
  { name: 'nextKey1', field: FIELD.NEXTKEY1, encoding: ENCODING.DIGIT },
  { name: 'delay1', field: FIELD.DELAY1, encoding: ENCODING.DIGIT },
  { name: 'username', field: FIELD.USERNAME, encoding: ENCODING.TEXT, maxLength: 56 },
  { name: 'nextKey2', field: FIELD.NEXTKEY2, encoding: ENCODING.DIGIT },
  { name: 'delay2', field: FIELD.DELAY2, encoding: ENCODING.DIGIT },
  { name: 'password', field: FIELD.PASSWORD, encoding: ENCODING.TEXT, maxLength: 56 },
  { name: 'nextKey5', field: FIELD.NEXTKEY5, encoding: ENCODING.DIGIT },
  { name: 'nextKey3', field: FIELD.NEXTKEY3, encoding: ENCODING.DIGIT },
  { name: 'delay3', field: FIELD.DELAY3, encoding: ENCODING.DIGIT },
  { name: 'tfaType', field: FIELD.TFATYPE, encoding: ENCODING.TEXT },
  { name: 'totpKey', field: FIELD.TFAUSERNAME, encoding: ENCODING.HEX },
  { name: 'yubikey', field: FIELD.YUBIAUTH, encoding: ENCODING.HEX },
  { name: 'typeSpeed', field: FIELD.TYPESPEED, encoding: ENCODING.BYTE },
];

const FIELD_BY_NAME = new Map(SLOT_FIELDS.map((f) => [f.name, f]));

/**
 * One report holds 64 bytes; header, message id, slot and field take 7.
 *
 * The original has no length check anywhere - sendMessage stops at the buffer
 * end - so an over-long value is silently cut and the slot holds a truncated
 * password that the user believes they set. The HTML maxlength attributes were
 * the only guard, and they never ran: the submit button is type="button" with
 * an onclick, so constraint validation never fires.
 */
const MAX_CONTENT = 57;

function encodeValue(spec, value) {
  switch (spec.encoding) {
    case ENCODING.TEXT: {
      const text = KEEP_WHITESPACE.has(spec.name) ? String(value) : String(value).trim();
      if (spec.maxLength && text.length > spec.maxLength) {
        throw new Error(
          `${spec.name} is ${text.length} characters, the device stores ${spec.maxLength}`,
        );
      }
      return fromLatin1(text);
    }

    case ENCODING.DIGIT: {
      /*
       * The ASCII digit, not the number. These come from radio values and
       * one-character text inputs in the original, so what reached the device
       * was always '0'-'9'. A numeric 2 would write 0x02.
       */
      const text = String(value).trim();
      if (!/^[0-9]$/.test(text)) {
        throw new Error(`${spec.name} must be a single digit 0-9, got "${text}"`);
      }
      return fromLatin1(text);
    }

    case ENCODING.BYTE: {
      /*
       * Guarded against NaN explicitly. `parseInt('')` is NaN, and the
       * original's bounds check is `contents < 0 || contents > 255`, which is
       * false for NaN on both sides - so an empty type-speed box wrote
       * `bytes[cursor++] = NaN`, which coerces to 0. Checking the type-speed
       * box without entering a value silently set the slowest possible speed.
       */
      const n = typeof value === 'number' ? value : parseInt(String(value).trim(), 10);
      if (!Number.isInteger(n) || n < 0 || n > 255) {
        throw new Error(`${spec.name} must be a byte 0-255, got ${JSON.stringify(value)}`);
      }
      return Uint8Array.of(n);
    }

    case ENCODING.HEX:
      return value instanceof Uint8Array ? value : fromHex(String(value));

    default:
      throw new Error(`unknown encoding for ${spec.name}`);
  }
}

/**
 * Turn a slot description into the ordered writes it becomes.
 *
 * Pure: it sends nothing and touches no device, so the whole encoding table
 * can be tested without one. `writeSlot` below is the part that needs a
 * transport.
 *
 * @param {object} values  keyed by the names in SLOT_FIELDS
 * @param {number} slot    the device's slot number
 * @returns {Array<{name, field, data}>}
 */
function planSlotWrites(values, slot) {
  const writes = [];

  for (const spec of SLOT_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(values, spec.name)) continue;
    const raw = values[spec.name];
    /*
     * Absent and empty are different. Omitting a key leaves the field alone;
     * passing '' is a request to write an empty value, which is how a field is
     * blanked without wiping the whole slot.
     */
    if (raw === undefined || raw === null) continue;

    const data = encodeValue(spec, raw);
    if (data.length > MAX_CONTENT) {
      throw new Error(
        `${spec.name} needs ${data.length} bytes, one report holds ${MAX_CONTENT}`,
      );
    }

    writes.push({
      name: spec.name,
      field: spec.field,
      data,
      frame: okmsg.build({ msg: MSG.OKSETSLOT, slot, field: spec.field, payload: data }),
    });
  }

  return writes;
}

/**
 * Build the TOTP field pair from a base32 seed.
 *
 * Returns both fields, because writing the seed without the type leaves the
 * device with a secret and no idea what to do with it. The order in
 * SLOT_FIELDS puts the type first.
 */
function totpFields(base32Seed) {
  return {
    tfaType: TFA_TYPE.GOOGLE_AUTH,
    totpKey: fromHex(base32ToHex(String(base32Seed).replace(/\s/g, ''))),
  };
}

/** Build the Yubikey field pair. Same reasoning as totpFields. */
function yubikeyFields(credential) {
  return {
    tfaType: TFA_TYPE.YUBIKEY,
    yubikey: yubiCredential(credential),
  };
}

/** Wipe one field, or the whole slot when no field is named. */
function wipeMessage(slot, fieldName = null) {
  if (fieldName === null) {
    // No field byte at all - that is what makes it a whole-slot wipe.
    return okmsg.build({ msg: MSG.OKWIPESLOT, slot });
  }
  const spec = FIELD_BY_NAME.get(fieldName);
  if (!spec) throw new Error(`unknown slot field "${fieldName}"`);
  return okmsg.build({ msg: MSG.OKWIPESLOT, slot, field: spec.field });
}

module.exports = {
  ENCODING,
  SLOT_FIELDS,
  FIELD_BY_NAME,
  KEEP_WHITESPACE,
  MAX_CONTENT,
  encodeValue,
  planSlotWrites,
  totpFields,
  yubikeyFields,
  wipeMessage,
};
