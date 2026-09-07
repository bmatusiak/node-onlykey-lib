/*
 * pin.js - PIN entry, for both device families.
 *
 * The classic flow is a bracketed state machine that exists nowhere as code:
 * it is spread across a wizard's step table (OnlyKeyWizard.js:164-233) as
 * enterFn/exitFn pairs, so reading any single function tells you nothing about
 * the sequence. It is written out here.
 *
 * The DUO flow is different in kind - one message carrying all the PINs at
 * once - and shares only the message id.
 */
'use strict';

const okmsg = require('../protocol/okmsg');
const { MSG, PIN_KIND } = require('../protocol/msg');

/**
 * Digits are BUTTON NUMBERS, not a keypad.
 *
 * The device has six touch buttons, so a PIN digit is 1-6. The firmware
 * rejects anything outside 7-10 digits with
 * "Error PIN is not between 7 - 10 digits".
 *
 * Verified empirically: provisioning a soft key with 1234561 succeeds and the
 * PIN survives a restart.
 */
const MIN_DIGITS = 7;
const MAX_DIGITS = 10;
const BUTTONS = 6;

/** The firmware's own strings, matched to drive the sequence. */
const PROMPTS = {
  enter: /Enter PIN/,
  storing: /Storing PIN/,
  confirm: /Confirm PIN/,
  matched: /Both PINs Match/,
};

const ERRORS = {
  tooShort: /Error PIN is not between 7 - 10 digits/,
  mismatch: /Error PINs Don't Match/,
};

/**
 * One print per DIGIT, so a first-match wait returns after the first one.
 * Counting them is the only way to know a whole burst was consumed.
 */
const DIGIT_ACK = /password appended with/gi;

/**
 * Validate a classic PIN.
 * @returns {string[]} problems, empty when acceptable
 */
function validatePin(pin, { confirm = null } = {}) {
  const problems = [];
  const text = String(pin || '');

  if (!text.length) problems.push('PIN is required.');
  else {
    if (text.length < MIN_DIGITS || text.length > MAX_DIGITS) {
      problems.push(`PIN must be ${MIN_DIGITS}-${MAX_DIGITS} digits.`);
    }
    if (!/^[1-6]*$/.test(text)) {
      problems.push(`PIN digits are button numbers, so each must be 1-${BUTTONS}.`);
    }
  }
  if (confirm !== null && text !== String(confirm)) {
    problems.push('PINs do not match.');
  }
  return problems;
}

/**
 * Validate the DUO PIN set.
 *
 * Policy from OnlyKeyWizard.js:1435-1449, with two corrections.
 *
 * The original enforces no MAXIMUM in JavaScript - the 16-character cap is
 * only an HTML maxlength attribute. Since the wire format gives each PIN a
 * 16-byte slot, a 17th character silently overflows into the next PIN. That is
 * enforced here.
 *
 * The original also checks `pin3.match(/\D/g)` without the `pin3 &&` guard its
 * neighbours have. Harmless on an empty string, but asymmetric.
 */
const DUO_PIN_BYTES = 16;

function validateDuoPins({ pin, pinConfirm, selfDestruct = '', selfDestructConfirm = '' }) {
  const primary = [];
  const sd = [];
  const p = String(pin || '');
  const s = String(selfDestruct || '');

  if (!p.length) primary.push('PIN is required.');
  else {
    if (p !== String(pinConfirm || '')) primary.push('PINs do not match.');
    if (/\D/.test(p)) primary.push('PIN must be numerals only.');
    if (p.length < MIN_DIGITS) primary.push(`PIN must be at least ${MIN_DIGITS} digits.`);
    if (p.length > DUO_PIN_BYTES) {
      primary.push(`PIN must be at most ${DUO_PIN_BYTES} digits.`);
    }
  }

  // The self-destruct PIN is optional; only validated when supplied.
  if (s.length) {
    if (s !== String(selfDestructConfirm || '')) sd.push('Self-destruct PINs do not match.');
    if (/\D/.test(s)) sd.push('Self-destruct PIN must be numerals only.');
    if (s.length < MIN_DIGITS) sd.push(`Self-destruct PIN must be at least ${MIN_DIGITS} digits.`);
    if (s.length > DUO_PIN_BYTES) {
      sd.push(`Self-destruct PIN must be at most ${DUO_PIN_BYTES} digits.`);
    }
    if (s === p) sd.push('Self-destruct PIN cannot match the primary PIN.');
  }

  return { ok: !primary.length && !sd.length, primary, selfDestruct: sd };
}

/**
 * Encode DUO PINs for the wire.
 *
 * Three things carry meaning and none of them are obvious:
 *
 *   Digits are ASCII: 48 + the digit, so '1' is 49.
 *
 *   A leading 0xFF means SET; its absence means VERIFY. Same message id either
 *   way, so this sentinel is the only thing distinguishing them - and it
 *   shifts every slot boundary by one.
 *
 *   Multiple PINs each occupy a fixed 16-byte slot. A SINGLE PIN - the unlock
 *   path - is sent at its natural length, unpadded. That asymmetry is the
 *   discriminator between unlocking and provisioning at the buffer level.
 *
 * An absent middle PIN is 16 zero bytes: the DUO has no second profile PIN,
 * and the original reaches that by passing an empty array through a
 * `typeof !== 'string'` check. Passed as '' here.
 */
function encodeDuoPins(pins, { set = false } = {}) {
  const list = pins.map((p) => (typeof p === 'string' ? p : ''));

  const bytes = list.length === 1
    ? new Uint8Array(list[0].length)
    : new Uint8Array(list.length * DUO_PIN_BYTES);

  list.forEach((p, i) => {
    const base = list.length === 1 ? 0 : i * DUO_PIN_BYTES;
    for (let j = 0; j < p.length; j++) {
      const digit = Number(p[j]);
      if (!Number.isInteger(digit)) {
        throw new Error(`DUO PIN must be numerals, got "${p[j]}"`);
      }
      bytes[base + j] = 48 + digit;
    }
  });

  if (!set) return bytes;
  const out = new Uint8Array(bytes.length + 1);
  out[0] = 0xff;
  out.set(bytes, 1);
  return out;
}

/** The DUO PIN message. Always OKPIN, in both directions. */
function duoPinMessage(pins, opts) {
  return okmsg.build({ msg: MSG.OKPIN, payload: encodeDuoPins(pins, opts) });
}

/**
 * The classic PIN bracket.
 *
 * The same message id drives every transition, and what it means depends on
 * where the state machine already is. The wizard tracks this with
 * `pendingMessages[msgId] = !pendingMessages[msgId]` - a toggle, where an odd
 * count means "entry is open". Sending one too many or too few silently
 * advances past a step rather than erroring, which is why the sequence has to
 * wait for each prompt rather than assume it.
 *
 * Six transitions per PIN:
 *
 *   OKPIN  -> "Enter PIN"        open entry
 *   digits -> one ack per digit
 *   OKPIN  -> "Storing PIN"      close entry
 *   OKPIN  -> "Confirm PIN"      open confirmation
 *   digits -> one ack per digit
 *   OKPIN  -> "Both PINs Match"  close confirmation
 *
 * Transcribed from onlykey-testing/lib/fixtures/states/initialized.js, which
 * drives it against both real and emulated devices.
 */
const PIN_SEQUENCE = [
  { send: true, expect: 'enter', label: 'armed' },
  { digits: true, label: 'entered' },
  { send: true, expect: 'storing', reject: ['tooShort'], label: 'stored' },
  { send: true, expect: 'confirm', label: 'confirming' },
  { digits: true, label: 're-entered' },
  { send: true, expect: 'matched', reject: ['mismatch', 'tooShort'], label: 'committed' },
];

/** The message for one step of a PIN kind. */
function pinMessage(kind = 'primary') {
  const msg = PIN_KIND[kind];
  if (msg === undefined) {
    throw new Error(`unknown PIN kind "${kind}"; expected ${Object.keys(PIN_KIND).join(', ')}`);
  }
  return okmsg.build({ msg });
}

/**
 * Where to return to when a PIN step fails.
 *
 * From goBackOnError (OnlyKeyWizard.js:1174-1189): always the ENTER step of
 * the failing pair, never the confirm step - re-confirming a PIN the device
 * has already rejected cannot succeed.
 */
const RECOVERY_STEP = {
  [MSG.OKPIN]: 'enterPrimary',
  [MSG.OKPINSEC]: 'enterSecondary',
  [MSG.OKPINSD]: 'enterSelfDestruct',
};

module.exports = {
  MIN_DIGITS,
  MAX_DIGITS,
  BUTTONS,
  DUO_PIN_BYTES,
  PROMPTS,
  ERRORS,
  DIGIT_ACK,
  PIN_SEQUENCE,
  RECOVERY_STEP,
  validatePin,
  validateDuoPins,
  encodeDuoPins,
  duoPinMessage,
  pinMessage,
};
