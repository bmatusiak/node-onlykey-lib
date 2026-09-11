/*
 * A fake firmware, layered over the fake pipe.
 *
 * The device plugin is almost entirely sequencing - which message, in what
 * order, waiting for which printed line - so testing it needs something that
 * answers the way the firmware answers, not something that returns canned
 * bytes. In particular it has to reproduce the two behaviours that make the
 * PIN flow awkward:
 *
 *   The same message id means different things depending on how many times it
 *   has been sent. The firmware treats OKPIN as a toggle, so the bracket is
 *   positional and a host that sends one too many silently skips a step.
 *
 *   Digits are acknowledged INDIVIDUALLY, one printed line each. A host that
 *   waits for the first ack carries on while the rest are still arriving.
 *
 * Everything it prints is the firmware's own wording, matched by the regexes
 * in src/device/pin.js.
 */
'use strict';

const { fakePipe } = require('./fake-pipe');
const { IFACE } = require('../../src/transport/contract');
const { MSG } = require('../../src/protocol/msg');
const { toLatin1 } = require('../../src/bytes');

/** The classic bracket, in order. One entry per OKPIN the host sends. */
const PIN_REPLIES = ['Enter PIN\n', 'Storing PIN\n', 'Confirm PIN\n', 'Both PINs Match\n'];

/**
 * @param {object} [opts]
 *   pinFailAt   - index into PIN_REPLIES to answer with an error instead
 *   pinError    - the error text to use
 *   labels      - array of label strings, 1-based by slot
 *   labelSlots  - how many slots the device reports (12 classic, 24 duo)
 *   dropTerminal- never send the last label, to exercise the deadline
 */
function fakeFirmware(opts = {}) {
  const {
    slotError = null,
    slotSilent = false,
    /* The real firmware drops OKSETPRIV outside config mode, saying nothing. */
    setPrivSilent = false,
    pinFailAt = -1,
    pinError = 'Error PIN is not between 7 - 10 digits',
    labels = null,
    labelSlots = 12,
    dropTerminal = false,
    ackDigits = true,
    pin = null,          // when set, the device starts LOCKED and this unlocks it
    /*
     * The model letter is part of this, because HW_MODEL() appends one
     * unconditionally - 'c' Classic, 'p'/'n' DUO, 'o' Original. A fixture
     * without it is a device that has never existed, and detection reading
     * "unknown" from a fixture would hide a real failure to detect.
     */
    version = 'v3.0.4-prodc',
    /* slot -> public key bytes, for OKGETPUBKEY. Absent means an empty slot. */
    pubKeys = {},
  } = opts;

  const pipe = fakePipe({ autoStart: true });
  let pinStep = 0;

  /*
   * The lock state, modelled because it gates almost everything. A locked
   * device answers "Error device locked" rather than failing to answer, which
   * is a distinction a client has to get right.
   */
  let unlocked = pin === null;
  let entered = '';

  function handleVendor(frame) {
    const msg = frame[4];

    if (msg === MSG.OKCONNECT) {
      /*
       * OKCONNECT over the vendor interface is set_time(), and set_time replies
       * with the status string - a plaintext announcement, no key exchange
       * (okcore.cpp:1348-1375). That string is where the version, the model and
       * the build come from, so a fixture that stayed silent here left every
       * caller of connect() looking at a device that had never said what it is.
       */
      return pipe.deliver(reportText(
        unlocked ? `UNLOCKED${version}` : 'INITIALIZED',
      ));
    }

    if (msg === MSG.OKPIN) {
      const at = pinStep++;
      if (at === pinFailAt) return pipe.deliverText(`${pinError}\n`);
      const reply = PIN_REPLIES[at];
      if (reply) pipe.deliverText(reply);
      return undefined;
    }

    if (msg === MSG.OKSETSLOT || msg === MSG.OKWIPESLOT) {
      /*
       * Acknowledged as a VENDOR report, which is what hidprint() produces -
       * it calls send_transport_response, not the debug console. The wording
       * varies per field in the real firmware and one of them is misspelled,
       * so a host must not match the exact strings; only the "Error" prefix is
       * load-bearing.
       */
      if (slotSilent) return undefined;
      const text = slotError || (msg === MSG.OKSETSLOT
        ? 'Successfully set Label'
        : 'Successfully wiped slot');
      return pipe.deliver(reportText(text));
    }

    if (msg === MSG.OKSETPRIV) {
      /*
       * ecc_priv_flash acknowledges, and which sentence depends on the slot
       * (okcore.cpp:5399,5413). Modelled because setBackupPassphrase now WAITS
       * for it - the real firmware drops this frame entirely outside config
       * mode, so a client that did not wait reported success for a passphrase
       * the device never took.
       */
      if (setPrivSilent) return undefined;
      const slot = frame[5];
      return pipe.deliver(reportText(
        slot === 131
          ? 'Successfully set Backup Passphrase'
          : 'Successfully set ECC Key',
      ));
    }

    if (msg === MSG.OKGETPUBKEY) {
      /*
       * okcrypto_getpubkey: the key as RAW 64-byte reports with no length
       * and no terminator, an empty slot as an error sentence
       * (okcore.cpp:5245). `pubKeys` maps slot -> bytes; a slot not in it is
       * empty, which is how a caller asks whether a slot is free.
       */
      const slot = frame[5];
      const key = pubKeys[slot];
      if (!key) {
        return pipe.deliver(reportText(
          slot >= 1 && slot <= 4
            ? 'Error no RSA Private Key set in this slot'
            : 'Error no ECC Private Key set in this slot',
        ));
      }
      for (let at = 0; at < key.length; at += 64) {
        const report = new Uint8Array(64);
        report.set(key.subarray(at, Math.min(at + 64, key.length)));
        pipe.deliver(report);
      }
      return undefined;
    }

    if (msg === MSG.OKGETLABELS && !unlocked) {
      return pipe.deliver(reportText('Error device locked'));
    }

    if (msg === MSG.OKGETLABELS) {
      /*
       * The wire format, not the app's reconstruction of it.
       *
       * get_slot_labels() sends 18 bytes per slot on the HID path: the slot as
       * a RAW BYTE (i for 1..9, i+6 above that), then 0x7C, then the text.
       * There is no priming message and no terminator - it simply sends
       * maxslots of them and returns.
       */
      const last = dropTerminal ? labelSlots - 1 : labelSlots;
      for (let slot = 1; slot <= last; slot++) {
        const text = (labels && labels[slot - 1]) || `slot${slot}`;
        const bytes = new Uint8Array(18);
        bytes[0] = slot <= 9 ? slot : slot + 6;
        bytes[1] = 0x7c;
        for (let i = 0; i < text.length && 2 + i < 18; i++) {
          bytes[2 + i] = text.charCodeAt(i) & 0xff;
        }
        pipe.deliver(bytes);
      }
      return undefined;
    }

    return undefined;
  }

  /** A 64-byte vendor report carrying text, padded the way hidprint() pads. */
  function reportText(text) {
    const bytes = new Uint8Array(64);
    for (let i = 0; i < text.length && i < 64; i++) bytes[i] = text.charCodeAt(i) & 0xff;
    return bytes;
  }

  function handleSeremu(frame) {
    const line = toLatin1(frame).replace(/\n$/, '');

    /*
     * A hold - "6!" - is the device's clear gesture: the >= 72 duration band at
     * OnlyKey.ino:914 that calls password.reset(). Without it a failed
     * attempt's digits stay in the buffer and the next attempt appends to them.
     */
    if (line.indexOf('!') !== -1) {
      entered = '';
      return;
    }

    if (ackDigits) {
      // One acknowledgement per digit, exactly as the firmware prints them.
      for (const digit of line) {
        pipe.deliverText(`password appended with ${digit}\n`);
      }
    }

    /*
     * The firmware evaluates the hash after EVERY press, so unlocking needs no
     * submit and there is nothing to acknowledge until it matches. Announced on
     * both interfaces, as the firmware announces it.
     */
    if (!unlocked && pin !== null) {
      entered += line;
      /*
       * EXACT match on the whole accumulated buffer, not a suffix.
       *
       * profile1hashevaluate() hashes everything entered since the last reset
       * and compares, so a wrong attempt does not slide out of a window - it
       * stays, and the correct PIN typed after it hashes to something else
       * entirely. Modelling this as endsWith() made a poisoned buffer look
       * recoverable, which is precisely the confusion the real device causes.
       */
      if (entered === pin) {
        unlocked = true;
        entered = '';
        pipe.deliver(reportText(`UNLOCKED${version}`));
        pipe.deliverText('UNLOCKED\n');
      }
    }
  }

  const wrapped = {
    ...pipe,
    async write(iface, bytes) {
      const n = await pipe.write(iface, bytes);
      const frame = Uint8Array.from(bytes);
      /*
       * Answered on a later turn, like a device that has to come back round
       * its loop. Replying synchronously inside write() would let a host that
       * subscribes afterwards still see the reply, hiding an ordering bug that
       * hardware would expose.
       */
      await Promise.resolve();
      if (iface === IFACE.VENDOR) handleVendor(frame);
      else if (iface === IFACE.SEREMU) handleSeremu(frame);
      return n;
    },
    /**
     * Acknowledge presses the way the firmware does, one line per digit.
     *
     * For hosts that enter a PIN by pressing the device's BUTTONS rather than
     * by writing to the debug console. The firmware prints the same line
     * either way - it is acknowledging an append, not a channel - but this
     * fake only sees writes, and a button press is not one.
     */
    ackPresses(digits) {
      for (const digit of String(digits)) {
        pipe.deliverText(`password appended with ${digit}
`);
      }
    },

    /** How many OKPIN messages have been received. */
    get pinStep() { return pinStep; },
    get unlocked() { return unlocked; },
  };

  return wrapped;
}

module.exports = { fakeFirmware, PIN_REPLIES };
