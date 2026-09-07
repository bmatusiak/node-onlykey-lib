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
    pinFailAt = -1,
    pinError = 'Error PIN is not between 7 - 10 digits',
    labels = null,
    labelSlots = 12,
    dropTerminal = false,
    ackDigits = true,
  } = opts;

  const pipe = fakePipe({ autoStart: true });
  let pinStep = 0;

  /** Slot number -> the two-character token the device prints. */
  function token(slot) {
    if (slot <= 19) return String(slot).padStart(2, '0');
    return `1${'abcde'[slot - 20]}`;
  }

  function handleVendor(frame) {
    const msg = frame[4];

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

    if (msg === MSG.OKGETLABELS) {
      /*
       * The priming response first. The device sends one before the list
       * proper; a reader that counts it as a label drops slot 1 and shifts
       * every one after it.
       */
      pipe.deliver(new Uint8Array(64));

      const last = dropTerminal ? labelSlots - 1 : labelSlots;
      for (let slot = 1; slot <= last; slot++) {
        const text = `${token(slot)}|${(labels && labels[slot - 1]) || `slot${slot}`}`;
        const bytes = new Uint8Array(64);
        for (let i = 0; i < text.length; i++) bytes[i] = text.charCodeAt(i) & 0xff;
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
    if (!ackDigits) return;
    /*
     * One acknowledgement per digit, exactly as the firmware prints them. The
     * trailing newline is not a digit.
     */
    const line = toLatin1(frame).replace(/\n$/, '');
    for (const digit of line) {
      pipe.deliverText(`password appended with ${digit}\n`);
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
    /** How many OKPIN messages have been received. */
    get pinStep() { return pinStep; },
  };

  return wrapped;
}

module.exports = { fakeFirmware, PIN_REPLIES };
