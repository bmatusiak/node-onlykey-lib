/*
 * device - everything above the wire and below a GUI.
 *
 * This is the plugin plugins/session has been authorising since it was written
 * (`setup.allowed = [['device'], ['okcrypto']]`) and which did not exist: the
 * only implementation was a stub inside test/app.test.js. So it is also the
 * first real consumer of the session key.
 *
 * It owns no protocol knowledge of its own. Everything here is sequencing -
 * which message, in what order, waiting for what - over the pure modules in
 * src/device/. That split is deliberate: the tables and encoders are testable
 * without a device, and this file is testable against a fake transport.
 */
'use strict';

const pin = require('../../src/device/pin');
const slots = require('../../src/device/slots');
const slotConfig = require('../../src/device/slotConfig');
const okmsg = require('../../src/protocol/okmsg');
const { DeviceConsole, pressLine } = require('../../src/device/console');
const { IFACE } = require('../../src/transport/contract');

function setup(imports, register) {
  const { app, transport, session } = imports;
  const EventEmitter = app.EventEmitter;

  const events = new EventEmitter();
  const console_ = new DeviceConsole().attach(transport);

  let deviceType = slots.DEVICE_TYPE.CLASSIC;

  /** Progress is emitted, not logged: a GUI needs to render these steps. */
  function progress(step, detail) {
    events.emit('progress', { step, ...detail });
  }

  /**
   * One classic PIN bracket.
   *
   * Driven from pin.PIN_SEQUENCE rather than written out, because the six
   * transitions all send the SAME message id and differ only in what they wait
   * for. Unrolled, that reads as six identical writes and invites someone to
   * "simplify" two of them away - which does not error, it silently advances
   * past a step, because the firmware treats the id as a toggle.
   *
   * @param {string} kind  primary | secondary | selfDestruct
   * @param {string} digits
   */
  async function runPinSequence(kind, digits, { timeoutMs = 10000 } = {}) {
    const problems = pin.validatePin(digits);
    if (problems.length) throw new Error(problems.join(' '));

    const message = pin.pinMessage(kind);

    for (const step of pin.PIN_SEQUENCE) {
      /*
       * Cleared before every step. The firmware prints the same words at more
       * than one point in the bracket - "Enter PIN" appears for the primary
       * and again for the confirmation - so stale text would satisfy the next
       * wait immediately and the host would run ahead of the device.
       */
      console_.clear();

      if (step.send) {
        await transport.write(IFACE.VENDOR, message);
        await console_.waitFor(pin.PROMPTS[step.expect], {
          reject: (step.reject || []).map((name) => pin.ERRORS[name]),
          timeoutMs,
        });
      } else if (step.digits) {
        await pressLine(transport, digits);
        /*
         * Counted, not first-match. The firmware acknowledges each digit
         * separately, so returning on the first ack leaves the rest of the
         * burst in flight - the next message lands mid-burst and the device
         * sees a short PIN, which surfaces later as a mismatch between two
         * PINs that were typed identically.
         */
        await console_.waitForCount(pin.DIGIT_ACK, digits.length, { timeoutMs });
      }

      progress(step.label, { kind });
    }
  }

  const device = {
    /* ---- identity ------------------------------------------------------ */

    get deviceType() { return deviceType; },
    setDeviceType(next) {
      if (!Object.values(slots.DEVICE_TYPE).includes(next)) {
        throw new Error(`unknown device type "${next}"`);
      }
      deviceType = next;
      return deviceType;
    },

    /** The raw console, for callers that want to watch the device talk. */
    console: console_,

    /* ---- session ------------------------------------------------------- */

    async connect(opts) {
      const result = await session.connect(opts);
      events.emit('connected', result);
      return result;
    },
    get connected() { return session.established; },
    get status() { return session.status; },

    /* ---- PIN ----------------------------------------------------------- */

    /**
     * Set a PIN on a classic device.
     *
     * Does NOT restart afterwards. `initialized` is recomputed from flash only
     * in setup(), so the device keeps reporting its old state until it boots
     * again - and the firmware resets before its DEBUG buffer is flushed, so
     * the acknowledgement of a restart is the next boot, never a message.
     * Whoever owns the process decides when to pay that.
     */
    setPin(digits, { kind = 'primary', timeoutMs } = {}) {
      return runPinSequence(kind, digits, { timeoutMs });
    },

    /** Validate without sending, so a GUI can gate its own button. */
    validatePin: pin.validatePin,
    validateDuoPins: pin.validateDuoPins,

    /**
     * Set or verify the DUO PINs.
     *
     * A different mechanism, not a different encoding: the classic device
     * captures digits from its own buttons and the host only brackets that,
     * while DUO carries the PINs in the message body. They share a message id
     * and nothing else.
     */
    async duoPin(pins, { set = false, timeoutMs = 6000 } = {}) {
      const reply = await transport.request({
        iface: IFACE.VENDOR,
        data: pin.duoPinMessage(pins, { set }),
        timeoutMs,
      });
      return reply;
    },

    /** Send button presses directly - the manual half of the PIN bracket. */
    press(digits) { return pressLine(transport, digits); },

    /* ---- slots --------------------------------------------------------- */

    readLabels(opts = {}) {
      return slots.readLabels(transport, { deviceType, ...opts });
    },

    slotNumber(slotId) { return slots.slotNumber(slotId, deviceType); },

    /**
     * Write fields to a slot, one at a time, WAITING for each.
     *
     * The original does not wait. Its callback is the HID write's callback
     * plus a fixed 100 ms sleep - there is no listenforvalue on this path,
     * unlike setYubiAuth or setLockout - so a device-side error is discarded
     * after the form field has already been cleared, and the user is shown
     * success over a slot that is wrong.
     *
     * The firmware does acknowledge every field: okcore.cpp's SETSLOT handler
     * hidprint()s "Successfully set Label", "Successfully set URL" and so on
     * through send_transport_response, which is a vendor report. The wording
     * varies per field and contains at least one typo ("Additonal"), so
     * matching the exact strings would be brittle; the test is the one the app
     * itself uses in pollForInput - a message beginning "Error" is an error,
     * anything else is the acknowledgement.
     *
     * The whole plan is built BEFORE the first write. An invalid tenth field
     * therefore fails with nothing sent, rather than leaving nine fields
     * written and the slot half configured.
     */
    async setSlot(slotId, values, { timeoutMs = 3000 } = {}) {
      const slot = typeof slotId === 'number' ? slotId : slots.slotNumber(slotId, deviceType);
      const writes = slotConfig.planSlotWrites(values, slot);
      const applied = [];

      for (const write of writes) {
        const reply = await transport.request({
          iface: IFACE.VENDOR,
          data: write.frame,
          timeoutMs,
        });
        const text = okmsg.text(reply);
        if (/^Error/i.test(text)) {
          throw new Error(`${write.name}: ${text}`);
        }
        applied.push({ name: write.name, response: text });
        progress('field', { slot, field: write.name, response: text });
      }

      return applied;
    },

    /** Wipe one field, or the whole slot when no field is named. */
    async wipeSlot(slotId, field = null, { timeoutMs = 3000 } = {}) {
      const slot = typeof slotId === 'number' ? slotId : slots.slotNumber(slotId, deviceType);
      const reply = await transport.request({
        iface: IFACE.VENDOR,
        data: slotConfig.wipeMessage(slot, field),
        timeoutMs,
      });
      const text = okmsg.text(reply);
      if (/^Error/i.test(text)) throw new Error(text);
      return text;
    },

    /** Build the field pair for a second factor, without sending it. */
    totpFields: slotConfig.totpFields,
    yubikeyFields: slotConfig.yubikeyFields,

    /* ---- events -------------------------------------------------------- */

    on(event, listener) {
      events.on(event, listener);
      return () => events.removeListener(event, listener);
    },
  };

  register(null, {
    device,
    onDestroy: () => {
      console_.detach();
      events.removeAllListeners();
    },
  });
}

setup.consumes = ['app', 'transport', 'session'];
setup.provides = ['device'];

module.exports = setup;
