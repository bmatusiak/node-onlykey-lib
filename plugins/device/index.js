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
const chunker = require('../../src/device/chunker');
const parsers = require('../../src/device/parsers');
const deviceKeys = require('../../src/device/keys');
const keystrokes = require('../../src/device/keystrokes');
const presses = require('../../src/device/press');
const encoders = require('../../src/device/encoders');
const { MSG, FIELD } = require('../../src/protocol/msg');
const okmsg = require('../../src/protocol/okmsg');
const { DeviceConsole, pressLine } = require('../../src/device/console');

/**
 * A byte the console parser recognises as neither a press nor a command.
 *
 * `dbg_commit_line` sends 1-6 to the press parser and everything else to the
 * command parser, which knows 0, 8 and 9. Z reaches the command parser, is not
 * one of those, and so produces the line echo and no other effect at all.
 */
const CONSOLE_PROBE_BYTE = 'Z';

/** The echo carries the byte as a NUMBER, so Z arrives as 90. */
const CONSOLE_PROBE_ECHO = new RegExp(
  `I received from DEBUG: *${CONSOLE_PROBE_BYTE.charCodeAt(0)}`);
const { IFACE } = require('../../src/transport/contract');
const version = require('../../src/device/version');

function setup(imports, register) {
  const { app, transport, session } = imports;
  const EventEmitter = app.EventEmitter;

  const events = new EventEmitter();
  const console_ = new DeviceConsole().attach(transport);

  /*
   * What the DEVICE said it is, and what a caller INSISTED it is.
   *
   * Kept apart because they answer different questions. `detected` is set from
   * any status line that names a model - the once-a-second broadcast does, and
   * so does connect(). `override` is set only by setDeviceType(), and wins,
   * because a caller who says "this is a DUO" is usually working around
   * something and should not be argued with.
   *
   * This used to be one variable initialised to CLASSIC and never assigned by
   * anything but setDeviceType(), which ok-rn never called. Against a DUO that
   * meant setSlot('7a') wrote the wrong slot and readLabels stopped at 12 of
   * 24 - no error, just half the device missing.
   */
  let detectedType = null;
  let overrideType = null;

  /** What to use right now: what a caller insisted on, else what was detected. */
  function currentType() {
    return overrideType || detectedType || slots.DEVICE_TYPE.CLASSIC;
  }

  /**
   * Learn the model from a status line, if it names one.
   *
   * Called for every status broadcast, so a LOCKED device is identified too:
   * INITIALIZED-D carries no version but does say DUO, and a locked DUO is
   * exactly the device a caller is about to enumerate 24 slots on.
   *
   * Only a positive identification is recorded. An unknown model leaves what
   * was already learned alone rather than resetting it to a guess.
   */
  function learnModel(status) {
    const model = version.parseStatus(status).model;
    if (model === version.MODEL.DUO) detectedType = slots.DEVICE_TYPE.DUO;
    else if (model === version.MODEL.CLASSIC) detectedType = slots.DEVICE_TYPE.CLASSIC;
    else if (model === version.MODEL.ORIGINAL) {
      /*
       * An Original has the Classic slot layout. It is recorded as CLASSIC for
       * that reason and not because the two are the same device - the poll
       * delays differ, and those come from capabilities(), not from here.
       */
      detectedType = slots.DEVICE_TYPE.CLASSIC;
    }
  }

  /**
   * Is this report the device talking to itself rather than answering us?
   *
   * A locked device runs Task taskInitialized(1000, sendInitialized)
   * (OnlyKey.ino:213) and broadcasts its status once a second until it
   * unlocks. Any request() that takes the next report therefore has a good
   * chance of taking that instead of its answer - measured on the device, a
   * slot write came back acknowledged "INITIALIZED".
   */
  function isStatusBroadcast(report) {
    /*
     * The specific lock states, NOT "parseState returned something" - it always
     * does, falling back to {state:'unknown'}, so a truthiness test here
     * rejected every real answer including "Successfully set Label".
     *
     * An ERROR is deliberately not a broadcast. "Error device locked" is a
     * genuine answer to a slot write, and filtering it out would turn a device
     * that refused clearly into one that timed out silently - the same bug the
     * label reader had.
     */
    const { state, raw } = okmsg.parseState(report);
    const isBroadcast =
      state === 'locked' || state === 'unlocked' || state === 'uninitialized';
    // A broadcast is the device naming itself; that is worth keeping, not just
    // filtering out.
    if (isBroadcast) learnModel(raw);
    return isBroadcast;
  }

  /**
   * The shape of an answer to a slot write.
   *
   * okcore.cpp's SETSLOT handler hidprint()s "Successfully set Label" and its
   * siblings, and refuses with "Error ...". Anything else on the bus at that
   * moment - a status broadcast, a straggling label report - is traffic, not a
   * reply.
   */
  function isSlotAcknowledgement(report) {
    return /^(Success|Error)/i.test(okmsg.text(report));
  }

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
  /**
   * @param {function|null} enterDigits how the digits reach the device. Null
   *   uses the DEBUG console, which is the only option on a wire-attached key
   *   and is DEBUG-BUILD-ONLY (FINDING-provisioning-needs-a-debug-build.md).
   *   A host that can press the device's buttons - an emulator, a soft key -
   *   passes a function that does, which is what the hardware flow actually
   *   is: the firmware appends whatever is pressed while entry is open, and
   *   pressLine only ever stood in for a finger.
   */
  async function runPinSequence(kind, digits, { timeoutMs = 10000, enterDigits = null } = {}) {
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
        if (enterDigits) await enterDigits(digits);
        else await pressLine(transport, digits);
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

  /**
   * One field, resent if the device says nothing at all.
   *
   * A SILENT device is not a failed write, it is an UNKNOWN one, and the two
   * need different handling. An "Error ..." reply is a definitive answer and
   * is returned untouched - resending would be arguing with the device. A
   * timeout means the frame may never have been looked at, and the only way
   * to find out is to ask again.
   *
   * Measured, on device: writing a field within about 20 ms of a label read
   * completing fails this way roughly 40% of the time. readLabels() resolves
   * the moment the last label arrives, but get_slot_labels() has not returned
   * yet - it still owes a delay(20) and the walk back out of recvmsg()
   * (okcore.cpp:1578-1583) - so the frame sits in the queue unlooked-at, and
   * nothing comes back on any interface, not even the status broadcast. See
   * ok-rn/FINDING-slot-write-after-a-label-read-is-lost.md.
   *
   * Resending is safe for every field this sends: each frame is a complete
   * self-contained store of one value, so writing it twice leaves the slot
   * exactly as writing it once would. That is what makes a retry the right
   * answer here rather than a sleep before the write - a sleep only fixes
   * the trigger someone happened to notice.
   */
  async function sendField(write, { timeoutMs = 3000, retries = 2 } = {}) {
    let last = null;
    for (let attempt = 1; attempt <= retries + 1; attempt++) {
      try {
        const reply = await transport.request({
          iface: IFACE.VENDOR,
          data: write.frame,
          timeoutMs,
          /*
           * Positively matched, not merely filtered.
           *
           * The bus carries the once-a-second status broadcast AND, right
           * after a write, label reports left over from a list the device is
           * still sending. Excluding only the broadcast let one of those
           * through: a slot write came back acknowledged with the bytes
           * 01 7C 'e2e4344', which is slot 1's label, not an acknowledgement.
           *
           * The firmware's acknowledgements are all "Successfully ..." or
           * "Error ...", so that is what is waited for.
           */
          match: isSlotAcknowledgement,
        });
        return { text: okmsg.text(reply), attempts: attempt };
      } catch (err) {
        last = err;
        if (attempt <= retries) {
          progress('retry', { field: write.name, attempt, reason: err.message });
        }
      }
    }
    throw new Error(
      `${write.name}: no acknowledgement after ${retries + 1} attempts - ${last.message}`,
    );
  }

/*
 * The whole Preferences and Advanced surface, as data.
 *
 * Every one of these is the SAME operation: OKSETSLOT on the global slot
 * ('XX', slot 0) carrying one field id and one byte. The desktop app spells
 * that out as twelve near-identical methods (OnlyKeyDevice.ts:1089-1160);
 * as a table it is one method, and the app can render the settings screen
 * from it rather than hard-coding the same list a third time.
 *
 * `max` is the firmware's limit where one is known, so a bad value is
 * refused here instead of being written and silently clamped.
 */
/**
 * Vendor messages that mean backup() has given up.
 *
 * Deliberately a short allowlist. The firmware prints an error for every empty
 * slot it walks, so "an error arrived" says nothing; these are the ones after
 * which no backup is coming (okcore.cpp:6802).
 */
const BACKUP_REFUSALS = [
  /no backup key set/i,
];

/*
 * The whole Preferences and Advanced surface, as data.
 *
 * Every one of these is the SAME operation: OKSETSLOT on the global slot
 * ('XX', slot 0) carrying one field id and one byte. The desktop app spells
 * that out as twelve near-identical methods (OnlyKeyDevice.ts:1089-1160); as a
 * table it is one method, and a settings screen can render itself from it
 * rather than hard-coding the same list a third time.
 *
 * `requires` IS NOT DECORATION. set_slot gates these differently field by
 * field, and the difference is invisible until a write is silently refused:
 *
 *   always     accepted whenever the device is unlocked and initialized
 *   configMode needs config mode, else "Error not in config mode"
 *              (okcore.cpp cases 21, 22, 26, 27)
 *   firstUse   only on a device that has not completed setup - !initcheck -
 *              and refused for ever after (case 23)
 *
 * Two are worse than either: WIPEMODE and BACKUPKEYMODE take their DANGEROUS
 * value in config mode and their safe value only on first use, so which rule
 * applies depends on what you are setting. `requires` names the stricter of
 * the two and `note` says so.
 */
const PREFERENCES = {
  lockout:              { field: FIELD.LOCKOUT, max: 255, unit: 'minutes', label: 'Idle lockout', requires: 'always' },
  typeSpeed:            { field: FIELD.TYPESPEED, max: 10, label: 'Typing speed', requires: 'always' },
  keyboardLayout:       { field: FIELD.KBDLAYOUT, max: 255, label: 'Keyboard layout', requires: 'always' },
  ledBrightness:        { field: FIELD.LEDBRIGHTNESS, max: 255, label: 'LED brightness', requires: 'always' },
  lockButton:           { field: FIELD.LOCKBUTTON, max: 6, label: 'Lock button', requires: 'always' },

  /*
   * A BITMASK, not a flag. It was capped at 1 here, which made the one value
   * that matters unreachable: the firmware tests BIT 3 of this byte
   * (ok_extension.cpp:262, `is_bit_set(mode, 3)` = value 8) before it will
   * derive a per-site key without a touch, and setPreference refuses
   * anything above `max`. Its own setter takes the raw byte with no range
   * check at all (okcore.cpp:2021).
   *
   * The two bits mean different things on different paths, which is why this
   * cannot be presented as one on/off:
   *
   *   bit 0 (1)  raw-HID derives raise a three-button challenge
   *              (okcore.cpp:7571 sets CRYPTO_AUTH = 3)
   *   bit 3 (8)  FIDO2 derives are allowed WITHOUT a touch; clear, they are
   *              refused as CTAP2_ERR_EXTENSION_NOT_SUPPORTED, which names
   *              the wrong cause entirely
   *              (FINDING-a-preference-bit-masquerades-as-an-unsupported-feature.md)
   */
  derivedChallengeMode: {
    field: FIELD.derivedchallengeMode,
    max: 255,
    label: 'Derived key challenge',
    requires: 'configMode',
    bits: {
      0: 'Three-button challenge on raw-HID derives',
      3: 'Allow per-site derived keys without a touch',
    },
    note: 'A bitmask. Bit 3 (value 8) is what lets a derived key be produced without pressing a button; without it the device answers "extension not supported", which is not what it means.',
  },
  storedChallengeMode:  { field: FIELD.storedchallengeMode, max: 1, label: 'Stored key challenge', requires: 'configMode' },
  hmacChallengeMode:    { field: FIELD.hmacchallengeMode, max: 1, label: 'HMAC challenge', requires: 'configMode' },
  modKeyMode:           { field: FIELD.modkeyMode, max: 1, label: 'Sysadmin mode', requires: 'configMode' },

  wipeMode: {
    field: FIELD.WIPEMODE, max: 2, label: 'Wipe mode', requires: 'configMode',
    note: 'Full wipe (2) needs config mode; the other values can only be set '
      + 'before setup is finished.',
  },
  backupKeyMode: {
    field: FIELD.BACKUPKEYMODE, max: 1, label: 'Backup key mode', requires: 'configMode',
    note: 'Locking it (1) needs config mode, and cannot be undone afterwards.',
  },

  secProfileMode: {
    field: FIELD.SECPROFILEMODE, max: 2, label: 'Second profile mode', requires: 'firstUse',
    note: 'Only settable before setup is finished. A provisioned key refuses it.',
  },
};

  const device = {
    /* ---- identity ------------------------------------------------------ */

    get deviceType() { return currentType(); },

    /** What was learned from the device itself, or null if it has not said. */
    get detectedType() { return detectedType; },

    /**
     * Insist on a device type, overriding detection.
     *
     * Pass null to drop the override and go back to what the device says.
     */
    setDeviceType(next) {
      if (next === null) {
        overrideType = null;
        return currentType();
      }
      if (!Object.values(slots.DEVICE_TYPE).includes(next)) {
        throw new Error(`unknown device type "${next}"`);
      }
      overrideType = next;
      return overrideType;
    },

    /**
     * What the device said it is: state, version, model, build.
     *
     * Null until connect() has run. `capabilities` is the one to read for a
     * decision - see src/device/version.js.
     */
    get identity() { return session.identity; },

    /** What this device can be asked to do. Null until connect() has run. */
    get capabilities() { return session.capabilities; },

    /** The raw console, for callers that want to watch the device talk. */
    console: console_,

    /* ---- session ------------------------------------------------------- */

    async connect(opts) {
      const result = await session.connect(opts);
      /*
       * The connect reply does not pass through isStatusBroadcast - it is an
       * ANSWER, not a broadcast, so the filter that watches for the device
       * naming itself never sees the one reply guaranteed to carry a version.
       */
      learnModel(result.status || '');
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
    setPin(digits, { kind = 'primary', timeoutMs, enterDigits } = {}) {
      return runPinSequence(kind, digits, { timeoutMs, enterDigits });
    },

    /**
     * Unlock a provisioned device by entering its PIN.
     *
     * Different from setPin in kind, not just in sequence. setPin brackets the
     * device's own capture mode with four OKPIN messages; unlocking sends no
     * message at all. The digits go in as button presses and the firmware
     * evaluates the hash after EVERY one (OnlyKey.ino:697) - there is no
     * submit, and nothing to acknowledge until it either matches or does not.
     *
     * This is the gate on almost everything. okcore.cpp guards its vendor
     * dispatch on `unlocked == true`, so a locked device answers
     * "Error device locked" to a label read; CTAPHID packets are dropped with
     * no error frame at all (okcore.cpp:639,651); and U2Finit() only runs here
     * (OnlyKey.ino:716), so FIDO does not exist until this succeeds.
     *
     * Success is announced twice - hidprint(HW_MODEL(UNLOCKED)) on the vendor
     * interface and "UNLOCKED" on the debug console - so either arriving is
     * enough. Both are watched because the SEREMU one is DEBUG-build-only.
     */
    async unlock(digits, { timeoutMs = 15000, enterDigits } = {}) {
      const problems = pin.validatePin(digits);
      if (problems.length) throw new Error(problems.join(' '));

      /*
       * HOW the digits are entered is the caller's business, not this
       * function's.
       *
       * The default writes them to the debug console, which is a DEBUG-build
       * feature: the whole simulated-press command interface sits inside
       * `#ifdef DEBUG` in okcore.cpp, so on a production build the firmware
       * never reads what pressLine writes. It does not refuse - it says
       * nothing, and this call times out after fifteen seconds with a message
       * about the PIN possibly being wrong. The PIN was fine; there was no
       * listener.
       *
       * So a host that can press buttons passes `enterDigits`, and gets a path
       * that works on either build. runPinSequence has accepted this hook since
       * it was written; unlock() not taking it is why ok-rn's PIN screen
       * reimplemented the flow instead of using this.
       *
       * When the device is known to be a production build and no hook was
       * given, say so immediately rather than waiting out the timeout - a
       * message naming the real cause is worth more than fifteen seconds.
       */
      const caps = session.capabilities;
      if (!enterDigits && caps && caps.debugConsole === false
        && currentType() !== slots.DEVICE_TYPE.DUO) {
        throw new Error(
          'this is a production firmware build, which has no debug console to ' +
          'accept typed digits - pass enterDigits to press the buttons instead',
        );
      }
      /*
       * A DUO DOES NOT UNLOCK BY PRESSING ANYTHING.
       *
       * Its PIN travels in the message body - one OKPIN carrying the digits as
       * ASCII, at their natural length, which is what distinguishes an unlock
       * from a provisioning write (src/device/pin.js, encodeDuoPins). The
       * classic device captures digits from its own buttons and the host only
       * brackets that; these share a message id and nothing else.
       *
       * Handled here rather than left to callers because the caller cannot
       * reasonably know: every screen and every suite would have to branch on
       * the model before asking a device to unlock, and the one that forgot
       * would sit pressing buttons at a device with three of them until the
       * timeout ran out.
       *
       * The wait below is unchanged - the device announces UNLOCKED the same
       * way whichever mechanism opened it.
       */
      const isDuo = currentType() === slots.DEVICE_TYPE.DUO;
      const enter = isDuo
        ? (line) => device.duoPin([String(line)], { set: false })
        : (enterDigits || ((line) => pressLine(transport, line)));

      const seen = await new Promise((resolve, reject) => {
        const offs = [];
        const done = (fn) => {
          clearTimeout(timer);
          for (const off of offs) off();
          fn();
        };

        const timer = setTimeout(() => {
          /*
           * There is no rejection message to wait for. A wrong digit is simply
           * appended and the device stays quiet, so a timeout is the ONLY
           * signal that the PIN was wrong - and it cannot be distinguished
           * from a device that is not listening. Both possibilities go in the
           * message rather than guessing between them.
           */
          done(() => reject(new Error(
            `the device did not unlock within ${timeoutMs}ms - the PIN may be wrong, ` +
            'or a previous attempt may still be in its buffer (see clearPinEntry). ' +
            `console tail: ${JSON.stringify(console_.text.slice(-120))}`,
          )));
        }, timeoutMs);

        offs.push(transport.on('report', (event) => {
          if (event.iface !== IFACE.VENDOR) return;
          const state = okmsg.parseState(event.data);
          if (state && state.state === 'unlocked') done(() => resolve(state.raw));
        }));

        offs.push(transport.on('log', (event) => {
          if (/UNLOCKED/.test(event.text)) done(() => resolve(event.text.trim()));
        }));

        /*
         * Pressed AFTER both subscriptions are up. The firmware answers within
         * a loop iteration of the last digit, which on an in-process bus is
         * faster than a caller that writes first can start listening.
         */
        Promise.resolve(enter(digits)).catch((err) => done(() => reject(err)));
      });

      progress('unlocked', { status: seen });
      events.emit('unlocked', { status: seen });
      return seen;
    },

    /**
     * Attempt to discard a half-entered PIN. UNRELIABLE, and measured to be.
     *
     * A failed attempt is not cleared on its own: the digits stay in the
     * firmware's `password` buffer and the next attempt APPENDS to them, so a
     * second try with the correct PIN fails too.
     *
     * The device's own way out is a long press on button 6 - the `>= 72` band
     * at OnlyKey.ino:914 that calls password.reset(). But that branch sits at
     * the end of a long else-if chain guarded on `!isfade`, while
     * password.append() runs unconditionally 220 lines earlier at :694. So when
     * the LED happens to be fading - which on a locked device pulsing its
     * status is much of the time - the press is APPENDED and never reset, and
     * the gesture makes the buffer worse rather than empty.
     *
     * Observed on the device: "6!" followed by a 7-digit PIN produced EIGHT
     * appends and no unlock.
     *
     * The reliable reset is a firmware restart, since the buffer is RAM. See
     * FINDING-pin-buffer-cannot-be-cleared.md.
     */
    clearPinEntry() {
      return pressLine(transport, '6!');
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

    /**
     * Take the device into CONFIG MODE, and confirm it actually went.
     *
     * The gesture, the proof and the retry - everything except the pressing.
     * A host supplies `hold(button, ticks)`, because pressing a button is
     * platform-specific and the library has no business knowing how; the same
     * split device.captureBackup() already makes about its own trigger.
     *
     * ## The gesture comes from the device
     *
     * A classic wants button 6 held past 72 main-loop iterations, a DUO button
     * 1 past 180 (OnlyKey.ino:914). Holding the classic gesture at a DUO
     * presses a button that does something else and then waits for a lock that
     * never comes.
     *
     * ## The LOCK is the proof, not the press
     *
     * `hold` resolving means the press was delivered and counted, not that
     * payload() acted on it. Two firmware states swallow the gesture and
     * neither is readable over the wire: `isfade`, while the LED is still
     * fading from a previous press, and `pending_operation`, for up to twenty
     * seconds after a FIDO ceremony. A swallowed hold is handled as an ordinary
     * long press instead - which TYPES A SLOT at the keyboard.
     *
     * Entering config mode locks the device (OnlyKey.ino:914-926), so a device
     * still answering readLabels afterwards did not enter it. That is the only
     * positive signal available, so it is the one used, and a miss is retried
     * rather than reported - the window that swallowed it is transient.
     *
     * ## It cannot be left
     *
     * There is no message to exit. Config mode ends at RESTART and nowhere
     * else, and while in it the device goes silent on CTAPHID - every derive
     * and every FIDO ceremony for the rest of the firmware's life. That is
     * recorded on the session the moment this succeeds, so the next thing to
     * try one gets told by name instead of timing out.
     *
     * @param {object} opts
     * @param {function} opts.hold        (button, ticks) => Promise
     * @param {function} [opts.settle]    ms => Promise, for the waits
     * @param {number} [opts.attempts]    holds before giving up
     * @param {number} [opts.lockMs]      how long to watch for the lock
     * @param {number} [opts.quietMs]     wait before a retry, for the fade
     */
    async enterConfigMode({
      hold,
      settle = (ms) => new Promise((r) => setTimeout(r, ms)),
      attempts = 3,
      lockMs = 8000,
      quietMs = 22000,
    } = {}) {
      if (typeof hold !== 'function') {
        throw new Error(
          'enterConfigMode needs a hold(button, ticks) - the library does not '
          + 'press buttons, the host does',
        );
      }

      const caps = session.capabilities;
      const gesture = (caps && caps.configModeGesture) || { button: 6, ticks: 72 };
      /*
       * A small margin over the floor, never a generous one. Past the same band
       * a hold stops being config mode and becomes another gesture, so
       * overshooting is not the safe direction.
       */
      const ticks = gesture.ticks + 8;

      for (let attempt = 1; attempt <= attempts; attempt++) {
        progress('configMode', { step: 'holding', button: gesture.button, ticks, attempt });
        await hold(gesture.button, ticks);

        const deadline = Date.now() + lockMs;
        while (Date.now() < deadline) {
          await settle(1000);
          try {
            await device.readLabels({ timeoutMs: 2000 });
          } catch (_) {
            /* Refused: it locked, so the gesture landed. */
            session.configMode = true;
            progress('configMode', { step: 'entered', attempt });
            return { entered: true, attempts: attempt, gesture };
          }
        }

        progress('configMode', { step: 'swallowed', attempt });
        if (attempt < attempts) await settle(quietMs);
      }

      throw new Error(
        `the device never locked after ${attempts} holds, so the config-mode `
        + 'gesture was not taken. A hold is ignored while the LED is fading and '
        + 'while pending_operation is set after a FIDO ceremony, and is then '
        + 'handled as an ordinary long press that types a slot.',
      );
    },

    /**
     * Whether the device has become readable again after a config-mode unlock.
     *
     * UNLOCKING IN CONFIG MODE IS NEVER ANNOUNCED (OnlyKey.ino:707), so there
     * is no broadcast to wait for and unlock()'s own wait can only time out
     * saying the PIN may be wrong. It is not; there is nothing to hear.
     *
     * OKGETLABELS is on the config-mode allowlist and is refused while locked,
     * so a successful read is the positive proof the broadcast never gives.
     * Polled rather than inferred from the status broadcast stopping, because
     * silence is also what a wedged device produces.
     */
    async configModeReady({ timeoutMs = 2500 } = {}) {
      try {
        await device.readLabels({ timeoutMs });
        return true;
      } catch (_) {
        return false;
      }
    },

    /** True once enterConfigMode has succeeded. Ends only at restart. */
    get inConfigMode() { return session.configMode; },

    /** Send button presses directly - the manual half of the PIN bracket. */
    press(digits) { return pressLine(transport, digits); },

    /**
     * DOES THE CONSOLE ANSWER? Asked, not inferred from a version.
     *
     * `press()` writes to the debug console, and whether anything READS it
     * depends on the firmware: the working tree has a parser, and no released
     * firmware has a `Serial.read` in okcore.cpp at all. `capabilities()`
     * models that as `consolePress`, from the version string.
     *
     * WHICH IS NO USE WHEN IT MATTERS. A locked device answers with no version
     * - `INITIALIZED` and nothing else - so `consolePress` is unknowable until
     * the PIN is in, and entering the PIN is exactly what needs the answer. A
     * host that consults the capability before unlocking is always told no.
     *
     * The firmware settles it itself. `dbg_commit_line()` prints
     * `I received from DEBUG: <first byte>` BEFORE acting on a line, and says
     * in its own comment that clients use it as an acknowledgement and as a
     * "the firmware is running loop()" readiness probe.
     *
     * ## Nothing is pressed
     *
     * The byte sent is neither a button (1-6) nor a command (0, 8, 9), so it
     * reaches the command parser, matches nothing, and produces the echo and
     * nothing else. That matters more than it sounds: the obvious probe is to
     * press a button and watch for the digit, and on a LOCKED device that
     * appends to the PIN buffer and counts as a failed attempt. Enough of them
     * wipe the key - see
     * ok-rn/FINDING-probing-on-a-locked-key-burns-pin-attempts.md, which was
     * written after doing exactly that to a bench key.
     *
     * @returns {Promise<boolean>} whether the console read what was written
     */
    async consoleAnswers({ timeoutMs = 3000 } = {}) {
      /*
       * Cleared first. The echo has to be one this call caused - the buffer
       * holds whatever the device has been saying, and a device says a lot.
       */
      console_.clear();
      await device.press(CONSOLE_PROBE_BYTE);

      try {
        await console_.waitFor(CONSOLE_PROBE_ECHO, { timeoutMs });
        return true;
      } catch (_) {
        /*
         * A timeout is the ANSWER here, not a failure. Every released firmware
         * reaches this branch and is working exactly as built.
         */
        return false;
      }
    },

    /* ---- slots --------------------------------------------------------- */

    readLabels(opts = {}) {
      return slots.readLabels(transport, { deviceType: currentType(), ...opts });
    },

    slotNumber(slotId) { return slots.slotNumber(slotId, currentType()); },

    /**
     * Ask the key to TYPE a slot, and read back what it typed.
     *
     * There is no message that reads a credential out; the firmware will not
     * hand one over. The only way to see what is in a slot is to press its
     * button and decode the keystrokes, which on hardware means into a text
     * editor and here means off the keyboard interface.
     *
     * `press` is the caller's, for the same reason captureBackup's `trigger`
     * is: making the device do it is platform-specific - a counted hold on the
     * emulator, a finger on a real key - and the library has no business
     * knowing which. Everything else is protocol, so it lives here rather than
     * in a screen.
     *
     * ## THE PRESS IS COUNTED, NOT TIMED
     *
     * The band comes from pressForSlot(), which is the inverse of gen_press()
     * and gen_hold(). A tap types the a profile, a hold types the b profile,
     * and a hold that runs past the gesture floor stops being a slot read
     * entirely - button 1 takes a backup, button 3 locks the key or cycles a
     * DUO's profile. src/device/press.js has the bands and the refusal, and
     * both are used rather than restated.
     *
     * ## IT WAITS FOR THE TYPING TO STOP, NOT FOR A FIXED TIME
     *
     * A slot is typed one character at a time, paced by its own TYPESPEED, so
     * how long it takes is a property of the slot and not something to guess.
     * The read ends after `quietMs` with no new report, and `timeoutMs` is only
     * the outer bound for a device that never starts.
     *
     * ## NOTHING IN THE REPLY SAYS WHICH SLOT IT WAS
     *
     * The device types the profile it is on, and does not announce which one.
     * `profile` is passed through to pressForSlot, which refuses a slot id the
     * requested profile cannot reach; the physical slot that will be typed is
     * returned as `slot` so a caller can check it against a label.
     *
     * @param {string|number} slotId
     * @param {object} opts
     * @param {function} opts.press      (button, ticks) => Promise
     * @param {number} [opts.profile]    the profile the DEVICE is on
     * @param {number} [opts.ticks]      override the band's hold length
     * @param {number} [opts.quietMs]    idle before the typing is finished
     * @param {number} [opts.timeoutMs]  outer bound on the whole read
     * @param {string} [opts.layout]     keyboard layout for the decode
     */
    async readSlot(slotId, {
      press,
      profile = 0,
      ticks = null,
      quietMs = 600,
      timeoutMs = 8000,
      layout,
    } = {}) {
      if (typeof press !== 'function') {
        throw new Error(
          'readSlot needs a press(button, ticks) - the library does not press '
          + 'buttons, the host does',
        );
      }

      const plan = slots.pressForSlot(slotId, {
        deviceType: currentType(),
        profile,
      });

      const held = ticks === null
        ? (plan.band === 'hold' ? presses.PRESS_TICKS.HOLD : presses.PRESS_TICKS.TAP)
        : ticks;

      /*
       * An overridden hold is checked against the gesture band, because the
       * whole point of allowing the override is that a slow TYPESPEED might
       * want a longer one - and the next number up from "longer" is the one
       * that takes a backup.
       */
      const refusal = presses.gestureRefusal(plan.button, held);
      if (refusal) {
        throw new Error(`readSlot would not be a slot read: ${refusal}`);
      }

      const decoder = keystrokes.createDecoder(layout ? { layout } : {});
      let reports = 0;
      let lastAt = 0;

      const off = transport.on('keyboard', (event) => {
        decoder.push(event.data);
        reports += 1;
        lastAt = Date.now();
      });

      try {
        await press(plan.button, held);

        const deadline = Date.now() + timeoutMs;
        for (;;) {
          await new Promise((r) => setTimeout(r, 100));
          if (reports && Date.now() - lastAt >= quietMs) break;
          if (Date.now() >= deadline) break;
        }
      } finally {
        off();
      }

      const text = decoder.text;
      const { segments, separators } = keystrokes.splitFields(text);

      progress('readSlot', {
        slot: plan.slot, button: plan.button, band: plan.band, reports,
      });

      return {
        ...plan,
        slotId,
        ticks: held,
        text,
        segments: reports ? segments : [],
        separators,
        reports,
        unmapped: decoder.events.filter((e) => e.unmapped),
      };
    },

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
    async setSlot(slotId, values, { timeoutMs = 3000, retries = 2 } = {}) {
      const slot = typeof slotId === 'number' ? slotId : slots.slotNumber(slotId, currentType());
      const writes = slotConfig.planSlotWrites(values, slot);
      const applied = [];

      for (const write of writes) {
        const { text, attempts } = await sendField(write, { timeoutMs, retries });
        if (/^Error/i.test(text)) {
          throw new Error(`${write.name}: ${text}`);
        }
        applied.push({ name: write.name, response: text, attempts });
        progress('field', { slot, field: write.name, response: text, attempts });
      }

      return applied;
    },

    /* ---- preferences --------------------------------------------------- */

    /** The settable preferences, for a screen that renders itself. */
    preferences() {
      return Object.entries(PREFERENCES).map(([name, spec]) => ({ name, ...spec }));
    },

    /**
     * One preference: OKSETSLOT on the global slot with a single byte.
     *
     * Goes through the same retrying send as a slot field, for the same
     * reason - an unacknowledged write is unknown, not failed.
     */
    async setPreference(name, value, { timeoutMs = 10000, retries = 2 } = {}) {
      const spec = PREFERENCES[name];
      if (!spec) {
        throw new Error(
          `unknown preference "${name}"; known: ${Object.keys(PREFERENCES).join(', ')}`,
        );
      }
      const byte = Number(value);
      if (!Number.isInteger(byte) || byte < 0 || byte > spec.max) {
        throw new RangeError(
          `${name} must be an integer 0..${spec.max}, got ${value}`,
        );
      }

      const frame = okmsg.build({
        msg: MSG.OKSETSLOT,
        slot: slots.GLOBAL_SLOT,
        field: spec.field,
        payload: [byte],
      });
      const { text, attempts } = await sendField(
        { name, frame }, { timeoutMs, retries },
      );
      if (/^Error/i.test(text)) throw new Error(`${name}: ${text}`);
      progress('preference', { name, value: byte, response: text, attempts });
      return { name, value: byte, response: text, attempts };
    },

    /* ---- keys ---------------------------------------------------------- */

    /**
     * Load a private key into an RSA or ECC slot.
     *
     * RSA keys do not fit in one report, so they go out as OKSETPRIV packets
     * with a continuation byte (chunker.sendRsaKey). ECC keys do fit and are
     * one frame - the split is the key SIZE, not the algorithm, which is why
     * both live behind one method.
     */
    async loadKey(slotId, { type, key },
      { onProgress = null, ackTimeoutMs = 8000, ackRetries = 2 } = {}) {
      const slot = typeof slotId === 'number' ? slotId : slots.slotNumber(slotId, currentType());
      const bytes = Uint8Array.from(key);
      const send = (frame) => transport.write(IFACE.VENDOR, frame);

      /*
       * Chunked when it does not fit, which for OKSETPRIV means anything past
       * chunker.CHUNK_BYTES. That is the real distinction and it happens to
       * separate RSA from ECC: an ECC scalar is 32 bytes and a single frame,
       * an RSA p||q is at least 128 and is not.
       */
      /*
       * AWAIT THE ACKNOWLEDGEMENT, and retry if it does not come.
       *
       * This used to write one frame and return. The device DOES answer -
       * ecc_priv_flash hidprints "Successfully set ECC Key" on every release in
       * the matrix - so a write that went nowhere was indistinguishable from one
       * that landed, and the caller found out one operation later when the slot
       * turned out to be empty.
       *
       * Measured on v2.1.0: a key write issued immediately after another
       * command produced no answer and no console output at all, and the SAME
       * write repeated 1.5 seconds later succeeded. The preference write before
       * it had already been landing on its own retry, which is why nothing else
       * in this plugin showed the problem - `sendField` has retried since it was
       * written, and this was the one command that did not.
       *
       * Rewriting the same key to the same slot is idempotent, so a retry
       * cannot do half a thing.
       *
       * Slots 131 and 132 answer differently - "Successfully set Backup
       * Passphrase" for the designated backup slot - so the match is the
       * plugin's general acknowledgement shape rather than one string.
       */
      const acknowledged = async (frame) => {
        const reply = await transport.request({
          iface: IFACE.VENDOR,
          data: frame,
          timeoutMs: ackTimeoutMs,
          match: isSlotAcknowledgement,
        });
        return okmsg.text(reply);
      };

      if (bytes.length > chunker.CHUNK_BYTES) {
        /*
         * RSA keys are many frames and the device answers once, at the end, so
         * the chunker owns the write and only the final acknowledgement is
         * waited for here.
         */
        await chunker.sendRsaKey({ slot, type, key: bytes, send, onProgress });
      } else {
        const frame = okmsg.build({
          msg: MSG.OKSETPRIV, slot, field: type, payload: bytes,
        });
        let text = null;
        let last = null;
        for (let attempt = 1; attempt <= ackRetries + 1 && text === null; attempt++) {
          try {
            text = await acknowledged(frame);
            if (attempt > 1) progress('retry', { field: `key:${slot}`, attempt });
          } catch (err) {
            last = err;
            if (attempt > ackRetries) {
              throw new Error(
                `key write to slot ${slot} was never acknowledged after `
                + `${attempt} attempts - ${err.message}`,
              );
            }
          }
        }
        if (text && /^Error/i.test(text)) {
          throw new Error(`key write to slot ${slot} refused: ${text}`);
        }
        if (text) progress('keyAck', { slot, response: text });
      }
      /*
       * WRITING AN HMAC KEY REMOVES THAT SLOT'S PRESS REQUIREMENT, and the
       * device does not say so.
       *
       * process_setreport() recomputes hmac_challengemode on the success path
       * (okcore.cpp:7703-7715) so that the slot just written no longer needs a
       * button - and if the other HMAC slot was already press-free, both end up
       * that way. Afterwards any host that can reach the keyboard interface can
       * get HMAC-SHA1 responses from that key with no physical presence at all.
       *
       * The write is acknowledged exactly as any other key write is. So the
       * consequence is RETURNED rather than left to be discovered: a caller can
       * show it, and one that ignores it is at least ignoring something stated.
       * See onlykey-testing/FINDING-hmac-press-free-on-write.md.
       */
      const pressFree = slots.HMAC_SLOTS.includes(slot);
      if (pressFree) {
        progress('warning', {
          slot,
          warning: 'press-free',
          detail:
            'writing an HMAC key clears the button-press requirement on that ' +
            'slot; ' +
            'the device does not report this',
        });
      }

      progress('key', { slot, type, bytes: bytes.length, pressFree });
      return {
        slot,
        type,
        bytes: bytes.length,
        /** True when this write also made the slot answer without a press. */
        clearedPressRequirement: pressFree,
      };
    },

    /* ---- Yubico OTP ----------------------------------------------------- */

    /**
     * Write the DEVICE-GLOBAL Yubico credential - the Advanced tab's form.
     *
     * Validated first, and every problem is reported at once. The desktop app
     * converts the public id inline, throws on a hex digit where modhex was
     * wanted, and lets the throw escape into event dispatch: the button appears
     * to do nothing, the fields keep their values, and no byte is sent. See
     * onlykey-testing/FINDING-app-yubico-silent-discard.md.
     *
     * The global credential differs from the per-slot one in three ways, none
     * cosmetic: its public id is HEX rather than modhex, it must be exactly six
     * bytes because the firmware memcpys that many, and it lands on the
     * device-global pseudo-slot rather than a real one.
     *
     * @returns {Promise<{slot: number, response: string}>}
     * @throws with every field problem listed, before anything is sent
     */
    async setYubiAuth({ publicId, privateId, secretKey }, { timeoutMs = 10000, retries = 2 } = {}) {
      const check = encoders.validateYubiCredential(
        { publicId, privateId, secretKey }, { global: true },
      );
      if (!check.ok) {
        throw new Error(
          `Yubico credential rejected: ${check.errors.map((e) => `${e.field} ${e.message}`).join('; ')}`,
        );
      }

      const payload = encoders.yubiGlobalCredential({ publicId, privateId, secretKey });
      const frame = okmsg.build({
        msg: MSG.OKSETSLOT,
        slot: slots.GLOBAL_SLOT,
        field: FIELD.YUBIAUTH,
        payload,
      });

      const { text, attempts } = await sendField({ name: 'yubiAuth', frame }, { timeoutMs, retries });
      if (/^Error/i.test(text)) throw new Error(`yubiAuth: ${text}`);
      progress('yubiAuth', { slot: slots.GLOBAL_SLOT, response: text, attempts });
      return { slot: slots.GLOBAL_SLOT, response: text };
    },

    /** Check a credential without sending it, so a form can mark its fields. */
    validateYubiCredential: encoders.validateYubiCredential,

    /**
     * Import a PGP private key: extract, assign roles, and load each slot.
     *
     * Takes the PARSED key rather than armored text. OpenPGP.js is 1.2 MB
     * parsed and deliberately unreachable from this package's root - connecting
     * to a device must not pay for a PGP implementation - so the caller that
     * already has it does the reading:
     *
     *     const openpgp = require('node-onlykey-lib/crypto/pgp');
     *     let key = await openpgp.readPrivateKey({ armoredKey });
     *     if (!key.isDecrypted()) {
     *       key = await openpgp.decryptKey({ privateKey: key, passphrase });
     *     }
     *     await device.loadPgpKey(key);
     *
     * The roles are POSITIONAL - primary, then decryption subkey, then signing
     * subkey - so nothing here reorders or filters the candidates. A key it
     * cannot read fails the whole import rather than being skipped, because a
     * skipped subkey shifts every later one into the wrong role and the result
     * is a device that signs with its decryption key.
     */
    async loadPgpKey(parsedKey, { backup = false, onProgress = null } = {}) {
      const candidates = deviceKeys.fromPgpKey(parsedKey);
      const assignments = deviceKeys.assignPgpSlots(candidates);

      /*
       * Prepared in full BEFORE the first write, the same rule setSlot follows.
       * An unreadable second key should fail with nothing sent, not with one
       * slot written and the device half configured.
       */
      const planned = assignments.map(({ role, slot, key }) => ({
        role,
        ...deviceKeys.prepareKey(key, { slot, backup, autoAssign: true }),
      }));

      const loaded = [];
      for (const item of planned) {
        /* `device`, not `this` - these methods are routinely destructured off
         * the service, and `this` is undefined the moment they are. */
        await device.loadKey(item.slot, { type: item.type, key: item.key }, { onProgress });
        loaded.push({ role: item.role, slot: item.slot, type: item.type });
      }
      progress('pgpKey', { slots: loaded.map((l) => l.slot) });
      return loaded;
    },

    /** Erase a key slot. Irreversible; the caller has already confirmed. */
    async wipeKey(slotId) {
      const slot = typeof slotId === 'number' ? slotId : slots.slotNumber(slotId, currentType());
      await transport.write(IFACE.VENDOR, okmsg.build({
        msg: MSG.OKWIPEPRIV, slot,
      }));
      progress('wipeKey', { slot });
      return { slot };
    },

    /**
     * Derive the backup key from a passphrase and store it.
     *
     * The passphrase never reaches the device - only the key derived from it
     * does - so getting the derivation wrong produces a backup that cannot be
     * restored and says nothing at the time. validateBackupPassphrase() is
     * therefore not advisory: a passphrase it rejects is one the desktop app
     * would have derived a different key from.
     */
    async setBackupPassphrase(passphrase, { timeoutMs = 5000, retries = 1 } = {}) {
      /*
       * backupKeyFromPassphrase() returns { slot, type, key } and validates on
       * the way - passing the whole object through as the payload builds a
       * frame with an EMPTY body, because Uint8Array.from() of a plain object
       * yields nothing. That is what this did at first, and the test did not
       * catch it: it asserted the passphrase was absent from the frame, which
       * is trivially true of a frame with no body at all.
       */
      const derived = deviceKeys.backupKeyFromPassphrase(passphrase);
      const frame = okmsg.build({
        msg: MSG.OKSETPRIV,
        slot: derived.slot,
        field: derived.type,
        payload: derived.key,
      });

      /*
       * AWAITED, because this write is silently refused more often than it
       * succeeds. OKSETPRIV is accepted only in config mode or on a device's
       * first use (okcore.cpp:452), and the refusal has no else branch - the
       * frame is dropped with nothing said. Writing and returning therefore
       * reports success for a passphrase the device never took, and the next
       * thing the user hears is a backup refusing itself for want of the key
       * they were told had been set. Measured exactly that.
       *
       * ecc_priv_flash answers "Successfully set Backup Passphrase"
       * (okcore.cpp:5399), so there is an acknowledgement to wait for.
       */
      const { text, attempts } = await sendField(
        { name: 'backup passphrase', frame }, { timeoutMs, retries },
      );
      if (/^Error/i.test(text)) throw new Error(`backup passphrase: ${text}`);

      progress('backupKey', { slot: derived.slot, response: text, attempts });
      return { slot: derived.slot, type: derived.type, response: text, attempts };
    },

    /**
     * Set the backup key from a PGP private scalar instead of a passphrase.
     *
     * The desktop's Setup Step 9. Same slot as the passphrase form and a
     * different source, so the two share everything below the derivation -
     * including the wait, which matters for the same reason: OKSETPRIV is
     * accepted only in config mode or on first use, and the refusal has no else
     * branch. Writing and returning would report success for a key the device
     * never took, and the next thing anyone hears is a backup refusing itself.
     *
     * The CURVE is required rather than guessed. A NIST P-256 scalar written
     * with the Ed25519 type is accepted and then decrypts nothing, which is
     * discovered at restore time.
     */
    async setBackupKeyFromPgp(scalar, {
      curve, alsoSignature = false, timeoutMs = 5000, retries = 1,
    } = {}) {
      const derived = deviceKeys.backupKeyFromPgp(scalar, { curve, alsoSignature });
      const frame = okmsg.build({
        msg: MSG.OKSETPRIV,
        slot: derived.slot,
        field: derived.type,
        payload: derived.key,
      });

      const { text, attempts } = await sendField(
        { name: 'backup key', frame }, { timeoutMs, retries },
      );
      if (/^Error/i.test(text)) throw new Error(`backup key: ${text}`);

      progress('backupKey', { slot: derived.slot, response: text, attempts });
      return { slot: derived.slot, type: derived.type, response: text, attempts };
    },

    /* ---- backup and restore -------------------------------------------- */

    /**
     * Restore from a backup file.
     *
     * VERIFIED BEFORE A BYTE IS SENT. The digest is a chain - each line hashed
     * with the running digest - so it catches a reordering as well as an edit,
     * and a restore is not something to discover halfway through.
     */
    async restore(text, { onProgress = null } = {}) {
      const check = parsers.verifyBackup(text);
      if (!check.ok) {
        throw new Error(
          `backup failed verification (${check.reason || 'digest mismatch'}): ` +
          `expected ${check.expected}, computed ${check.digest}`,
        );
      }
      const hex = parsers.parseBackup(text);
      await chunker.sendHexStream({
        msg: MSG.OKRESTORE,
        hex,
        send: (frame) => transport.write(IFACE.VENDOR, frame),
        onProgress,
      });
      progress('restore', { bytes: hex.length / 2 });
      return { bytes: hex.length / 2, digest: check.digest };
    },

    /**
     * Capture a backup the device TYPES.
     *
     * There is no command for this. The firmware answers the backup gesture by
     * typing the whole file at the keyboard (Backup.tsx:116-130 sends nothing
     * at all), which on hardware means into a text editor the user opened. Here
     * the app is the host, so the keystrokes arrive as HID reports and can be
     * decoded back into the file.
     *
     * `trigger` is supplied by the caller because making the device do it is
     * platform-specific - on the emulator it is a counted button hold, on
     * hardware it is a finger - and the library has no business knowing which.
     *
     * Ends on the END marker rather than on a timeout, so a backup that is
     * still arriving is not truncated into a file that verifies as damaged.
     */
    async captureBackup({ trigger, timeoutMs = 60000, layout, onProgress = null } = {}) {
      const decoder = keystrokes.createDecoder(layout ? { layout } : {});

      return new Promise((resolve, reject) => {
        let settled = false;
        const finish = (fn, arg) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          offKeys();
          offReports();
          fn(arg);
        };

        const timer = setTimeout(() => {
          const text = decoder.text;
          finish(reject, Object.assign(
            new Error(
              `backup capture timed out after ${timeoutMs}ms with ` +
              `${text.length} characters and no end marker`,
            ),
            { partial: text },
          ));
        }, timeoutMs);

        const offKeys = transport.on('keyboard', (event) => {
          decoder.push(event.data);
          if (onProgress) onProgress({ characters: decoder.text.length });
          if (!decoder.text.includes(parsers.BACKUP_END)) return;

          const text = decoder.text;
          const check = parsers.verifyBackup(text);
          progress('backup', { characters: text.length, ok: check.ok });
          finish(resolve, { text, verified: check.ok, ...check });
        });

        /*
         * The device also SAYS why it will not do it.
         *
         * backup() refuses when no backup key is set: it hidprint()s
         * "Error no backup key set" on the vendor interface and then TYPES a
         * sentence pointing at the documentation, instead of a backup
         * (okcore.cpp:6802-6813). Watching only the keyboard, that looks like
         * a backup that started and stopped - a hundred-odd characters, no end
         * marker - and the capture waits out its whole timeout before
         * reporting something that says nothing about the cause.
         *
         * Listening on the vendor interface as well turns a two-minute stall
         * into the device's own sentence, immediately.
         */
        const offReports = transport.on('report', (event) => {
          if (event.iface !== IFACE.VENDOR) return;
          const text = okmsg.text(event.data);

          /*
           * ONLY THE REFUSAL, not every error.
           *
           * A normal backup emits an error PER EMPTY SLOT while it walks them -
           * "Error no RSA Private Key set in this slot", and the ECC twin -
           * and those are chatter, not failure. Treating the first Error as
           * fatal (which this did at first) aborts a backup that was going
           * perfectly well, on the strength of an empty slot 1.
           *
           * BACKUP_REFUSALS is therefore a list of the messages that actually
           * END the operation, and nothing else here is load-bearing. A
           * refusal that is not on it costs a timeout, which is the old
           * behaviour; a false positive on it costs a backup.
           */
          if (!BACKUP_REFUSALS.some((re) => re.test(text))) return;
          finish(reject, Object.assign(new Error(text), { partial: decoder.text }));
        });

        Promise.resolve()
          .then(() => (trigger ? trigger() : undefined))
          .catch((err) => finish(reject, err));
      });
    },

    /** Wipe one field, or the whole slot when no field is named. */
    async wipeSlot(slotId, field = null, { timeoutMs = 3000 } = {}) {
      const slot = typeof slotId === 'number' ? slotId : slots.slotNumber(slotId, currentType());
      const reply = await transport.request({
        iface: IFACE.VENDOR,
        data: slotConfig.wipeMessage(slot, field),
        timeoutMs,
        match: isSlotAcknowledgement,
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
