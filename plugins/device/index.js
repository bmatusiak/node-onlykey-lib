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
const openssh = require('../../src/device/openssh');
const firmware = require('../../src/device/firmware');
const keystrokes = require('../../src/device/keystrokes');
const presses = require('../../src/device/press');
const encoders = require('../../src/device/encoders');
const { MSG, FIELD } = require('../../src/protocol/msg');
const okmsg = require('../../src/protocol/okmsg');
const { DeviceConsole, pressLine, safeTail } = require('../../src/device/console');
const { challengeDigits } = require('../../src/protocol/challenge');

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
  /**
   * Wait for one of the firmware's HID replies.
   *
   * The PIN bracket's prompts exist on two channels and only one of them
   * survives a release build - see pin.js HID_PROMPTS. This reads the wire,
   * which every device has, rather than the debug console, which most do not.
   */
  function waitForHid(match, { reject = [], timeoutMs = 10000 } = {}) {
    return new Promise((resolve, rejectP) => {
      let off = null;
      const done = (fn, arg) => {
        clearTimeout(timer);
        if (off) off();
        fn(arg);
      };
      const timer = setTimeout(
        () => done(rejectP, new Error(`the device did not answer ${match} within ${timeoutMs}ms`)),
        timeoutMs,
      );
      off = transport.on('report', (event) => {
        if (event.iface !== IFACE.VENDOR) return;
        const text = okmsg.parseState(event.data).raw || '';
        if (!text) return;
        for (const bad of reject) {
          if (bad && bad.test(text)) return done(rejectP, new Error(text.trim()));
        }
        if (match.test(text)) done(resolve, text);
      });
    });
  }

  /**
   * Wait for one step of the PIN bracket, on WHICHEVER channel answers.
   *
   * The wire is the design. Every prompt is hidprinted by every pinned
   * firmware version, ungated, which is why a production build can be
   * provisioned at all - the console twins are all `Serial.println` inside
   * `#ifdef DEBUG` and a release compiles them out.
   *
   * The console is raced alongside it and is NEVER REQUIRED. It cannot make a
   * step pass that the wire would have failed; it can only answer sooner, or
   * answer for a firmware whose wording we have not seen. Nothing production
   * does depends on it being there.
   *
   * A step whose HID prompt is null - `committed` - has nothing left to wait
   * for on the wire, so it waits on the console alone when there is one and
   * returns immediately when there is not.
   */
  function waitForStep(step, { timeoutMs = 10000 } = {}) {
    const names = step.reject || [];
    const onWire = pin.HID_PROMPTS[step.expect];
    const waits = [];

    if (onWire) {
      waits.push(waitForHid(onWire, {
        reject: names.map((name) => pin.HID_ERRORS[name]),
        timeoutMs,
      }));
    }
    waits.push(console_.waitFor(pin.PROMPTS[step.expect], {
      reject: names.map((name) => pin.ERRORS[name]),
      timeoutMs,
    }));

    /*
     * A STEP WITH NO WIRE PROMPT IS ADVISORY, and `committed` is the only one.
     * The wire announces the commit once, in `matched`, after the flash write -
     * so by the time that resolved there was nothing left to wait for. The
     * console still has its second line and waiting for it costs nothing on a
     * debug build, but a release has no console and must not be held up for
     * ten seconds by a line that cannot arrive. So it is tried and its timeout
     * is tolerated.
     */
    if (!onWire) {
      const advisory = pin.PROMPTS[step.expect];
      if (!advisory) return Promise.resolve();
      return console_.waitFor(advisory, {timeoutMs}).catch(() => {});
    }

    /*
     * Rejections are not swallowed by the race: a refusal on either channel -
     * "Error PINs Don't Match" - is a real answer and has to stop the bracket,
     * and Promise.race propagates the FIRST settlement whichever way it goes.
     *
     * The LOSER still settles though, and on a production build it always
     * loses by timing out - there is no console to answer. That rejection
     * arrives after the race is decided and would be an unhandled rejection,
     * which Node treats as fatal. Attaching a catch to each entry handles it
     * without changing what the race itself does.
     */
    const decided = Promise.race(waits);
    for (const wait of waits) wait.catch(() => {});
    return decided;
  }

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
      /*
       * ...but a step that only WAITS must not clear, or it throws away the
       * very line it is waiting for. The commit line can arrive in the same
       * read as "Both PINs Match" on a device that writes flash quickly, and
       * clearing here would then wait out the full timeout for a line that
       * had already been said.
       */
      if (step.send || step.digits) console_.clear();

      if (step.send) {
        await transport.write(IFACE.VENDOR, message);
        await waitForStep(step, { timeoutMs });
      } else if (step.digits) {
        if (enterDigits) await enterDigits(digits);
        else {
          await pressLine(transport, digits);
          /*
           * THE CONSOLE PATH STILL NEEDS THIS, and only the console path.
           *
           * pressLine writes the digits to SEREMU and returns; nothing in that
           * write says the device consumed them. The firmware acknowledges
           * each one with "password appended with", so counting the acks is
           * how a burst is known to have landed before the next OKPIN is sent
           * - and a message arriving mid-burst leaves the device holding a
           * SHORT PIN, which surfaces later as a mismatch between two PINs
           * that were typed identically.
           *
           * It is skipped for enterDigits because that hook is awaited and its
           * presses resolve on the observed release (holdTicks waits out the
           * idle sense rounds), so the burst is already known to be in. Which
           * is just as well: the ack is a Serial.println under DEBUG and does
           * not exist on a release build, so a caller that needs this count
           * needs the console anyway - and pressLine needs the console to work
           * at all.
           */
          await console_.waitForCount(pin.DIGIT_ACK, digits.length, { timeoutMs });
        }
      } else if (step.expect) {
        /*
         * A WAIT WITH NOTHING SENT. The firmware is already working and the
         * host has nothing to add - it only has to stay out of the way until
         * the write is done. See pin.js PROMPTS.committed: letting the caller
         * go at "Both PINs Match" means its next button press lands in the
         * buffer the firmware is still hashing, and the device stores the
         * hash of a longer string than the PIN it was given.
         */
        await waitForStep(step, { timeoutMs });
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
 *
 * ## `oneWay` - this write CANNOT BE TAKEN BACK
 *
 * A property of the FIRMWARE, so it belongs here rather than in whichever GUI
 * happens to notice. ok-rn held the list privately for a while; the nw desktop
 * app and the CLI can write all three fields and would each have had to
 * rediscover the hazard, and the next irreversible field would have been added
 * to the table and adopted silently by every screen that renders from it.
 *
 *   webcryptPolicy  the FIRST write ends the legacy field-21 inheritance
 *                   permanently, in either direction, including a write of 0
 *   backupKeyMode   locking it (1) cannot be undone
 *   wipeMode        on a provisioned key only the destructive value is settable
 *                   at all - the gentler ones need first use - so it is one-way
 *                   in practice
 *
 * WHICH settings are irreversible is protocol. WHERE a GUI puts them and how
 * hard it makes them to trigger is that GUI's business: ok-rn moves them to a
 * separate screen behind a typed word, a CLI might simply require a flag.
 */
/*
 * NAMED FOR WHAT THEY GOVERN, not for the mechanism.
 *
 * These labels are what a GUI shows, so they are the user's vocabulary rather
 * than the firmware's. "Derived key challenge" describes the byte; "SSH/GPG
 * derived keys" describes the thing the person is deciding about, and the
 * choice of challenge-or-press is the row's VALUE, not its name.
 *
 * Fields 21, 22 and 30 all answer "how do you approve this". Field 31 answers
 * "is this allowed at all", which is why it reads as a permission and not as a
 * confirmation - and why its own screen, not this table, is where it is set.
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
    label: 'SSH/GPG derived keys',
    requires: 'configMode',
    bits: {
      0: 'Three-button challenge on raw-HID derives',
      3: 'Allow per-site derived keys without a touch',
    },
    note: 'A bitmask. Bit 3 (value 8) is what lets a derived key be produced without pressing a button; without it the device answers "extension not supported", which is not what it means.',
  },

  /*
   * FIRMWARE 3.0.5 REINTERPRETS FIELD 21 ABOVE, and this field replaces it for
   * the derive path.
   *
   * From 3.0.5 fields 21, 22 and 30 are a 0/1/2 ENUM, not bitmasks, and
   * set_slot() refuses anything above 2 with "Error invalid user input mode" -
   * so the value 8 documented above stops working entirely. It is left as it is
   * because every pinned release before 3.0.5 still wants it.
   *
   * And 21 is the wrong byte for the web-and-agent derive in any case:
   * okcore_user_input_mode_for_slot() routes slot 128 straight to field 30, and
   * web_agent_derive_gate() reads okcore_web_agent_derive_mode() directly.
   *
   * THIS SETTING GOVERNS THE BROWSER. A web app reaches only the FIDO
   * interface, so it can neither read nor write this - the GUI that sets it is
   * one with VENDOR (desktop, react-native, CLI), on the browser's behalf.
   */
  webAgentDeriveMode: {
    field: FIELD.webAgentDeriveMode,
    max: 2,
    label: 'Web and agent derived keys',
    requires: 'configMode',
    choices: {
      0: 'Three-digit challenge',
      1: 'Button press',
      2: 'No confirmation',
    },
    note: 'How a shared-secret derive is authorised. A public-key derive is never gated. "No confirmation" is refused ("unsupported user input mode") on firmware built without OK_ALLOW_NO_PRESS.',
  },
  /*
   * FIELD 31 - what the browser may DO, as against field 30's how it is
   * confirmed. Two bytes on purpose; see FIELD.webcryptPolicy.
   *
   * IT IS A ONE-WAY LATCH, and that makes it unlike every other row here.
   * While unwritten (OKWC_UNSET 0xFF) the disable bit is inherited from legacy
   * field 21 bit 1, and the FIRST write of this byte ends that inheritance
   * permanently - it also becomes the marker deciding whether a 2 in field 21
   * means the enum's "no press" or the legacy bitfield's "disable extension".
   * So writing it AT ALL, even to 0, changes how field 21 is read afterwards,
   * and a device cannot be put back.
   *
   * Consequences a GUI must respect: never write this as part of a "restore
   * defaults" or a save-everything, and never write it to prove a form
   * round-trips. Only when the user asked for this specific change.
   *
   * ABSENT FROM THE BACKUP BLOB entirely, so a restore silently drops the
   * policy back to OKWC_UNSET and re-enables the legacy inheritance - unlike
   * field 30, which does appear there when non-zero.
   *
   * Undefined bits are REJECTED, not masked ("Error invalid webcrypt policy",
   * okcore.cpp:2117), so max is the valid mask rather than 255.
   */
  webcryptPolicy: {
    field: FIELD.webcryptPolicy,
    max: 3,
    label: 'Browser permissions',
    requires: 'configMode',
    oneWay: true,
    bits: {
      0: 'Let the browser use stored keys (PGP) over FIDO2',
      1: 'Turn the OnlyKey FIDO2 extension off entirely',
    },
    note: 'Governs the BROWSER, which cannot set it itself - a web app reaches only the FIDO interface. Both bits default off: derived keys yes, stored keys no, extension on. Writing this once permanently ends the legacy field-21 inheritance, so set it only when you mean to.',
  },
  storedChallengeMode:  { field: FIELD.storedchallengeMode, max: 1, label: 'Stored keys (PGP, SSH, RSA and ECC slots)', requires: 'configMode' },
  hmacChallengeMode:    { field: FIELD.hmacchallengeMode, max: 1, label: 'HMAC challenge', requires: 'configMode' },
  modKeyMode:           { field: FIELD.modkeyMode, max: 1, label: 'Sysadmin mode', requires: 'configMode' },

  /*
   * How hard a finger has to press, and the ONE preference with a floor.
   *
   * okcore.cpp:2106-2119 accepts `buffer[7] > 1 && buffer[7] <= 100` and
   * answers "Error touchsense value out of range" otherwise - so 0 and 1
   * are refused, which every other preference here would have accepted.
   * That is why `min` exists at all; the alternative was letting a caller
   * send a byte the firmware throws away and calling it a success.
   *
   * Lower is MORE sensitive (it is an offset from the measured baseline);
   * the firmware's own default lives in EEPROM and is not readable, so
   * this sets without being able to show what it is now - the same
   * limitation every preference here has.
   */
  touchSense: {
    field: FIELD.TOUCHSENSE, min: 2, max: 100, label: 'Touch sensitivity',
    requires: 'configMode',
    note: 'Lower is more sensitive. The firmware refuses anything outside 2-100.',
  },

  wipeMode: {
    field: FIELD.WIPEMODE, max: 2, label: 'Wipe mode', requires: 'configMode',
    oneWay: true,
    note: 'Full wipe (2) needs config mode; the other values can only be set '
      + 'before setup is finished.',
  },
  backupKeyMode: {
    field: FIELD.BACKUPKEYMODE, max: 1, label: 'Backup key mode', requires: 'configMode',
    oneWay: true,
    note: 'Locking it (1) needs config mode, and cannot be undone afterwards.',
  },

  secProfileMode: {
    field: FIELD.SECPROFILEMODE, max: 2, label: 'Second profile mode', requires: 'firstUse',
    note: 'Only settable before setup is finished. A provisioned key refuses it.',
  },
};

/**
 * What fields 21, 22 and 30 become at firmware 3.0.5 - applied over the rows
 * above by preferences(), never instead of them.
 *
 * An OVERLAY rather than a second table, because only the SHAPE changes:
 * the field number, the gate and the label are the same settings either way,
 * and duplicating them is how two descriptions of one byte drift apart.
 *
 * `max` drops from 255 to the largest value the firmware will take, and the
 * bitmask is replaced outright - `bits: undefined` rather than omitted,
 * because a spread leaves an untouched key in place and a stale `bits` would
 * have the screen draw toggles beside the choices.
 *
 * "NO CONFIRMATION" IS ON FIELD 30 ONLY. Production firmware refuses 2 on 21
 * and 22 ("unsupported user input mode") and fails a stale one closed to the
 * challenge code, so offering it there could only produce an error the user
 * cannot act on. Even on 30 it depends on OK_ALLOW_NO_PRESS, which is why the
 * note says so rather than the option being silently absent.
 */
const USER_INPUT_ENUM_ROWS = {
  derivedChallengeMode: {
    max: 1,
    bits: undefined,
    choices: { 0: 'Three-digit challenge', 1: 'Button press' },
    note: 'How you approve a key derived for SSH or GPG. From firmware 3.0.5 this is one of two values, not a bitmask - the old "bit 3 for no touch" is gone, and writing 8 is refused.',
  },
  storedChallengeMode: {
    max: 1,
    choices: { 0: 'Three-digit challenge', 1: 'Button press' },
    note: 'How you approve a key the device already holds - PGP, SSH, and the RSA and ECC slots.',
  },
  webAgentDeriveMode: {
    max: 2,
    choices: {
      0: 'Three-digit challenge',
      1: 'Button press',
      2: 'No confirmation',
    },
    note: 'How you approve a key derived on demand from a label, shared by the OnlyKey web app and by local agents over USB (onlykey-agent, python-onlykey, age). It never changes WHICH key is derived, only how you authorise it, so anything already encrypted to a label still decrypts. "No confirmation" is refused on firmware built without OK_ALLOW_NO_PRESS.',
  },
};

  /**
   * One OKGETPUBKEY read. `getPublicKey` wraps this with the retry.
   *
   * @param {number|string} slotId
   * @param {object} [opts] {bytes, keyType, timeoutMs, settleMs}
   */
  async function readPublicKey(slotId, { bytes = 0, keyType = 0, timeoutMs = 8000, settleMs = 60 } = {}) {
    const slot = typeof slotId === 'number' ? slotId : slots.slotNumber(slotId, currentType());
    const frame = okmsg.build({ msg: MSG.OKGETPUBKEY, slot, field: keyType });

    /*
     * Subscribed before the write, and leading status broadcasts skipped
     * only BEFORE the first data byte - the same rule okcrypto's collector
     * and python-onlykey's read_exact follow, for the same reason: once
     * the key has started arriving a report may legitimately read as text
     * or be all zeros, and dropping one corrupts the answer silently.
     */
    let started = false;
    let off = null;
    const collected = [];
    let got = 0;

    const answer = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (off) off();
        reject(new Error(
          `slot ${slot} did not answer OKGETPUBKEY within ${timeoutMs}ms`,
        ));
      }, timeoutMs);

      off = transport.on('report', (event) => {
        if (event.iface !== IFACE.VENDOR) return;
        if (!started) {
          const state = okmsg.parseState(event.data);
          if (state.state === 'unlocked' || state.state === 'locked'
              || state.state === 'uninitialized' || state.state === 'bootloader') return;
          if (state.state === 'error') {
            clearTimeout(timer);
            if (off) off();
            reject(okmsg.deviceError(state.raw));
            return;
          }
          /*
           * The one refusal that does not begin with "Error": an
           * uninitialized device answers "No PIN set, You must set a PIN
           * first" (okcore.cpp:576). Matched by its exact words rather
           * than by "looks like text", because a public key may look like
           * text too.
           */
          const text = okmsg.text(event.data);
          if (/^No PIN set/i.test(text)) {
            clearTimeout(timer);
            if (off) off();
            reject(okmsg.deviceError(text));
            return;
          }
          started = true;
        }
        collected.push(Uint8Array.from(event.data));
        got += event.data.length;
        if (bytes && got < bytes) return;
        clearTimeout(timer);
        if (off) off();
        const out = new Uint8Array(got);
        let at = 0;
        for (const c of collected) { out.set(c, at); at += c.length; }
        resolve(bytes ? out.slice(0, bytes) : out);
      });
    });

    await transport.write(IFACE.VENDOR, frame);
    let key;
    try {
      key = await answer;
    } catch (err) {
      /* A refusal owes the same settle: it is a hidprint like any other. */
      if (settleMs > 0) await new Promise((r) => setTimeout(r, settleMs));
      throw err;
    }
    if (settleMs > 0) await new Promise((r) => setTimeout(r, settleMs));
    progress('publicKey', { slot, bytes: key.length });
    return key;
  }

  /**
   * The eight bytes that mean "make one yourself".
   *
   * set_private() sums buffer[7..14] and compares against 2040
   * (okcore.cpp:5311). Eight 0xFFs is the only way to hit it with a key body
   * that is otherwise a legal length, and the sum - rather than a flag byte -
   * is what the firmware actually tests, which is why this is written as the
   * bytes and not as a named constant somewhere claiming to be a command.
   */
  /**
   * Resolve once no vendor report has arrived for `quietMs`.
   *
   * Capped, because a device that chatters forever - the once-a-second
   * INITIALIZED broadcast of a locked key, say - would otherwise hang a
   * caller rather than fail it. Reaching the cap is not an error: the
   * operation goes ahead and its own timeout covers it.
   */
  function busQuiet(quietMs, capMs) {
    return new Promise((resolve) => {
      let timer = null;
      const giveUp = setTimeout(() => { finish(); }, capMs);
      const off = transport.on('report', (event) => {
        if (event.iface !== IFACE.VENDOR) return;
        clearTimeout(timer);
        timer = setTimeout(finish, quietMs);
      });
      function finish() {
        clearTimeout(timer);
        clearTimeout(giveUp);
        off();
        resolve();
      }
      timer = setTimeout(finish, quietMs);
    });
  }

  const GENERATE_TRIGGER = Uint8Array.from([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  ]);

  /**
   * Ask the DEVICE to make a post-quantum key in a slot, and read the public
   * half back.
   *
   * The private half is a 32-byte seed that is generated inside the key,
   * encrypted with the profile key and written to flash without ever crossing
   * the wire. That is the whole point of this over generating on the phone:
   * there is no moment at which a private key exists in the host's memory.
   *
   * ## Why this cannot go through loadKey
   *
   * loadKey waits for a `Successfully set ...` acknowledgement. This
   * operation deliberately does NOT send one - `ecc_priv_flash` is called
   * with `quiet` set, and the firmware comment at okcore.cpp:5401 explains
   * why at length: the acknowledgement would go out as an ordinary transport
   * response and the public key follows immediately after, so a host
   * collecting 1216 bytes would take the sentence as the key's first report,
   * end up with "Successfully set ECC Key" followed by zeros and the real key
   * shifted along, and print a recipient the device does not have. Anything
   * encrypted to it would be lost.
   *
   * So the answer here is raw key bytes from the first report, and the only
   * thing that says how many to read is the key type.
   *
   * ## The button challenge, and why the frame is sent ONCE
   *
   * Generation needs a three-button confirmation. The first request primes it
   * - ecc_priv_flash builds a nine-byte payload `[keytype, FF x8]`, hands it
   * to process_packets(), sets a pending operation and RETURNS without
   * generating (okcore.cpp:5326-5339).
   *
   * The host does not re-send. The third press replays it: the button handler
   * decrypts the stored payload, rebuilds the buffer and calls set_private()
   * itself (OnlyKey.ino:846-859). A client that sent the trigger again while
   * the challenge was up would hit `CRYPTO_AUTH != 4` and be ignored, and on
   * an unlocked device the stray presses that follow type slot contents at
   * the keyboard.
   *
   * The digits are computed over those nine bytes, NOT over the eight-byte
   * payload - done_process_packets hashes what process_packets was given.
   *
   * ## One press may be enough
   *
   * For slots 101..116 the firmware reads the stored-key challenge
   * preference, and when it is on it sets CRYPTO_AUTH straight to 3 and never
   * computes the digits at all (okcore.cpp:7567-7573): ANY single press
   * confirms. `confirm` is therefore handed `isAnswered()` so a caller
   * pressing on the user\'s behalf can stop after the device has answered,
   * instead of leaving two stray presses behind.
   *
   * @param {number|string} slotId  101..116
   * @param {number} keyType        keys.KEY_TYPE.MLKEM768 or .XWING - the
   *                                SLOT table, not okconnect\'s; see the note
   *                                above KEY_TYPE, where 5 means two things
   * @returns {Promise<Uint8Array>} the public key, 1184 or 1216 bytes
   */
  async function generateKey(slotId, keyType, {
    confirm = null,
    duo = false,
    timeoutMs = 60000,
    settleMs = 60,
    /*
     * WAIT FOR THE BUS TO GO QUIET FIRST, and this is not politeness.
     *
     * This collector takes consecutive 64-byte reports and cannot tell one
     * from another - there is no length, no tag and no terminator anywhere in
     * a public key. So ANY reply still arriving from an earlier request is
     * read as the beginning of this one.
     *
     * Measured on the soft key, and it is not a rare race. A host GUI that
     * refreshes its slot list when the device unlocks sends OKGETSLOTLABELS,
     * which answers with twelve reports shaped `[index, 0x7c, label...]`.
     * Generating a key straight after unlocking put those twelve into this
     * collector: the first one (`01 7c "band-a"`) started the key, `answered`
     * went true, and the caller - which uses that to stop pressing early when
     * the device only wants one press - pressed ONE button of a three-button
     * challenge. The generation then never happened, and sixty seconds later
     * the timeout blamed the user for not pressing buttons they had been told
     * to stop pressing.
     *
     * Waiting for a gap costs a few hundred milliseconds before an operation
     * that takes a human several seconds to confirm.
     */
    quietMs = 250,
    quietTimeoutMs = 5000,
  } = {}) {
    const slot = typeof slotId === 'number' ? slotId : slots.slotNumber(slotId, currentType());

    /*
     * Bounded here rather than at the device, because the device does not
     * bound it: okcrypto.cpp has no else for a slot past 116, so the request
     * produces no answer and no error at all - just a timeout the caller has
     * to guess the meaning of.
     */
    if (!(slot >= 101 && slot <= 116)) {
      throw new Error(
        `a post-quantum key lives in slot 101..116; ${slot} is not one of them`,
      );
    }

    const bytes = deviceKeys.PUBLIC_KEY_BYTES[keyType];
    if (!bytes) {
      const names = deviceKeys.GENERATED_KEY_TYPES
        .map((t) => `${t.name} (${t.type})`).join(', ');
      throw new Error(
        `the device can only generate ${names}; key type ${keyType} is not one of them`,
      );
    }

    const frame = okmsg.build({
      msg: MSG.OKSETPRIV, slot, field: keyType, payload: GENERATE_TRIGGER,
    });

    /* The nine bytes the firmware hashes - see the note above. */
    const challenged = new Uint8Array(1 + GENERATE_TRIGGER.length);
    challenged[0] = keyType;
    challenged.set(GENERATE_TRIGGER, 1);
    const digits = challengeDigits(challenged, { duo });

    let answered = false;
    let started = false;
    let off = null;
    const collected = [];
    let got = 0;

    /*
     * NOTHING SENT BEFORE OUR REQUEST CAN BE OUR ANSWER.
     *
     * Subscribing before the write is not optional - the device can answer
     * inside it - but it also picks up whatever was still arriving from the
     * PREVIOUS operation, and this collector cannot tell one 64-byte report
     * from another. Measured on the soft key: a label listing was still
     * streaming when a generation was triggered, its first report
     * (`01 7c "band-a"`) was taken as the first 64 bytes of the key, and the
     * caller was told the device had already answered - so it pressed ONE
     * button of a three-button challenge, and the generation that never
     * happened timed out sixty seconds later blaming the user for not
     * pressing. See ok-rn/FINDING-a-collector-ate-the-previous-replys-reports.md.
     *
     * A timestamp rather than a drain: draining guesses how long the bus
     * needs to go quiet, and this needs no guess at all.
     */
    let sent = false;

    const answer = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (off) off();
        reject(new Error(
          `slot ${slot} produced no key within ${timeoutMs}ms; the challenge `
          + `was ${digits.join('-')} - were those buttons pressed?`,
        ));
      }, timeoutMs);

      off = transport.on('report', (event) => {
        if (event.iface !== IFACE.VENDOR) return;
        if (!sent) return;
        if (!started) {
          const state = okmsg.parseState(event.data);
          if (state.state === 'unlocked' || state.state === 'locked'
              || state.state === 'uninitialized' || state.state === 'bootloader') return;
          if (state.state === 'error') {
            clearTimeout(timer);
            answered = true;
            if (off) off();
            reject(okmsg.deviceError(state.raw));
            return;
          }
          started = true;
        }
        answered = true;
        collected.push(Uint8Array.from(event.data));
        got += event.data.length;
        if (got < bytes) return;
        clearTimeout(timer);
        if (off) off();
        const out = new Uint8Array(got);
        let at = 0;
        for (const c of collected) { out.set(c, at); at += c.length; }
        resolve(out.slice(0, bytes));
      });
    });

    if (quietMs > 0) await busQuiet(quietMs, quietTimeoutMs);

    await transport.write(IFACE.VENDOR, frame);
    sent = true;
    events.emit('challenge', { slot, digits });
    progress('generateKey', { slot, keyType, digits });

    let key;
    try {
      if (confirm) await confirm({ digits, slot, isAnswered: () => answered });
      key = await answer;
    } catch (err) {
      if (off) off();
      throw err;
    }
    if (settleMs > 0) await new Promise((r) => setTimeout(r, settleMs));
    progress('publicKey', { slot, bytes: key.length });
    return key;
  }

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
     * Run ONE step of the PIN bracket, for a caller driving it by hand.
     *
     * setPin below owns the whole sequence and presses the digits itself,
     * which suits a script. It does not suit a KEYPAD: the device only
     * captures digits while entry is open, and entry is opened and closed by
     * the very messages setPin is sending, so a screen where someone types one
     * digit at a time has to be the thing deciding when each message goes.
     * That is exactly how OnlyKey-App's wizard works - the messages are its
     * steps' enterFn/exitFn, and the person presses the key in between
     * (OnlyKeyWizard.js Step2/Step3).
     *
     * So this exposes a step rather than a second copy of the sequence. It
     * sends what that step sends and waits the way every other step waits.
     *
     * The labels are PIN_SEQUENCE's, in order:
     *
     *   armed       entry is open; press the digits now
     *   entered     (the caller's own presses - nothing to send)
     *   stored      the device takes what was pressed
     *   confirming  entry is open again; press them again
     *   re-entered  (the caller's own presses)
     *   matched     the device compares and commits
     *   committed   nothing left to wait for on the wire
     *
     * @param {string} label one of the labels above
     * @param {object} [opts]
     * @param {string} [opts.kind] 'primary' | 'secondary' | 'selfDestruct'
     * @param {number} [opts.timeoutMs]
     */
    async pinStep(label, { kind = 'primary', timeoutMs = 10000 } = {}) {
      const step = pin.PIN_SEQUENCE.find((entry) => entry.label === label);
      if (!step) {
        throw new Error(
          `unknown PIN step "${label}"; expected ${
            pin.PIN_SEQUENCE.map((entry) => entry.label).join(', ')}`,
        );
      }
      /*
       * A digits step is the CALLER'S to perform - it is the one place the
       * device is waiting for a human - so this does nothing but say so.
       */
      if (step.digits) return {label, waiting: 'digits'};

      if (step.send || step.digits) console_.clear();
      if (step.send) await transport.write(IFACE.VENDOR, pin.pinMessage(kind));
      await waitForStep(step, {timeoutMs});
      progress(step.label, {kind});
      return {label, waiting: null};
    },

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
          /*
           * The tail stays; the DIGITS come out of it. See safeTail.
           *
           * On a DEBUG firmware the last thing the console said during a PIN
           * bracket is the device acknowledging each digit by value, so this
           * message used to carry the PIN that had just been typed - and an
           * Error goes further than a log line does.
           *
           * Removing the tail outright was the first attempt and it was wrong:
           * "timed out" with nothing else is close to undiagnosable from a
           * phone, which is the whole reason it was added. Redacting the acks
           * keeps the diagnosis and drops the secret.
           */
          done(() => reject(new Error(
            `the device did not unlock within ${timeoutMs}ms - the PIN may be wrong, ` +
            'or a previous attempt may still be in its buffer (see clearPinEntry). ' +
            `console tail: ${safeTail(console_.text)}`,
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
         * IN CONFIG MODE NOTHING ANNOUNCES THE UNLOCK, so ask instead.
         *
         * `if (!configmode) hidprint(HW_MODEL(UNLOCKED))` - OnlyKey.ino:707.
         * The device unlocks, stops its INITIALIZED broadcast, turns the LED
         * red and says nothing. Both listeners above go quiet: there is no
         * vendor status to parse and no console line to match.
         *
         * On a DEBUG build the console line existed anyway, so this waited
         * successfully for years without anyone noticing it was waiting on the
         * wrong thing. Built as it ships there is no console at all, and
         * unlocking inside config mode became impossible - which takes loading
         * a key, setting a preference and requesting a firmware update with it,
         * since all three need config mode.
         *
         * So: a positive probe. OKGETLABELS is on the config-mode allowlist
         * (okcore.cpp:347) and answers "Error device locked" until the device
         * is unlocked, so a label read that SUCCEEDS is proof. Silence is not
         * used as evidence either way - it is also what a wedged device
         * produces.
         *
         * Only while this session put the key into config mode. Outside it the
         * announcement arrives and probing would be traffic during PIN entry
         * for no reason.
         *
         * The app's Keys screen already did exactly this, in its own copy
         * (FINDING-config-mode-unlock-is-silent.md). It belongs here, where
         * every GUI gets it rather than each one rediscovering it.
         */
        if (session.configMode) {
          let probing = false;
          const probe = setInterval(async () => {
            if (probing) return;
            probing = true;
            try {
              await device.readLabels({ timeoutMs: 2000 });
              /*
               * Resolved with a marker rather than a status line, because
               * there is no status line to report - the device never sent one.
               * parseStatus reads it as unlocked with no version, which is the
               * truth: in config mode the version is not on offer either.
               */
              done(() => resolve('UNLOCKED'));
            } catch (_) {
              /* Still locked, or busy. Ask again. */
            } finally {
              probing = false;
            }
          }, 1500);
          offs.push(() => clearInterval(probe));
        }

        /*
         * Pressed AFTER both subscriptions are up. The firmware answers within
         * a loop iteration of the last digit, which on an in-process bus is
         * faster than a caller that writes first can start listening.
         */
        Promise.resolve(enter(digits)).catch((err) => done(() => reject(err)));
      });

      /*
       * THE FIRST TIME THIS DEVICE SAYS WHAT IT IS.
       *
       * A locked device answers `INITIALIZED` - no version - and connect()
       * parsed its capabilities from that, i.e. from `version: null`, which
       * every version gate reads as pre-3.0.5. Unlocking is what produces
       * `UNLOCKEDv3.0.5-testc`, and since a device has to be connected before
       * it can be unlocked, this is the ordinary order rather than an unusual
       * one. Handing the status back to the session here is what stops the
       * rest of the session being spoken in an older protocol than the device
       * on the other end - see session.observeStatus() for what that cost.
       */
      if (session.observeStatus) session.observeStatus(seen);

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

    /**
     * Hand back a status string seen somewhere other than connect() or
     * unlock(), so capabilities can be recomputed from it.
     *
     * A LOCKED DEVICE DOES NOT SAY WHAT IT IS - its status is the bare word
     * INITIALIZED - so a session that connected before unlocking has
     * capabilities derived from `version: null`, which reads as the OLDEST
     * firmware. unlock() hands its own status over for exactly this reason.
     *
     * But a GUI need not call unlock() at all. ok-rn watches the device's
     * status broadcasts and drives the keypad itself, so it learns the version
     * on a path the library never sees, and without this it would keep the
     * pre-unlock capabilities for the life of the session - rendering, for
     * one, a settings table describing firmware older than the key in hand.
     *
     * Only ever ADDS information; a status carrying no version is ignored.
     * See session.observeStatus().
     */
    observeStatus(statusText) {
      return session.observeStatus ? session.observeStatus(statusText) : false;
    },

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

    /**
     * Restart the device, through the console. No data is touched.
     *
     * `dbg_run_command()` in okcore.cpp: a line of "8" is CPU_RESTART. It
     * does not return, so there is no acknowledgement to wait for; the key
     * drops off the bus and comes back, and whoever owns the pipe sees that
     * as a disconnect. Only a console that answers (consoleAnswers) will act
     * on it - on any other build this writes into silence, which is what the
     * caller should check first rather than what this should guess.
     *
     * The emulator cannot do this: its firmware thread only exits through the
     * reset trap. On a real key it is the one restart there is short of
     * unplugging.
     */
    /**
     * Reboot the key, which is the ONLY thing that ends config mode.
     *
     * So the flag is cleared here. It is not cleared by connect(): OKCONNECT
     * is one of the eleven messages config mode still answers, and it replies
     * UNLOCKED from inside it exactly as it does outside (okcore.cpp:1362-1367),
     * so a connect proves nothing about the mode either way.
     */
    restart() {
      session.configMode = false;
      return device.press('8');
    },

    /**
     * Wipe the USER data - PIN, profiles, slots - and restart. NOT the firmware.
     *
     * The firmware's "0C" path: the C on the same line is the confirmation,
     * so no arm/confirm state has to be carried between lines and no stray
     * single byte can reach a wipe. This deliberately never sends "9C", the
     * full wipe, which also erases the firmware hash and leaves a key that
     * needs reflashing; nothing above the wire has a reason to want that.
     *
     * Same console requirement as restart(). Written for the bench: a key
     * with a forgotten PIN is a key whose whole path is read-only, and ten
     * wrong attempts is the firmware's own route to the same wipe, one that
     * cannot be told apart from an attack.
     */
    wipeUserspace() {
      /* Wipes and reboots, and a reboot is what ends config mode. */
      session.configMode = false;
      return device.press('0C');
    },

    /* ---- slots --------------------------------------------------------- */

    readLabels(opts = {}) {
      return slots.readLabels(transport, { deviceType: currentType(), ...opts });
    },

    /**
     * The KEY labels: what is loaded in each RSA and ECC slot.
     *
     * A SECOND list, read with the same message and a different slot byte -
     * 'k' rather than nothing (okcore.cpp:387) - and nothing in this library
     * could read it, so a host could load a key and never see that it had.
     * python-onlykey has had it as `getkeylabels` from the beginning
     * (client.py:484-498); the desktop app has no control for it.
     *
     * Twenty rows, one per host key slot: RSA 1-4 then ECC 101-116. A row
     * whose label is '' is a slot with a key and no name; a row whose label
     * is null never answered. Which slots actually HOLD a key is a separate
     * question - `getPublicKey` answers that - because the firmware keeps
     * the label and the key in different places and wiping one used to leave
     * the other (see wipeKey).
     */
    readKeyLabels(opts = {}) {
      return slots.readKeyLabels(transport, opts);
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
          throw okmsg.deviceError(text, write.name);
        }
        applied.push({ name: write.name, response: text, attempts });
        progress('field', { slot, field: write.name, response: text, attempts });
      }

      return applied;
    },

    /* ---- preferences --------------------------------------------------- */

    /** The settable preferences, for a screen that renders itself. */
    preferences() {
      /*
       * THE SAME BYTE MEANS TWO DIFFERENT THINGS, and the version decides
       * which. This used to hand back the static table, so every GUI drew
       * pre-3.0.5 semantics at a 3.0.5 key.
       *
       * Fields 21, 22 and 30 are a BITFIELD before 3.0.5 and a 0/1/2 ENUM at
       * and after it. A screen rendering the old shape offers a toggle that
       * writes 8 - which `set_slot()` refuses outright with "Error invalid
       * user input mode". That is not a hypothetical: writing 8 is what made
       * five derives answer OPERATION_DENIED for a whole session, and the
       * e2e was fixed for it while this table, which the UI reads, was not.
       *
       * Gated rather than replaced, because this app has to keep working
       * against older firmware: below 3.0.5 the bits are still correct and
       * still the only way to reach "derive without a touch".
       *
       * Version UNKNOWN (a locked device reports no version) falls to the
       * legacy shape. That is the safe direction: the bits are refused by
       * 3.0.5 with a message that names the problem, whereas offering the
       * enum to an older key would write bit 0 while the user believed they
       * had chosen "challenge", and nothing would say so.
       */
      const enumModes = Boolean(session.capabilities
        && session.capabilities.userInputModeEnum);

      return Object.entries(PREFERENCES).map(([name, spec]) => {
        const shape = enumModes ? USER_INPUT_ENUM_ROWS[name] : null;
        return shape ? { name, ...spec, ...shape } : { name, ...spec };
      });
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
      /* `min` is 0 for all but touchSense; see its entry for why it exists. */
      const min = spec.min ?? 0;
      if (!Number.isInteger(byte) || byte < min || byte > spec.max) {
        throw new RangeError(
          `${name} must be an integer ${min}..${spec.max}, got ${value}`,
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
      if (/^Error/i.test(text)) throw okmsg.deviceError(text, name);
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
      { onProgress = null, ackTimeoutMs = 8000, ackRetries = 2, label = null } = {}) {
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
        /*
         * ACKNOWLEDGED, like the single-frame path below. The chunked send
         * used to return as soon as the last chunk was written, and the
         * device's answer - "Successfully set RSA Key", or "Error not in
         * config mode" to EVERY chunk - went unread. A composite PQC key
         * cannot be read back (okcrypto_getpubkey has no branch for it), so
         * that answer is the only evidence a load happened; python-onlykey's
         * load_composite_key waits for the same line for the same reason.
         *
         * Subscribed before the first chunk: a refusal arrives after the
         * first one, long before the last is sent.
         */
        let answer = null;
        const off = transport.on('report', (event) => {
          if (event.iface !== IFACE.VENDOR || answer !== null) return;
          if (isSlotAcknowledgement(event.data)) answer = okmsg.text(event.data);
        });
        try {
          await chunker.sendRsaKey({ slot, type, key: bytes, send, onProgress });
          const deadline = Date.now() + ackTimeoutMs;
          while (answer === null && Date.now() < deadline) {
            await new Promise((r) => setTimeout(r, 50));
          }
        } finally {
          off();
        }
        if (answer === null) {
          throw new Error(
            `key write to slot ${slot} was never acknowledged within ${ackTimeoutMs}ms`,
          );
        }
        if (/^Error/i.test(answer)) {
          throw new Error(`key write to slot ${slot} refused: ${answer}`);
        }
        progress('keyAck', { slot, response: answer });
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

      /*
       * NAME IT, optionally, because otherwise nothing ever does.
       *
       * The key label list exists on the device and no client writes to it:
       * python-onlykey can read the names (`getkeylabels`) and never sets
       * one, and the desktop app has no control for either. So every key
       * slot on every OnlyKey is unnamed, and `readKeyLabels` shows twenty
       * blanks - which is correct and useless. The label is a separate
       * OKSETSLOT to the slot's own label index (25..44), gated on config
       * mode like any other, and this is already inside that window.
       *
       * It is written AFTER the key: a name on a slot whose key write
       * failed would be the same lie wipeKey used to leave behind.
       */
      let labelResponse = null;
      const labelIndex = slots.labelIndexForKeySlot(slot);
      if (label !== null && labelIndex !== null) {
        /*
         * Through planSlotWrites, not by hand: a key label is an ordinary
         * slot label at a different index, so it gets the same TEXT
         * encoding and the same sixteen-character cap (EElen_label,
         * okeeprom.h:95) rather than a second implementation of both.
         */
        const [write] = slotConfig.planSlotWrites({ label: String(label) }, labelIndex);
        const reply = await transport.request({
          iface: IFACE.VENDOR,
          data: write.frame,
          timeoutMs: ackTimeoutMs,
          match: isSlotAcknowledgement,
        });
        labelResponse = okmsg.text(reply).trim();
        if (/^Error/i.test(labelResponse)) {
          throw okmsg.deviceError(
            labelResponse, `the key went into slot ${slot} but its name did not`,
          );
        }
      }

      progress('key', { slot, type, bytes: bytes.length, pressFree, label });
      return {
        slot,
        type,
        bytes: bytes.length,
        /** True when this write also made the slot answer without a press. */
        clearedPressRequirement: pressFree,
        /** What the device said about the name, or null when none was given. */
        label: labelResponse,
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

    /**
     * Load an OpenSSH private key into ONE slot, with the roles given.
     *
     * The desktop's Keys panel takes an SSH key through sshpk and then the
     * same slot picker and role checkboxes a raw key gets (OnlyKeyComm.js
     * confirmRsaKeySelect); this is that path with the library's own parser
     * (device/openssh.js) in sshpk's place. Unlike a PGP key there is no
     * convention to assign slots by - an SSH key is one key - so `slot` is
     * required, and the roles default to signature only, which is what an
     * SSH key is for (ssh-agent signs; nothing decrypts with it). An ECC key
     * given a 1-based slot is moved to 101+ by prepareKey, as the raw loader
     * does.
     *
     * @param {string} text  the armoured "BEGIN OPENSSH PRIVATE KEY" block
     * @param {object} opts  {slot, backup, signature, decryption, onProgress}
     * @returns {{slot, type, keyType, comment}}
     */
    async loadSshKey(text, {
      slot, backup = false, signature = true, decryption = false, onProgress = null,
      label = null,
    } = {}) {
      if (slot === undefined || slot === null) throw new Error('loadSshKey needs a slot');
      const parsed = openssh.parsePrivateKey(text);
      const material = deviceKeys.fromSshpk(parsed);
      const prepared = deviceKeys.prepareKey(material, { slot, backup, signature, decryption });
      /*
       * The key file already carries a name - ssh-keygen puts the comment
       * there, usually user@host - so an SSH key names itself unless the
       * caller says otherwise. `label: ''` is how a caller asks for no name
       * at all, which is why the check is for null rather than falsiness.
       *
       * A DERIVED name is TRUNCATED; a chosen one is refused. The device
       * stores sixteen characters and "bmatusiak@desktop-3f2" is a perfectly
       * ordinary comment - failing the key load over the name nobody typed
       * would be the tail wagging the dog. A caller who typed a long name
       * gets told (planSlotWrites throws), because that one they can fix.
       */
      const name = label === null ? String(parsed.comment || '').slice(0, 16) : label;
      const written = await device.loadKey(
        prepared.slot, { type: prepared.type, key: prepared.key },
        { onProgress, label: name || null },
      );
      progress('sshKey', { slot: prepared.slot, keyType: parsed.type, label: name || null });
      return {
        slot: prepared.slot,
        type: prepared.type,
        keyType: parsed.type,
        comment: parsed.comment,
        label: written.label,
      };
    },

    /**
     * Read a slot's PUBLIC key.
     *
     * OKGETPUBKEY was in the message table and called by nothing: the app
     * could write a key and never see what it had written, and the e2e
     * suite built the frame by hand to ask whether a slot was empty.
     * python-onlykey has used it since the beginning (onlykey_hid.py:156,
     * tests/ssh_auth_ed25519.py:48).
     *
     * `bytes` IS NOT OPTIONAL FOR A USABLE ANSWER, and that is the
     * firmware's doing rather than a design choice here.
     * send_transport_response() writes raw 64-byte reports with no length
     * anywhere in them (okcore.cpp:2833-2850), and when the key is shorter
     * than a report it memcpy's only the key and leaves the rest of the
     * buffer as it was. So a 32-byte Ed25519 public key arrives as 32 bytes
     * of key followed by 32 bytes of whatever the device sent last. Omit
     * `bytes` and you get that whole report and have to know where to cut;
     * pass it and you get the key.
     *
     * The lengths, from okcrypto.cpp:
     *   Ed25519, Curve25519    32   (okcrypto.cpp:583)
     *   NIST P-256, secp256k1  64   (okcrypto.cpp:573)
     *   RSA                    128 * type, so 128/256/384/512
     *   ML-KEM-768, X-Wing     their own, and read by their own callers
     *
     * An empty slot is an ERROR, not an empty answer: "Error no ECC Private
     * Key set in this slot" (okcore.cpp:5245), which is how a caller asks
     * whether a slot is free. A slot outside 101-132 answers "Error invalid
     * ECC slot" (okcore.cpp:5229), and a locked device "Error device
     * locked" (okcore.cpp:590) - all of them thrown as they are.
     *
     * IT SETTLES AND IT RESENDS, because a read straight after a read is
     * SOMETIMES never answered.
     *
     * Measured on the bench, 2026-09-11: two probes back to back, and when
     * the first hit an EMPTY slot - which answers with hidprint's error
     * sentence rather than with key bytes - the second timed out in three
     * runs out of four. A 60 ms settle alone did not prevent it. It never
     * happened when the first slot held a key, which is what kept it
     * hidden.
     *
     * Whether this is the dead window
     * ok-rn/FINDING-slot-write-after-a-label-read-is-lost.md describes is
     * NOT established - the shape matches and nothing here traced the
     * firmware far enough to say so. The settle is there because that
     * finding says a read owes one; the resend is there because the settle
     * was not enough. A read is idempotent, so a resend cannot do half a
     * thing, and an unanswered read is unknown rather than failed - the
     * rule sendField and loadKey already follow for writes. Only SILENCE is
     * retried: a refusal, an error and a key all count as answers.
     *
     * AND IT RETRIES A SILENCE, because a read is idempotent and an
     * unanswered one is unknown rather than failed - the same rule
     * `sendField` and `loadKey` follow for writes. The settle alone was not
     * enough: measured on the bench, a read of an EMPTY slot straight after
     * another read of an empty slot went unanswered through a 60 ms pause
     * every time, and answered on the resend. A refusal, an error or a key
     * all count as an answer; only silence is retried.
     *
     * @param {number|string} slotId
     * @param {object} [opts] {bytes, keyType, timeoutMs, settleMs, retries}
     * @returns {Promise<Uint8Array>}
     */
    /**
     * Generate a post-quantum key INSIDE the key - see generateKey() above,
     * where the whole of the reasoning lives.
     *
     * Needs config mode, like any other slot write, and config mode ends only
     * at a restart. It also silences CTAPHID while it lasts, so a session
     * cannot generate a key and then derive anything without restarting in
     * between.
     */
    generateKey,

    async getPublicKey(slotId, opts = {}) {
      const { retries = 1, ...rest } = opts;
      let attempt = 0;
      for (;;) {
        attempt += 1;
        try {
          return await readPublicKey(slotId, rest);
        } catch (err) {
          const silent = /did not answer OKGETPUBKEY/.test(String(err.message));
          if (!silent || attempt > retries) throw err;
          progress('publicKeyRetry', { slot: slotId, attempt });
        }
      }
    },


    /**
     * Erase a key slot. Irreversible; the caller has already confirmed.
     *
     * TWO THINGS, because the firmware keeps a key and its label apart.
     * wipe_private() clears the key material (okcore.cpp:5191-5208) and
     * answers "Successfully wiped ECC Key" or "Successfully wiped RSA
     * Private Key" (:5405, :5516); it does not touch the label, so a wiped
     * slot went on naming a key that was no longer there. python-onlykey
     * blanks the label itself right afterwards (client.py:584-594) and so
     * does this now, through the same OKSETSLOT the label was written with.
     *
     * AND IT WAITS. This wrote one frame and returned, which is the
     * fire-and-forget that cost loadKey a whole debugging session: a wipe
     * that went nowhere was indistinguishable from one that landed, and the
     * caller found out when the slot turned out to be full. The device
     * answers; waiting for it is the difference between "wiped" and "sent".
     *
     * `keepLabel` is for a caller that is wiping in order to rewrite, where
     * blanking the name in between would just flicker.
     *
     * python-onlykey sends this with a payload of '00'. That is not a
     * difference: its send_message APPENDS only what it is given
     * (client.py:305-351), so the byte lands at buffer[6] where a field id
     * would be, and the frame is padded with zeros from there - which is
     * byte for byte the frame okmsg.build produces with neither. Checked
     * rather than assumed, because "Python sends a payload and we do not"
     * reads like a bug.
     */
    async wipeKey(slotId, { timeoutMs = 8000, keepLabel = false } = {}) {
      const slot = typeof slotId === 'number' ? slotId : slots.slotNumber(slotId, currentType());
      const reply = await transport.request({
        iface: IFACE.VENDOR,
        data: okmsg.build({ msg: MSG.OKWIPEPRIV, slot }),
        timeoutMs,
        match: isSlotAcknowledgement,
      });
      const said = okmsg.text(reply).trim();
      if (/^Error/i.test(said)) throw okmsg.deviceError(said, `wipeKey slot ${slot}`);

      let label = null;
      const labelIndex = slots.labelIndexForKeySlot(slot);
      if (!keepLabel && labelIndex !== null) {
        const cleared = await transport.request({
          iface: IFACE.VENDOR,
          data: okmsg.build({
            msg: MSG.OKSETSLOT, slot: labelIndex, field: FIELD.LABEL, payload: [],
          }),
          timeoutMs,
          match: isSlotAcknowledgement,
        });
        label = okmsg.text(cleared).trim();
        if (/^Error/i.test(label)) throw okmsg.deviceError(label, `wipeKey slot ${slot} label`);
      }

      progress('wipeKey', { slot, response: said, label });
      return { slot, response: said, label };
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

    /* ---- firmware update ----------------------------------------------- */

    /**
     * Ask a config-mode key to reboot into its bootloader.
     *
     * The desktop's "kick" (OnlyKeyComm.js submitFirmware): one OKFWUPDATE
     * carrying "1234". The firmware answers "SUCCESSFULL FW LOAD REQUEST,
     * REBOOTING..." and restarts (okcore.cpp:619-626); outside config mode
     * it answers "Error not in config mode", locked "Error device locked",
     * and both are thrown as they are. After the reboot the key
     * re-enumerates as BOOTLOADER; sendFirmware is the next step, and the
     * caller sees the re-enumeration, not this.
     *
     * NOT RUN ON HARDWARE - see src/device/firmware.js. The bench key is a
     * developer build nobody can re-image.
     */
    async requestFirmwareUpdate({ timeoutMs = 8000 } = {}) {
      const reply = await transport.request({
        iface: IFACE.VENDOR,
        data: firmware.kickFrame(),
        timeoutMs,
        match: (r) => {
          const t = okmsg.text(r);
          return firmware.SAYS.REQUESTED.test(t) || firmware.SAYS.ERROR.test(t);
        },
      });
      const text = okmsg.text(reply).trim();
      if (firmware.SAYS.ERROR.test(text)) throw new Error(text);
      progress('firmwareRequest', { said: text });
      return text;
    },

    /**
     * Send a signed firmware file to a key that is in its BOOTLOADER.
     *
     * The desktop's loadFirmware + submitFirmwareData, awaited the way the
     * bootloader talks: "RECEIVED OKFWUPDATE" per 57-byte packet, then
     * "NEXT BLOCK" once a block checks out against the signature chain, and
     * "SUCCESSFULLY LOADED FW" after the last, after which the key boots the
     * new firmware on its own. The block verdict is subscribed BEFORE the
     * block's last packet goes out, for the reason request() exists: the
     * bootloader answers faster than a listener attached afterwards.
     *
     * A refusal or a silence stops the update where it is and says which
     * block and packet; the bootloader keeps waiting, and the desktop's
     * remedy (send the file again from the start) applies.
     *
     * Does NOT check the status itself: the caller has watched the key say
     * BOOTLOADER, and a status request here would be one more frame to a
     * bootloader that expects firmware.
     */
    async sendFirmware(text, {
      onProgress = null, packetTimeoutMs = 8000, blockTimeoutMs = 30000,
    } = {}) {
      const blocks = firmware.parseSignedFirmware(text);
      const isVendorText = (re) => (r) => re.test(okmsg.text(r));

      for (let b = 0; b < blocks.length; b++) {
        const frames = firmware.blockFrames(blocks[b]);
        const lastBlock = b === blocks.length - 1;
        for (let i = 0; i < frames.length; i++) {
          const { frame, final } = frames[i];
          let verdict = null;
          const off = final
            ? transport.on('report', (event) => {
              if (event.iface !== IFACE.VENDOR || verdict !== null) return;
              const t = okmsg.text(event.data).trim();
              if (firmware.SAYS.NEXT_BLOCK.test(t) || firmware.SAYS.LOADED.test(t)
                  || firmware.SAYS.ERROR.test(t)) verdict = t;
            })
            : null;
          try {
            let reply;
            try {
              reply = await transport.request({
                iface: IFACE.VENDOR,
                data: frame,
                timeoutMs: packetTimeoutMs,
                match: (r) => {
                  const t = okmsg.text(r);
                  return firmware.SAYS.RECEIVED.test(t) || firmware.SAYS.ERROR.test(t);
                },
              });
            } catch (e) {
              throw new Error(
                `block ${b + 1} packet ${i + 1} was not acknowledged within ${packetTimeoutMs}ms (${e.message})`,
              );
            }
            const said = okmsg.text(reply).trim();
            if (firmware.SAYS.ERROR.test(said)) {
              throw new Error(`block ${b + 1} packet ${i + 1}: ${said}`);
            }
            if (onProgress) {
              onProgress({ block: b + 1, of: blocks.length, packet: i + 1, packets: frames.length });
            }
            if (final) {
              const deadline = Date.now() + blockTimeoutMs;
              while (verdict === null && Date.now() < deadline) {
                await new Promise((r) => setTimeout(r, 20));
              }
              if (verdict === null) {
                throw new Error(`block ${b + 1} was received but never judged within ${blockTimeoutMs}ms`);
              }
              if (firmware.SAYS.ERROR.test(verdict)) throw new Error(`block ${b + 1}: ${verdict}`);
              const expected = lastBlock ? firmware.SAYS.LOADED : firmware.SAYS.NEXT_BLOCK;
              if (!expected.test(verdict)) {
                throw new Error(`block ${b + 1}: expected ${lastBlock ? 'SUCCESSFULLY LOADED FW' : 'NEXT BLOCK'}, the bootloader said "${verdict}"`);
              }
            }
          } finally {
            if (off) off();
          }
        }
      }
      progress('firmware', { blocks: blocks.length });
      return { blocks: blocks.length };
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
