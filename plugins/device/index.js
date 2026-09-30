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
/*
 * The Preferences and Advanced surface - PREFERENCES and the per-firmware
 * row shapes - is data in src/device/preferences.js, exported from the
 * package, so a GUI can read it without composing this plugin, and
 * setPreference validates against the same row preferences() hands out.
 */
const {
  PREFERENCES, ENUM_ONLY_PREFERENCES, preferenceRow, preferenceRows,
} = require('../../src/device/preferences');

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

  /**
   * Is this text one of the device's refusal sentences?
   *
   * okmsg.errorKind() is the one place that knows them, including the three
   * that do not begin with "Error" ("No PIN set...", "Timeout occured...",
   * "Second Profile Mode may only be changed..."). A status broadcast, a
   * success sentence and binary data are all null there.
   */
  function isDeviceRefusal(text) {
    return okmsg.errorKind(text) !== null;
  }

  /**
   * Send a frame the firmware acts on WITHOUT REPLYING, and listen only for a
   * refusal.
   *
   * Some operations succeed in silence - the hidprint is missing or commented
   * out in the firmware (each caller cites its line). Waiting for an
   * acknowledgement there is waiting for nothing: request() times out, and a
   * retrying sender (sendField) spends three timeouts on a device that did
   * exactly what it was asked. What the firmware DOES still say on these
   * paths is why it would not - "Error device locked", "Error not in config
   * mode" - and those come back from inside the same recvmsg() call, so a
   * short window after the write catches them.
   *
   * SILENCE IS NOT PROOF. It is the success answer only because the firmware
   * has no other; a frame the key never processed looks the same. So the
   * result says `confirmed: false`, and no retry is attempted - resending a
   * wipe or a restart is not a harmless repeat the way a field store is.
   *
   * Subscribed before the write, as everywhere else here: a refusal can
   * arrive inside the write.
   *
   * @param {Uint8Array} frame
   * @param {object} opts
   * @param {string} opts.name        prefixes a refusal's message
   * @param {number} [opts.windowMs]  how long to listen; 0 returns once the frame is out
   * @returns {Promise<{response: null, confirmed: false}>}
   * @throws okmsg.deviceError on a refusal inside the window
   */
  async function sendUnanswered(frame, { name, windowMs = 500 } = {}) {
    let off = null;
    let timer = null;
    let refusal = null;
    const refused = new Promise((resolve) => {
      off = transport.on('report', (event) => {
        if (event.iface !== IFACE.VENDOR) return;
        const text = okmsg.text(event.data).trim();
        if (!refusal && isDeviceRefusal(text)) {
          refusal = text;
          resolve(text);
        }
      });
    });
    try {
      await transport.write(IFACE.VENDOR, frame);
      if (windowMs > 0 && !refusal) {
        await Promise.race([
          refused,
          new Promise((resolve) => { timer = setTimeout(resolve, windowMs); }),
        ]);
      }
      if (refusal) throw okmsg.deviceError(refusal, name);
      return { response: null, confirmed: false };
    } finally {
      clearTimeout(timer);
      if (off) off();
    }
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
      /*
       * ONLY A CONSOLE THAT HAS SPOKEN IS WAITED ON. The comment above says a
       * release "must not be held up"; the code still waited `timeoutMs` for
       * a console that does not exist, so `committed` cost the full timeout on
       * every release build (OnlyKey-App's LIB-PORT.md, gap 5). Why nothing
       * arrives: release 3.1.0 prints its console "Successfully set PIN" under
       * `#ifdef DEBUG` (okcore.cpp:878, :1150); the wire
       * copy (:888, :1016, :1156) is what `matched` already consumed.
       *
       * A DEBUG build talks on the console all through the commit block -
       * "Both PINs Match" (:841), "Generating NONCE" - before the wire line
       * that ended `matched`, and nothing has cleared the buffer since
       * `matched` sent. So an EMPTY buffer here means no console, and there
       * is nothing to wait for. If a real console merely lags, skipping is
       * still safe: the wire line that ended `matched` is printed after the
       * flash write (:888 follows okcore_flashset_pinhashpublic at :874).
       */
      if (!console_.text) return Promise.resolve();
      return console_.waitFor(advisory, {timeoutMs}).catch(() => {});
    }

    /*
     * THE WAITERS ARE BUILT ONLY HERE, after the advisory case has returned.
     *
     * They used to be built first, for every step - so for `committed` a
     * console waiter was created, then abandoned when the advisory branch
     * returned its own. With no catch attached, that orphan rejected at the
     * timeout wherever the console never answers - a production key, or a
     * Windows host, which will not open the console interface - and Node
     * treats an unhandled rejection as fatal. Measured 2026-09-25 on Windows
     * USB: the PIN was set, and 60 s later the process died with "timed out
     * after 60000ms waiting for /Successfully set PIN/; console tail: """.
     */
    const waits = [
      waitForHid(onWire, {
        /*
         * The step's own refusals, THEN ANY device refusal. Only the named
         * two used to end a step; every other "Error ..." on the wire was
         * ignored and the step waited out `timeoutMs` beside an answer
         * (OnlyKey-App LIB-PORT.md gap 3 - the App raced its own "Error"
         * watcher to get round it). Release 3.1.0's PIN functions print only
         * those two (okcore.cpp:814, :894, :905 and their twins), but a
         * refusal from the dispatcher, another firmware or a stray is still
         * the device saying no, and okmsg.errorKind knows every sentence.
         * The named ones stay first so their text is what the caller gets.
         */
        reject: [
          ...names.map((name) => pin.HID_ERRORS[name]),
          { test: isDeviceRefusal },
        ],
        timeoutMs,
      }),
      console_.waitFor(pin.PROMPTS[step.expect], {
        reject: names.map((name) => pin.ERRORS[name]),
        timeoutMs,
      }),
    ];

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
        /*
         * LISTEN FIRST, THEN WRITE. The vendor reply is not buffered the way
         * the console is, so a key that answers inside the write - a fast
         * one, or the test fake - was answering nobody, and on a host with no
         * readable console nothing else could satisfy the step. The catch
         * only stops a failed write from leaving this rejecting unobserved;
         * the await below still throws.
         */
        const answered = waitForStep(step, { timeoutMs });
        answered.catch(() => {});
        await transport.write(IFACE.VENDOR, message);
        await answered;
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

  /**
   * One OKGETPUBKEY read. `getPublicKey` wraps this with the retry.
   *
   * @param {number|string} slotId
   * @param {object} [opts] {bytes, keyType, payload, timeoutMs, settleMs}
   *   payload: bytes after the key type - agent derivation's 32-byte
   *   identity hash (slots 132/232); a stored slot takes none.
   */
  async function readPublicKey(slotId, { bytes = 0, keyType = 0, payload = undefined, timeoutMs = 8000, settleMs = 60 } = {}) {
    const slot = typeof slotId === 'number' ? slotId : slots.slotNumber(slotId, currentType());
    const frame = okmsg.build({ msg: MSG.OKGETPUBKEY, slot, field: keyType, payload });

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
    /* Handled from birth: the key can refuse before the write below returns
     * (replies do arrive first, over BLE especially), and a rejection with no
     * handler for a turn ends the process - see okcrypto's `answer`. */
    answer.catch(() => {});

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
   * ## No button challenge - the firmware dropped it
   *
   * This used to model a three-button confirmation: the first request primed
   * a challenge over `[keytype, FF x8]`, and the third press replayed it. That
   * gate lived in 0c-coder's development tree until libraries 97f0149
   * (2026-09-22, "stop gating PQC keygen"), which removed it: OKSETPRIV only
   * arrives in config mode or on first use (okcore.cpp dispatches it on
   * `configmode == true || !initcheck`), both already presence proofs, and ECC
   * keygen never asked for more. Every tree with PQC keygen worth supporting
   * has 97f0149 - the bench key (b412e78), 3.0.5 (57340df) and release 3.1.0
   * (eb25290, read at ecc_priv_flash: "No confirmation, as for ECC keygen") -
   * and no signed release has PQC keygen at all.
   *
   * So the device answers the ONE request with the key, and nothing is shown
   * or pressed. That matters beyond wording: a caller pressing "the challenge"
   * on the user's behalf until the device answered would, on an unlocked key,
   * type slot contents at the keyboard with every press that raced the
   * answer. `confirm`, `duo` and `formula` are still accepted, so existing
   * callers keep working, and are ignored; no `challenge` event is emitted.
   *
   * The frame is still sent ONCE: a second trigger would generate a second
   * key over the first.
   *
   * @param {number|string} slotId  101..116
   * @param {number} keyType        keys.KEY_TYPE.MLKEM768 or .XWING - the
   *                                SLOT table, not okconnect\'s; see the note
   *                                above KEY_TYPE, where 5 means two things
   * @returns {Promise<Uint8Array>} the public key, 1184 or 1216 bytes
   */
  async function generateKey(slotId, keyType, {
    /* confirm, duo, formula: accepted from older callers and ignored - there is no challenge (see above). */
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
     *
     * The mark is set just BEFORE the write, not after it. With no challenge
     * the device answers as soon as it has generated, and a fast one (the
     * emulator) can answer while the write is still being awaited - a mark set
     * after it dropped the key's first reports. Earlier replies are kept out
     * by the quiet-bus wait, which comes first.
     */
    let sent = false;

    const answer = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (off) off();
        reject(new Error(
          `slot ${slot} produced no key within ${timeoutMs}ms - generation needs `
          + 'config mode (or first use); is the key in it?',
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
            if (off) off();
            reject(okmsg.deviceError(state.raw));
            return;
          }
          started = true;
        }
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
    /* Handled from birth: the key can refuse before the write below returns
     * (replies do arrive first, over BLE especially), and a rejection with no
     * handler for a turn ends the process - see okcrypto's `answer`. */
    answer.catch(() => {});

    if (quietMs > 0) await busQuiet(quietMs, quietTimeoutMs);

    sent = true;
    await transport.write(IFACE.VENDOR, frame);
    progress('generateKey', { slot, keyType });

    let key;
    try {
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
      /* Listening before the write, as in runPinSequence - see there. */
      const answered = waitForStep(step, {timeoutMs});
      answered.catch(() => {});
      if (step.send) await transport.write(IFACE.VENDOR, pin.pinMessage(kind));
      await answered;
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
     *
     * ## Which report is the answer
     *
     * It took the FIRST report, and on a locked DUO that is often the status
     * broadcast rather than the answer (OnlyKey-App LIB-PORT.md gap 6). How a
     * locked DUO answers, from release 3.1.0: the PIN is read ONLY inside the
     * once-a-second broadcast task, sendInitialized (OnlyKey.ino:1275-1292;
     * the main loop does not call recvmsg while locked, :478). The tick that
     * reads it tries the PIN and then says
     *
     *   UNLOCKED<version>   the PIN was right (:1288) - the answer
     *   "Error password attempts ... exceeded"   (:1444) - the answer
     *   nothing             the PIN was wrong
     *
     * and every LATER tick says INITIALIZED-D (:1291). So INITIALIZED-D is two
     * different things: a tick that ran before the PIN reached the key (not
     * the answer - it says nothing about the attempt), or the first tick
     * after a wrong PIN (the only "no" a wrong PIN ever gets, and what the
     * App shows its incorrect-PIN dialog on, OnlyKeyComm.js sendPin_DUO).
     *
     * They are told apart by WHEN, because the firmware gives nothing else:
     * the tick that consumes the PIN runs within one period of it arriving,
     * so a broadcast from before it reaches the host at most a USB latency
     * after the write, and a broadcast after a wrong PIN comes a whole period
     * (1000 ms, OnlyKey.ino:217) after the consuming tick. A locked broadcast
     * inside `broadcastWindowMs` of the write is skipped; one after it is the
     * answer. UNLOCKED is never skipped on an unlock - it IS the success.
     *
     * SETTING PINs (`set`) is answered from recvmsg by okcore_quick_setup's
     * SETUP_MANUAL path: "Successfully set PIN" (okcore.cpp:888) or a
     * refusal. No status line is ever that answer, so all of them are
     * skipped, as readPublicKey does.
     *
     * The reply is RETURNED, refusal or not, as before: the App reads the
     * attempts-exceeded sentence off it to show its own dialog.
     */
    async duoPin(pins, { set = false, timeoutMs = 6000, broadcastWindowMs = 500 } = {}) {
      const sentAt = Date.now();
      const reply = await transport.request({
        iface: IFACE.VENDOR,
        data: pin.duoPinMessage(pins, { set }),
        timeoutMs,
        match: (report) => {
          const { state } = okmsg.parseState(report);
          if (state === 'error') return true;
          if (set) {
            return !(state === 'unlocked' || state === 'locked'
              || state === 'uninitialized' || state === 'bootloader');
          }
          if (state === 'unlocked') return true;
          if (state === 'locked') return Date.now() - sentAt >= broadcastWindowMs;
          return !(state === 'uninitialized' || state === 'bootloader');
        },
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
      return preferenceRows(session.capabilities);
    },

    /**
     * One preference: OKSETSLOT on the global slot with a single byte.
     *
     * Goes through the same retrying send as a slot field, for the same
     * reason - an unacknowledged write is unknown, not failed.
     *
     * EXCEPT a `silent` row (secProfileMode), which the firmware never
     * acknowledges: it is sent once, `refusalWindowMs` is spent listening for
     * a refusal, and the result carries `confirmed: false`.
     */
    async setPreference(name, value, { timeoutMs = 10000, retries = 2, refusalWindowMs = 500 } = {}) {
      /*
       * VALIDATED AGAINST THE ROW THIS FIRMWARE HAS, not the static table.
       *
       * It used to read PREFERENCES[name].max - the pre-3.0.5 limit - while
       * preferences() handed the screen the version-shaped row. So a 3.0.5+
       * key drew field 21 as Challenge/Press and still let 2..255 through
       * here, bitmask 8 included, for the firmware to refuse ("Error invalid
       * user input mode"). The same function now shapes both (G-4). Unknown
       * capabilities give the legacy row, as preferences() does: the enum
       * firmware refuses a stray bitmask by name, whereas capping an older
       * key at 1 would make its bit 3 unreachable.
       */
      const spec = preferenceRow(name, session.capabilities);
      if (!spec) {
        throw new Error(
          `unknown preference "${name}"; known: ${Object.keys(PREFERENCES).join(', ')}`,
        );
      }
      /*
       * Refused HERE on a key known to predate 3.0.5, because the firmware
       * would not refuse it at all - it would say nothing, and the retries
       * below would spend their whole budget on that silence. An unknown
       * version is let through: hiding the row is a display choice, but a
       * caller that writes anyway may know something this session does not.
       */
      if (ENUM_ONLY_PREFERENCES.has(name)
          && session.identity && session.identity.version
          && !(session.capabilities && session.capabilities.userInputModeEnum)) {
        throw new Error(
          `${name} needs firmware 3.1.0 or later; ${session.identity.version} ` +
          'has no such field and would not answer the write',
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
      if (spec.silent) {
        /* See the row's note: no acknowledgement exists, so none is awaited. */
        await sendUnanswered(frame, { name, windowMs: refusalWindowMs });
        progress('preference', { name, value: byte, response: null, attempts: 1 });
        return { name, value: byte, response: null, attempts: 1, confirmed: false };
      }
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

      /*
       * The device's own sentence ("Successfully set ECC Key"), RETURNED -
       * it used to go only to a `keyAck` progress event, so every caller that
       * wanted to show it (the CLI prints it, as python does) subscribed to
       * progress around the call to catch it.
       */
      let response = null;
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
          throw okmsg.deviceError(answer, `key write to slot ${slot} refused`);
        }
        progress('keyAck', { slot, response: answer });
        response = answer;
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
          throw okmsg.deviceError(text, `key write to slot ${slot} refused`);
        }
        if (text) progress('keyAck', { slot, response: text });
        response = text;
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
        /** What the device said about the key ("Successfully set ECC Key"). */
        response,
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

    /**
     * Wipe the DEVICE-GLOBAL Yubico credential - setYubiAuth's undo.
     *
     * OKWIPESLOT on the global slot, field YUBIAUTH: the firmware zeroes the
     * AES key, private id and public id (okcore.cpp:2012-2019, wipe_slot's
     * `value == 10 && slot == 0` branch) and PRINTS NOTHING - that branch has
     * no hidprint, unlike every per-slot wipe below it. wipeSlot(0, 'yubikey')
     * builds the same frame but waits for "Successfully ..." and so times out
     * on a wipe that happened; the App's old code waited for "wiped AES Key",
     * which no release has ever sent. So this does not wait for an answer,
     * only for a refusal (see sendUnanswered): the dispatcher still says why
     * it would not - "Error OnlyKey must be initialized first", or "Error
     * device locked" (okcore.cpp:405-413), which is also what a key still on
     * first use gets, since that branch requires FTFL_FSEC == 0x44.
     *
     * @param {object} [opts]
     * @param {number} [opts.refusalWindowMs] 0 returns as soon as the frame is out
     * @returns {Promise<{slot: number, response: null, confirmed: false}>}
     */
    async wipeYubiAuth({ refusalWindowMs = 500 } = {}) {
      const frame = okmsg.build({
        msg: MSG.OKWIPESLOT,
        slot: slots.GLOBAL_SLOT,
        field: FIELD.YUBIAUTH,
      });
      const result = await sendUnanswered(frame, { name: 'wipeYubiAuth', windowMs: refusalWindowMs });
      progress('wipeYubiAuth', { slot: slots.GLOBAL_SLOT, confirmed: false });
      return { slot: slots.GLOBAL_SLOT, ...result };
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
     * Restore a backup file to the device.
     *
     * VERIFIED BEFORE A SINGLE BYTE GOES OUT. Verifying after the first packet
     * is not verifying - it is finding out halfway through, with the device
     * already holding part of a file it cannot finish.
     *
     * ## A file with no digest is not a file that failed
     *
     * The rolling digest arrived in firmware v2.1.2
     * (`capabilities().backupDigest`). A backup written by v2.1.1, v2.1.0 or
     * v0.2-beta.8 has no `--<base64>` line at all, so verifyBackup() reports
     * `{ok: false, reason: 'no digest line found'}` - which is the truth about
     * the FILE, not a fault in it.
     *
     * This used to throw "backup failed verification" for that case, so the
     * library could not restore any backup from those releases and told the
     * holder their file was bad. That is the population restore exists for: an
     * old key that has died, whose owner has one armoured text file and no
     * other way back.
     *
     * So the two cases are separated rather than the check dropped:
     *
     *   digest present and WRONG  -> refuse, always, unchanged
     *   no digest line at all     -> refuse by DEFAULT and say why, and take
     *                                `unverifiable: true` from a caller who
     *                                knows the backup predates the chain
     *
     * The opt-in is deliberately not a boolean nobody reads: an unverifiable
     * restore cannot be checked by anything, on either side, so it is a
     * decision a person makes once and not a default a program drifts into.
     *
     * @param {string} text the armoured backup file
     * @param {object} [opts]
     * @param {boolean} [opts.unverifiable=false] allow a backup that carries no
     *   digest line - pre-v2.1.2 firmware only. Has no effect on a file whose
     *   digest is present and wrong.
     */
    async restore(text, { onProgress = null, unverifiable = false } = {}) {
      const check = parsers.verifyBackup(text);
      if (!check.ok) {
        const noDigest = check.reason === 'no digest line found';
        if (!noDigest) {
          throw new Error(
            `backup failed verification (${check.reason || 'digest mismatch'}): ` +
            `expected ${check.expected}, computed ${check.digest}`,
          );
        }
        if (!unverifiable) {
          throw new Error(
            'this backup carries no digest line, so it cannot be verified: the '
            + 'rolling digest arrived in firmware v2.1.2 and this file predates '
            + 'it. The file is not damaged - there is simply nothing to check '
            + 'it against. Pass { unverifiable: true } to restore it anyway.',
          );
        }
        progress('restore', { unverifiable: true });
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
     * Restart the key with an EMPTY restore - the restart a release build has.
     *
     * restart() goes through the debug console, which no release has. The
     * desktop wizard's Exit on the restore step ("Reboot Requested",
     * OnlyKeyWizard.js:458) restarts the key another way, and this is it
     * named: ONE OKRESTORE frame whose length byte and data are all zero.
     *
     * What the firmware does with it (RESTORE, okcore.cpp:6477 at release
     * 3.1.0): [5] is not 0xFF, so it is a LAST packet; it copies 0 bytes, the
     * running offset is still 0, and `if (offset == 0) CPU_RESTART();`
     * (:6535-6536). Nothing is decrypted, nothing written.
     *
     * The App sends exactly these 64 bytes, though not on purpose: it passes
     * "000000000" (nine characters) to submitRestoreData, whose header is
     * (9/2).toString(16) = "4.8", and hexStrToDec("4.8") is NaN, which a
     * Uint8Array stores as 0 (OnlyKeyComm.js submitRestore, submitRestoreData,
     * hexStrToDec). The zero header is what makes it a restart; a header of
     * 4 would have been a 4-byte "backup" going on to decrypt.
     *
     * WHEN IT RESTARTS, AND WHEN IT DOES NOT:
     *   - only where a restore is allowed: config mode, or first use
     *     (okcore.cpp:516). Elsewhere the dispatcher refuses - "Error not in
     *     config mode", "Error device locked", "No PIN set, You must set a
     *     PIN first" - and that refusal is thrown.
     *   - not on a non-STD build or an unencrypted profile: RESTORE is
     *     compiled out / returns (:518-521, :6478) and the frame is dropped
     *     in silence. Silence is also what success looks like, so this
     *     cannot tell those apart.
     *   - not after a restore was part-sent this boot: `offset` is static,
     *     so the empty last packet would FINISH that restore instead. Only a
     *     restart clears it.
     *
     * A restart acknowledges nothing (CPU_RESTART does not return); the key
     * drops off the bus and comes back, which whoever owns the pipe sees as a
     * disconnect. A restart is the one thing that ends config mode, so the
     * session's flag is cleared when no refusal came.
     *
     * @param {object} [opts]
     * @param {number} [opts.refusalWindowMs] 0 returns as soon as the frame is out
     * @returns {Promise<{response: null, confirmed: false}>}
     */
    async restartByRestore({ refusalWindowMs = 500 } = {}) {
      const frame = okmsg.build({ msg: MSG.OKRESTORE, slot: 0 });
      const result = await sendUnanswered(frame, { name: 'restartByRestore', windowMs: refusalWindowMs });
      session.configMode = false;
      progress('restartByRestore', { confirmed: false });
      return result;
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
     *
     * `timeoutMs` IS AN INACTIVITY TIMEOUT: how long to wait with NO keystroke
     * arriving - before the first one, or between any two - not a limit on
     * the whole capture. It was a fixed deadline, and a real backup outran it:
     * the app passes 120 s, and a key with its slots full, typing at ~12
     * characters a second, was cut off mid-file while still typing (found by
     * the bench owner, 2026-09-25). Restarted on every keyboard report, it
     * still catches a device that has stopped - that is what it is for - but
     * never a slow one that is still going.
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

        let timer = null;
        const arm = () => {
          clearTimeout(timer);
          timer = setTimeout(() => {
            const text = decoder.text;
            finish(reject, Object.assign(
              new Error(
                `backup capture timed out: no keystrokes for ${timeoutMs}ms, ` +
                `with ${text.length} characters and no end marker`,
              ),
              { partial: text },
            ));
          }, timeoutMs);
        };
        arm();

        const offKeys = transport.on('keyboard', (event) => {
          arm();   /* still typing - see "INACTIVITY TIMEOUT" above */
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

    /**
     * Wipe a slot, and collect EVERY answer the device gives.
     *
     * ## The device answers once per field, and the count is not fixed
     *
     * wipe_slot() hidprint()s one "Successfully wiped ..." per field it
     * erases - ten on v2.1.2 through 3.1.0 (Label, URL, Additional
     * Characters, Delay 1, Username, Delay 2, Password, Delay 3, 2FA Type,
     * 2FA Key; okcore.cpp wipe_slot at c8804e3 and 8d28305), eleven on
     * v2.1.0-2.1.1. This used to resolve on the first and return it: the
     * other nine were left on the bus for whatever read next, and a caller
     * had no way to see that the wipe finished. python-onlykey had the same
     * bug (it read eight) and fixed it in e6d261c by the rule used here:
     * wait for the first answer, then read until the device goes quiet.
     *
     * Quiet rather than a count, because the count moves between firmware
     * lines and nothing on the wire announces it.
     *
     * ## `field` does not narrow the wipe on the firmware
     *
     * wipe_slot() reads the field byte only for slot 0 value 10 (the Yubico
     * key, see wipeYubiAuth). For slots 1-24 it erases every field whatever
     * the byte says - so a caller naming one field still gets the whole slot
     * wiped, and the replies say so. Kept in the signature because the frame
     * carries it and callers pass it; the replies are the truth.
     *
     * Resolves `{ slot, response, responses }` - `response` the first answer
     * (what this returned as a bare string before), `responses` all of them.
     * A refusal throws okmsg.deviceError, so `err.deviceText` is the device's
     * sentence.
     */
    async wipeSlot(slotId, field = null, { timeoutMs = 3000, quietMs = 500 } = {}) {
      const slot = typeof slotId === 'number' ? slotId : slots.slotNumber(slotId, currentType());
      const responses = [];
      let off = null;
      let timer = null;
      const collected = new Promise((resolve, reject) => {
        const finish = (settle, value) => {
          clearTimeout(timer);
          if (off) off();
          settle(value);
        };
        /* The first wait is the caller's timeout; each answer then re-arms the quiet window. */
        const arm = (ms) => {
          clearTimeout(timer);
          timer = setTimeout(() => (responses.length
            ? finish(resolve, responses)
            : finish(reject, new Error(`slot ${slot} wipe was never acknowledged within ${timeoutMs}ms`))), ms);
        };
        /* Subscribed BEFORE the write, as transport.request() does. */
        off = transport.on('report', (event) => {
          if (event.iface !== IFACE.VENDOR || !isSlotAcknowledgement(event.data)) return;
          const text = okmsg.text(event.data).trim();
          if (/^Error/i.test(text)) {
            finish(reject, okmsg.deviceError(text));
            return;
          }
          responses.push(text);
          arm(quietMs);
        });
        arm(timeoutMs);
      });
      /*
       * Handled from birth, awaited below: a refusal that lands while the
       * write is still in flight must not be an unhandled rejection (2152942).
       */
      collected.catch(() => {});
      try {
        await transport.write(IFACE.VENDOR, slotConfig.wipeMessage(slot, field));
      } catch (err) {
        clearTimeout(timer);
        if (off) off();
        throw err;
      }
      const all = await collected;
      return { slot, response: all[0], responses: all.slice() };
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
