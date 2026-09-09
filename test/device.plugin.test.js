/*
 * plugins/device - the sequencing layer.
 *
 * plugins/session has authorised a `device` consumer since it was written, and
 * until now none existed outside a stub in app.test.js. These tests drive the
 * real one against a fake firmware that reproduces the two behaviours which
 * make this flow easy to get wrong: OKPIN means something different each time
 * it is sent, and digits are acknowledged one line each.
 *
 * The PIN sequence here is the one proven on a physical soft key - ok-rn's
 * provision.ts set 1234561 and it survived a restart - so these assert the
 * behaviour that code demonstrated, now driven from pin.PIN_SEQUENCE.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const Rectify = require('@bmatusiak/rectify');
const hostPlugin = require('../plugins/host');
const embedded = require('../plugins/transport/embedded');
const sessionPlugin = require('../plugins/session');
const devicePlugin = require('../plugins/device');
const { fakeFirmware } = require('./helpers/fake-firmware');
const { IFACE } = require('../src/transport/contract');
const { MSG } = require('../src/protocol/msg');
const { toLatin1 } = require('../src/bytes');

const PIN = '1234561';

function start(pipe) {
  const plugins = [hostPlugin, embedded, sessionPlugin, devicePlugin];
  plugins.config = { transport: { pipe } };
  return new Promise((resolve, reject) => {
    const app = Rectify.build(plugins, (err, started) => {
      if (err) reject(err);
      else resolve(started);
    });
    app.start();
  });
}

/* ------------------------------------------------------------ composition */

test('device is a service, and session still is not', async () => {
  // The whole point of setup.allowed: device may consume the session key, and
  // nothing else may even see it in the registry.
  const app = await start(fakeFirmware());
  assert.equal(typeof app.services.device.setPin, 'function');
  assert.equal('session' in app.services, false, 'the session stays restricted');
  await app.destroy();
});

/* -------------------------------------------------------------------- PIN */

test('setPin walks the full six-step bracket', async () => {
  const pipe = fakeFirmware();
  const app = await start(pipe);

  const steps = [];
  app.services.device.on('progress', (e) => steps.push(e.step));

  await app.services.device.setPin(PIN);

  assert.deepEqual(steps, [
    'armed', 'entered', 'stored', 'confirming', 're-entered', 'committed',
  ]);
  await app.destroy();
});

test('the bracket sends OKPIN exactly four times', async () => {
  /*
   * Four sends, two digit bursts. The firmware treats the id as a toggle, so
   * a fifth send does not error - it opens entry again, and the next step
   * waits for a prompt that will never come.
   */
  const pipe = fakeFirmware();
  const app = await start(pipe);

  await app.services.device.setPin(PIN);

  assert.equal(pipe.pinStep, 4);
  const vendorWrites = pipe.writes.filter((w) => w.iface === IFACE.VENDOR);
  assert.equal(vendorWrites.length, 4);
  for (const write of vendorWrites) {
    assert.equal(write.data[4], MSG.OKPIN, 'every one is the same message id');
  }
  await app.destroy();
});

test('the PIN goes out as ONE line on the debug interface', async () => {
  /*
   * Not one write per digit. The firmware queues presses and replays them one
   * per loop() iteration; splitting the burst is how the next message lands in
   * the middle of it and the device sees a short PIN.
   */
  const pipe = fakeFirmware();
  const app = await start(pipe);

  await app.services.device.setPin(PIN);

  const seremu = pipe.writes.filter((w) => w.iface === IFACE.SEREMU);
  assert.equal(seremu.length, 2, 'one burst to enter, one to confirm');
  assert.equal(toLatin1(seremu[0].data), `${PIN}\n`);
  await app.destroy();
});

test('it waits for EVERY digit acknowledgement, not the first', async () => {
  /*
   * The regression this guards is subtle: with a first-match wait the sequence
   * continues while acks are still arriving, the next OKPIN lands mid-burst,
   * and the device registers fewer digits than were sent. It surfaces as
   * "PINs don't match" between two PINs that were typed identically.
   *
   * Asserted by counting what the device printed before the next message went
   * out.
   */
  const pipe = fakeFirmware();
  const app = await start(pipe);

  let acksAtStore = null;
  app.services.device.on('progress', (e) => {
    if (e.step === 'entered') {
      acksAtStore = (app.services.device.console.text.match(/password appended with/g) || []).length;
    }
  });

  await app.services.device.setPin(PIN);

  assert.equal(acksAtStore, PIN.length, 'all seven acks were consumed first');
  await app.destroy();
});

test('a PIN the device rejects surfaces the device its own words', async () => {
  // The wording is what the user is shown and what a caller matches on, so it
  // is passed through rather than paraphrased.
  const pipe = fakeFirmware({ pinFailAt: 1 });
  const app = await start(pipe);

  await assert.rejects(
    () => app.services.device.setPin(PIN),
    /Error PIN is not between 7 - 10 digits/,
  );
  await app.destroy();
});

test('a mismatch on the final step is reported, not swallowed', async () => {
  const pipe = fakeFirmware({ pinFailAt: 3, pinError: "Error PINs Don't Match" });
  const app = await start(pipe);

  await assert.rejects(() => app.services.device.setPin(PIN), /PINs Don't Match/);
  await app.destroy();
});

test('an invalid PIN never reaches the device', async () => {
  // Validated before the first write: opening PIN entry and then failing
  // leaves the device armed, waiting for digits nobody will send.
  const pipe = fakeFirmware();
  const app = await start(pipe);

  await assert.rejects(() => app.services.device.setPin('123'), /7-10 digits/);
  await assert.rejects(() => app.services.device.setPin('1234567'.replace('7', '9')), /button numbers/);
  assert.equal(pipe.writes.length, 0, 'nothing was sent');
  await app.destroy();
});

test('a device that goes silent times out with the console tail in the message', async () => {
  // A bare "timed out" against a device that printed an unexpected line is
  // very hard to diagnose from a phone.
  const pipe = fakeFirmware({ ackDigits: false });
  const app = await start(pipe);

  await assert.rejects(
    () => app.services.device.setPin(PIN, { timeoutMs: 80 }),
    /timed out .* console tail:/s,
  );
  await app.destroy();
});

/* ----------------------------------------------------------------- labels */

test('reading labels discards the priming response', async () => {
  /*
   * The device sends one message before the list proper. Counting it as a
   * label drops slot 1 and shifts every subsequent one - the labels all look
   * present, just attached to the wrong slots, which is far worse than an
   * error.
   */
  const pipe = fakeFirmware({ labels: ['first', 'second', 'third'] });
  const app = await start(pipe);

  const { labels, complete } = await app.services.device.readLabels();

  assert.equal(complete, true);
  assert.equal(labels[0], 'first', 'slot 1 is the FIRST label, not the priming message');
  assert.equal(labels[1], 'second');
  assert.equal(labels.length, 12);
  await app.destroy();
});

test('a lost terminal message times out instead of hanging forever', async () => {
  // No existing client has a deadline here; a dropped final label hangs the
  // caller with no error at all.
  const pipe = fakeFirmware({ dropTerminal: true });
  const app = await start(pipe);

  await assert.rejects(
    () => app.services.device.readLabels({ timeoutMs: 60 }),
    /label read timed out after 60ms/,
  );
  await app.destroy();
});

test('a timed-out label read still reports what did arrive', async () => {
  const pipe = fakeFirmware({ dropTerminal: true });
  const app = await start(pipe);

  const err = await app.services.device.readLabels({ timeoutMs: 60 }).catch((e) => e);
  assert.equal(err.partial.labels[0], 'slot1', 'partial results, not nothing');
  assert.equal(err.partial.complete, false);
  await app.destroy();
});

/* ------------------------------------------------------------ slot config */

test('every field write is awaited, not fired and forgotten', async () => {
  /*
   * The defect this replaces: the original's callback reports only whether the
   * HID write succeeded, plus a fixed 100 ms sleep. A device-side error is
   * discarded AFTER the form field has been cleared, so the user is shown
   * success over a slot that is wrong.
   */
  const pipe = fakeFirmware();
  const app = await start(pipe);

  const applied = await app.services.device.setSlot(1, {
    label: 'GitHub',
    username: 'someone',
    password: 'hunter2',
  });

  assert.equal(applied.length, 3);
  for (const one of applied) {
    assert.match(one.response, /^Successfully/, 'each write was acknowledged');
  }
  await app.destroy();
});

test('a device error on one field aborts the rest', async () => {
  const pipe = fakeFirmware({ slotError: 'Error MFA already enabled on this slot, device PIN required' });
  const app = await start(pipe);

  await assert.rejects(
    () => app.services.device.setSlot(1, { label: 'a', password: 'b' }),
    /label: Error MFA already enabled/,
  );

  const setSlots = pipe.writes.filter((w) => w.data[4] === MSG.OKSETSLOT);
  assert.equal(setSlots.length, 1, 'it stopped at the failing field');
  await app.destroy();
});

test('an invalid field means NOTHING is sent, not a half-written slot', async () => {
  /*
   * The plan is built before the first write, so a bad tenth field fails with
   * the slot untouched. The original validates as it goes and stops mid-way,
   * leaving the slot partly configured with no way to tell how far it got.
   */
  const pipe = fakeFirmware();
  const app = await start(pipe);

  await assert.rejects(
    () => app.services.device.setSlot(1, { label: 'ok', typeSpeed: '' }),
    /must be a byte 0-255/,
  );
  assert.equal(pipe.writes.length, 0, 'not even the valid first field went out');
  await app.destroy();
});

test('a slot id is resolved through the device type', async () => {
  const pipe = fakeFirmware();
  const app = await start(pipe);

  await app.services.device.setSlot('3b', { label: 'x' });

  const write = pipe.writes.find((w) => w.data[4] === MSG.OKSETSLOT);
  assert.equal(write.data[5], 9, "classic '3b' is slot 9");
  await app.destroy();
});

test('a silent device times out rather than reporting success', async () => {
  const pipe = fakeFirmware({ slotSilent: true });
  const app = await start(pipe);

  await assert.rejects(
    () => app.services.device.setSlot(1, { label: 'x' }, { timeoutMs: 60 }),
    /no reply on interface 2/,
  );
  await app.destroy();
});

test('wiping a whole slot omits the field byte', async () => {
  const pipe = fakeFirmware();
  const app = await start(pipe);

  await app.services.device.wipeSlot(2);

  const wipe = pipe.writes.find((w) => w.data[4] === MSG.OKWIPESLOT);
  assert.equal(wipe.data[5], 2);
  assert.equal(wipe.data[6], 0, 'no field byte - that is what makes it whole-slot');
  await app.destroy();
});

test('slot numbering follows the device type', async () => {
  const app = await start(fakeFirmware());
  const { device } = app.services;

  assert.equal(device.slotNumber('3a'), 3);
  assert.equal(device.slotNumber('3b'), 9, 'classic is a +0/+6 split');

  device.setDeviceType('duo');
  assert.equal(device.slotNumber('3b'), 6, 'DUO interleaves within bands of three');
  assert.throws(() => device.setDeviceType('nope'), /unknown device type/);

  await app.destroy();
});

/* -------------------------------------------------------------- lifecycle */

test('destroy detaches the console from the transport', async () => {
  const pipe = fakeFirmware();
  const app = await start(pipe);
  const { device } = app.services;

  await app.destroy();

  device.console.push('after teardown');
  assert.equal(device.console.text, 'after teardown', 'the buffer still works');
  // but nothing is feeding it any more - the transport subscription is gone.
  pipe.deliverText('ignored\n');
  assert.equal(device.console.text, 'after teardown');
});

/* ----------------------------------------------------------------- unlock */

test('unlock enters the PIN and waits for the device to say so', async () => {
  /*
   * Unlocking is not setPin. No message is sent at all: the digits go in as
   * button presses and the firmware evaluates the hash after every one
   * (OnlyKey.ino:697), so there is no submit and nothing to acknowledge until
   * it matches.
   */
  const pipe = fakeFirmware({ pin: PIN });
  const app = await start(pipe);

  assert.equal(pipe.unlocked, false, 'starts locked');
  const status = await app.services.device.unlock(PIN);

  assert.match(status, /UNLOCKED/);
  assert.equal(pipe.unlocked, true);
  await app.destroy();
});

test('unlock sends NO vendor message, unlike setPin', async () => {
  const pipe = fakeFirmware({ pin: PIN });
  const app = await start(pipe);

  await app.services.device.unlock(PIN);

  assert.equal(
    pipe.writes.filter((w) => w.iface === IFACE.VENDOR).length,
    0,
    'the whole exchange is button presses',
  );
  await app.destroy();
});

test('a locked device refuses a label read, and unlocking fixes it', async () => {
  /*
   * The reason unlock had to exist before anything else could be trusted:
   * okcore.cpp guards its dispatch on `unlocked == true` and answers
   * "Error device locked" otherwise. Every device-management call written so
   * far would have failed this way against a real device.
   */
  const pipe = fakeFirmware({ pin: PIN, labels: ['github', 'email'] });
  const app = await start(pipe);

  await assert.rejects(() => app.services.device.readLabels({ timeoutMs: 500 }), /locked/i);

  await app.services.device.unlock(PIN);
  const { labels } = await app.services.device.readLabels();
  assert.equal(labels[0], 'github');

  await app.destroy();
});

test('a wrong PIN times out, and says both things it could mean', async () => {
  // There is no rejection message to wait for - a wrong digit is appended and
  // the device stays quiet - so a timeout is the only signal there is.
  const pipe = fakeFirmware({ pin: PIN });
  const app = await start(pipe);

  await assert.rejects(
    () => app.services.device.unlock('6543216', { timeoutMs: 80 }),
    /PIN may be wrong.*previous attempt/s,
  );
  await app.destroy();
});

test('a failed attempt poisons the next one until it is cleared', async () => {
  /*
   * The firmware does not reset its buffer on a wrong PIN; the digits stay and
   * the next attempt APPENDS. So a second try with the CORRECT PIN also fails,
   * which is a genuinely confusing thing to debug from a phone. The way out is
   * the device's own long-press gesture.
   */
  const pipe = fakeFirmware({ pin: PIN });
  const app = await start(pipe);
  const { device } = app.services;

  await assert.rejects(() => device.unlock('6543216', { timeoutMs: 60 }), /did not unlock/);

  // The correct PIN now lands after the failed digits, so it still fails.
  await assert.rejects(() => device.unlock(PIN, { timeoutMs: 60 }), /did not unlock/);

  await device.clearPinEntry();
  assert.match(await device.unlock(PIN), /UNLOCKED/, 'cleared, so it takes');
  await app.destroy();
});

test('an invalid PIN never reaches the device', async () => {
  const pipe = fakeFirmware({ pin: PIN });
  const app = await start(pipe);

  await assert.rejects(() => app.services.device.unlock('12'), /7-10 digits/);
  assert.equal(pipe.writes.length, 0);
  await app.destroy();
});

test('a status broadcast is not mistaken for a slot acknowledgement', async () => {
  /*
   * Measured on the device: a locked OnlyKey runs
   * Task taskInitialized(1000, sendInitialized) (OnlyKey.ino:213) and
   * broadcasts its status once a second. A request() that takes the next
   * report therefore races that timer, and a slot write came back acknowledged
   * "INITIALIZED".
   */
  const pipe = fakeFirmware();
  const app = await start(pipe);

  // A broadcast lands between the write and the real answer.
  const original = pipe.write.bind(pipe);
  pipe.write = async (iface, bytes) => {
    if (iface === IFACE.VENDOR && bytes[4] === MSG.OKSETSLOT) {
      pipe.deliverText('');
      const status = new Uint8Array(64);
      const text = 'INITIALIZED';
      for (let i = 0; i < text.length; i++) status[i] = text.charCodeAt(i);
      pipe.deliver(status);
    }
    return original(iface, bytes);
  };

  const [applied] = await app.services.device.setSlot(1, { label: 'x' });
  assert.match(applied.response, /^Successfully/, 'the broadcast was skipped');
  await app.destroy();
});

test('an error IS an answer, and is not filtered out as chatter', async () => {
  // "Error device locked" is the device refusing clearly. Treating it as
  // chatter turns that into a silent timeout - the same defect the label
  // reader had when it discarded its first response.
  const pipe = fakeFirmware({ slotError: 'Error device locked' });
  const app = await start(pipe);

  await assert.rejects(
    () => app.services.device.setSlot(1, { label: 'x' }, { timeoutMs: 800 }),
    /Error device locked/,
  );
  await app.destroy();
});

test('a host can enter the digits itself instead of using the debug console', async () => {
  /*
   * pressLine writes the PIN as TEXT to the DEBUG console, which is a stand-in
   * for a finger and exists only on a debug build
   * (FINDING-provisioning-needs-a-debug-build.md). A host that can press the
   * device's own buttons - the emulator, a soft key - is doing the real thing,
   * and should not be forced through a debug channel to do it.
   *
   * The bracket is unchanged either way: the firmware appends whatever arrives
   * while entry is open, and does not care which way it got there.
   */
  const pipe = fakeFirmware();
  const app = await start(pipe);

  const pressed = [];
  await app.services.device.setPin(PIN, {
    enterDigits: async (digits) => {
      pressed.push(digits);
      /* Stand in for the acks the firmware prints per digit. */
      pipe.ackPresses(digits);
    },
  });

  assert.deepEqual(pressed, [PIN, PIN], 'entered once, confirmed once');
  assert.equal(
    pipe.writes.filter((w) => w.iface === IFACE.SEREMU).length, 0,
    'nothing went to the debug console',
  );
  assert.equal(
    pipe.writes.filter((w) => w.iface === IFACE.VENDOR).length, 4,
    'the four-message bracket is unchanged',
  );
  await app.destroy();
});

test('the derived-key challenge mode accepts the bit that matters', async () => {
  /*
   * It was capped at 1, so value 8 - bit 3, the one the firmware tests before
   * it will derive a per-site key without a touch - was rejected by our own
   * validation before it ever reached the device
   * (FINDING-a-preference-bit-masquerades-as-an-unsupported-feature.md).
   *
   * The firmware's setter takes the raw byte with no range check
   * (okcore.cpp:2021), so a cap here was ours alone.
   */
  const pipe = fakeFirmware();
  const app = await start(pipe);
  const device = app.services.device;

  const spec = device.preferences().find((p) => p.name === 'derivedChallengeMode');
  assert.ok(spec, 'the preference is still in the table');
  assert.ok(spec.max >= 8, `max is ${spec.max}, which cannot express bit 3`);
  assert.ok(spec.bits && spec.bits[3], 'the bits are named, not left as a number');

  await assert.doesNotReject(() => device.setPreference('derivedChallengeMode', 8));

  /* And it is still bounded - a byte is a byte. */
  await assert.rejects(
    () => device.setPreference('derivedChallengeMode', 256),
    RangeError,
  );
  await app.destroy();
});

/* --------------------------------------------------------------- identity */

/*
 * These are the tests that would have caught "deviceType defaults to CLASSIC
 * and nothing ever sets it". The failure that bug produced was not an error -
 * readLabels stopped at 12 of 24 slots and setSlot wrote to the wrong one, both
 * in silence - so nothing short of asserting the detection catches it.
 */

test('the device type is detected from what the device says, not defaulted', async () => {
  const app = await start(fakeFirmware({ version: 'v3.0.4-prodp' }));
  await app.services.device.connect();

  assert.equal(app.services.device.deviceType, 'duo');
  assert.equal(app.services.device.detectedType, 'duo');
  await app.destroy();
});

test('a Classic is detected as one', async () => {
  const app = await start(fakeFirmware({ version: 'v3.0.4-prodc' }));
  await app.services.device.connect();
  assert.equal(app.services.device.deviceType, 'classic');
  await app.destroy();
});

test('connect reports the identity and the capabilities it implies', async () => {
  const app = await start(fakeFirmware({ version: 'v3.0.4-prodp' }));
  const result = await app.services.device.connect();

  assert.equal(result.identity.model, 'duo');
  assert.equal(result.identity.build, 'production');
  assert.equal(result.capabilities.slots, 24);
  assert.equal(result.capabilities.buttons, 3);
  assert.equal(result.capabilities.challengeFormula, 'duo');

  // And the same is readable from the service afterwards.
  assert.equal(app.services.device.capabilities.slots, 24);
  await app.destroy();
});

test('a production build is reported as having no console', async () => {
  /*
   * The library's PIN provisioning waits on prompts the serial console prints,
   * and a production build has no console to print them. Until the build was
   * detectable there was no way to know before the wait timed out.
   */
  const app = await start(fakeFirmware({ version: 'v3.0.4-prodc' }));
  await app.services.device.connect();
  assert.equal(app.services.device.capabilities.debugConsole, false);
  await app.destroy();
});

test('a debug build is reported as having one', async () => {
  const app = await start(fakeFirmware({ version: 'v3.0.4-testc' }));
  await app.services.device.connect();
  assert.equal(app.services.device.capabilities.debugConsole, true);
  await app.destroy();
});

test('setDeviceType still wins, and null gives detection back', async () => {
  const app = await start(fakeFirmware({ version: 'v3.0.4-prodp' }));
  await app.services.device.connect();
  assert.equal(app.services.device.deviceType, 'duo');

  app.services.device.setDeviceType('classic');
  assert.equal(app.services.device.deviceType, 'classic', 'a caller who insists wins');
  assert.equal(app.services.device.detectedType, 'duo', 'and detection is not forgotten');

  app.services.device.setDeviceType(null);
  assert.equal(app.services.device.deviceType, 'duo');
  await app.destroy();
});

test('an unrecognised device type is still refused', async () => {
  const app = await start(fakeFirmware());
  assert.throws(() => app.services.device.setDeviceType('quantum'), /unknown device type/);
  await app.destroy();
});

/* ------------------------------------------- the HMAC write's side effect */

test('writing an HMAC key reports that it cleared the press requirement', async () => {
  /*
   * The device does not say so. process_setreport() recomputes
   * hmac_challengemode on the success path (okcore.cpp:7703-7715) so the slot
   * just written no longer needs a button, and acknowledges the write exactly
   * as it acknowledges any other. Afterwards anything that can reach the
   * keyboard interface gets HMAC-SHA1 responses with no physical presence.
   *
   * So the library says it instead. A caller may still ignore it, but it is
   * ignoring something stated rather than never being told. See
   * onlykey-testing/FINDING-hmac-press-free-on-write.md.
   */
  const app = await start(fakeFirmware());
  const key = new Uint8Array(20).fill(7);

  const events = [];
  app.services.device.on('progress', (e) => events.push(e));

  const result = await app.services.device.loadKey(130, { type: 1, key });
  assert.equal(result.clearedPressRequirement, true);

  const warned = events.find((e) => e.step === 'warning');
  assert.ok(warned, 'no warning was emitted');
  assert.equal(warned.slot, 130);
  assert.match(warned.detail, /button-press/);

  await app.destroy();
});

test('the other HMAC slot behaves the same way', async () => {
  const app = await start(fakeFirmware());
  const result = await app.services.device.loadKey(129, { type: 1, key: new Uint8Array(20) });
  assert.equal(result.clearedPressRequirement, true);
  await app.destroy();
});

test('an ordinary key slot reports no such thing', async () => {
  /*
   * The claim has to be false somewhere, or it says nothing. Slot 1 is an
   * ordinary ECC slot and writing it changes no challenge mode.
   */
  const app = await start(fakeFirmware());
  const events = [];
  app.services.device.on('progress', (e) => events.push(e));

  const result = await app.services.device.loadKey(1, { type: 1, key: new Uint8Array(32) });
  assert.equal(result.clearedPressRequirement, false);
  assert.equal(events.filter((e) => e.step === 'warning').length, 0);

  await app.destroy();
});
