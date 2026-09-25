/*
 * plugins/device - preferences, keys, backup and restore.
 *
 * These wrap modules that were finished and tested but that nothing called:
 * chunker, parsers, keys. The tests here are about the WRAPPING - the frame
 * that goes on the wire, the validation that happens before it does, and the
 * one case where nothing should go on the wire at all.
 *
 * The most important test in the file is the one that asserts a tampered
 * backup sends NOTHING. Verifying after the first packet is out is not
 * verifying; it is finding out halfway through a restore.
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
const { fakePipe } = require('./helpers/fake-pipe');
const { IFACE } = require('../src/transport/contract');
const { MSG, FIELD } = require('../src/protocol/msg');
const parsers = require('../src/device/parsers');
const keys = require('../src/device/keys');
const { LAYOUTS } = require('../src/device/keylayouts.data');
const { sha256 } = require('@noble/hashes/sha2.js');
const { concat, toBase64 } = require('../src/bytes');

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

/** Only the vendor frames, which is what every assertion here is about. */
const vendor = (pipe) => pipe.writes.filter((w) => w.iface === IFACE.VENDOR);

/* --------------------------------------------------------------- backups */

/**
 * A backup file with a correct digest chain.
 *
 * Built rather than pasted, because the digest is a CHAIN - each line hashed
 * together with the running digest - and a fixture with a hand-copied digest
 * would only ever test that one byte string. Building it means the tampering
 * test below can change one line and know the digest no longer matches.
 */
function makeBackup(chunks) {
  const lines = [];
  let digest = new Uint8Array(32);
  /* Indexed, not looked up by value - two identical chunks are legal and
   * indexOf would hash the first one twice. */
  for (const chunk of chunks) {
    const bytes = Uint8Array.from(chunk);
    lines.push(toBase64(bytes));
    digest = sha256(concat([digest, bytes]));
  }
  return [
    parsers.BACKUP_BEGIN,
    ...lines,
    `--${toBase64(digest)}`,
    parsers.BACKUP_END,
  ].join('\n');
}

/** Text as the firmware types it: one press report, one release, per character. */
function typeText(text) {
  const spec = LAYOUTS.USA_ENGLISH;
  const reports = [];
  for (const ch of text) {
    const code = ch.charCodeAt(0);
    if (ch === '\n') {
      reports.push([0, 0, 0x28, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0]);
      continue;
    }
    const keycode = spec.ascii[code - 0x20];
    if (!keycode) continue;
    const usage = keycode & 0x3f;
    const mod = spec.shiftMask && (keycode & spec.shiftMask) ? 0x02 : 0;
    reports.push([mod, 0, usage, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0]);
  }
  return reports;
}

/* ------------------------------------------------------------ key labels */

test('readKeyLabels reads the OTHER label list, the one nothing could read', async () => {
  /*
   * OKGETLABELS with slot byte 'k' runs get_key_labels() instead of
   * get_slot_labels() (okcore.cpp:387). The rows arrive at their own label
   * indices - 25..28 for RSA 1..4, 29..44 for ECC 101..116 - and this test
   * pins that mapping, because getting it wrong names the wrong slot rather
   * than failing.
   */
  const pipe = fakeFirmware({
    keyLabels: { 25: 'signing rsa', 29: 'ssh', 44: 'the last one' },
  });
  const app = await start(pipe);

  const { keys, complete } = await app.services.device.readKeyLabels();
  assert.equal(complete, true);
  assert.equal(keys.length, 20);

  const bySlot = Object.fromEntries(keys.map((k) => [k.slot, k]));
  assert.equal(bySlot[1].label, 'signing rsa');
  assert.equal(bySlot[1].kind, 'rsa');
  assert.equal(bySlot[101].label, 'ssh');
  assert.equal(bySlot[101].kind, 'ecc');
  assert.equal(bySlot[116].label, 'the last one');
  /* A slot with no label is '' - it answered, it just has no name. */
  assert.equal(bySlot[102].label, '');

  const frames = vendor(pipe);
  assert.equal(frames[0].data[4], MSG.OKGETLABELS);
  assert.equal(frames[0].data[5], 0x6b, "the slot byte is 'k'");

  await app.destroy();
});

test('a locked device is silent here, and the timeout says so', async () => {
  /*
   * The same measurement readLabels records: the firmware source has an
   * `else { hidprint("Error device locked"); }` that does not reach the
   * wire, so from a host "locked" and "not listening" look identical unless
   * the status broadcast is noticed.
   */
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);
  const status = new Uint8Array(64);
  'INITIALIZED'.split('').forEach((c, i) => { status[i] = c.charCodeAt(0); });
  const ticker = setInterval(() => pipe.deliver(status), 20);

  await assert.rejects(
    () => app.services.device.readKeyLabels({ timeoutMs: 200 }),
    /LOCKED device does with this message/,
  );

  clearInterval(ticker);
  await app.destroy();
});

test('a key can be named as it is written, and an over-long name is refused', async () => {
  /*
   * Nothing has ever written a key label: python-onlykey can read them and
   * never sets one, and the desktop app has no control for either - so
   * every key slot on every device is blank, and a list of names is
   * correct and useless. The name is a separate OKSETSLOT to the slot's own
   * label index, sent AFTER the key, because a name on a slot whose key
   * write failed is the same lie wipeKey used to leave behind.
   */
  const pipe = fakeFirmware();
  const app = await start(pipe);
  const { device } = app.services;

  const result = await device.loadKey(101, { type: 1, key: new Uint8Array(32) }, { label: 'ssh key' });
  assert.match(result.label, /^Success/i);

  const frames = vendor(pipe);
  assert.equal(frames.length, 2, 'the key and then its name');
  assert.equal(frames[0].data[4], MSG.OKSETPRIV);
  assert.equal(frames[1].data[4], MSG.OKSETSLOT);
  assert.equal(frames[1].data[5], 29, 'ECC slot 101 keeps its label at index 29');
  assert.equal(frames[1].data[6], FIELD.LABEL);
  assert.equal(String.fromCharCode(...frames[1].data.slice(7, 14)), 'ssh key');

  /* No name given is no second frame at all. */
  pipe.writes.length = 0;
  const plain = await device.loadKey(101, { type: 1, key: new Uint8Array(32) });
  assert.equal(plain.label, null);
  assert.equal(vendor(pipe).length, 1);

  /* The device stores sixteen characters; a longer one is refused, not cut. */
  await assert.rejects(
    () => device.loadKey(101, { type: 1, key: new Uint8Array(32) }, { label: 'x'.repeat(17) }),
    /the device stores 16/,
  );

  await app.destroy();
});

/* ------------------------------------------------------------- wipe a key */

test('wipeKey waits for the device, and blanks the label the key left behind', async () => {
  /*
   * The firmware keeps a key and its label apart: wipe_private() clears the
   * key material and answers, and never touches the label - so a wiped slot
   * went on naming a key that was gone. python-onlykey blanks it right
   * afterwards (client.py:584-594); the two frames are asserted here in
   * order, with the label index the second one has to carry.
   */
  const pipe = fakeFirmware();
  const app = await start(pipe);

  const result = await app.services.device.wipeKey(101);
  assert.match(result.response, /^Success/i);

  const frames = vendor(pipe);
  assert.equal(frames.length, 2, 'a wipe is the key AND its label');
  assert.equal(frames[0].data[4], MSG.OKWIPEPRIV);
  assert.equal(frames[0].data[5], 101);
  assert.equal(frames[1].data[4], MSG.OKSETSLOT);
  assert.equal(frames[1].data[5], 29, 'ECC slot 101 keeps its label at index 29');
  assert.equal(frames[1].data[6], FIELD.LABEL);

  await app.destroy();
});

test('wipeKey on an RSA slot uses that ranges label index, and keepLabel sends one frame', async () => {
  const pipe = fakeFirmware();
  const app = await start(pipe);

  await app.services.device.wipeKey(1);
  assert.equal(vendor(pipe)[1].data[5], 25, 'RSA slot 1 keeps its label at index 25');

  pipe.writes.length = 0;
  await app.services.device.wipeKey(102, { keepLabel: true });
  assert.equal(vendor(pipe).length, 1, 'keepLabel leaves the name alone');

  await app.destroy();
});

test('a refused wipe throws instead of reporting success', async () => {
  /*
   * The whole point of waiting. This used to write one frame and return, so
   * a wipe the device refused was indistinguishable from one it did.
   */
  const pipe = fakeFirmware({ slotError: 'Error device locked' });
  const app = await start(pipe);
  await assert.rejects(
    () => app.services.device.wipeKey(101),
    /wipeKey slot 101: Error device locked/,
  );
  await app.destroy();
});

/* ------------------------------------------------------------ public keys */

test('getPublicKey reads a slot, and the length has to be asked for', async () => {
  /*
   * The firmware sends raw 64-byte reports with no length in them
   * (okcore.cpp:2833-2850) and memcpy's only the key, leaving the rest of
   * the buffer as it was. A 32-byte Ed25519 key therefore arrives with 32
   * bytes of something else behind it - so the fixture puts a recognisable
   * pattern there and the test proves `bytes` is what cuts it off.
   */
  const key = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
  const app = await start(fakeFirmware({ pubKeys: { 101: key } }));
  const { device } = app.services;

  assert.deepEqual([...await device.getPublicKey(101, { bytes: 32 })], [...key]);

  /* Without it, the whole report comes back and the caller has to know. */
  const raw = await device.getPublicKey(101);
  assert.equal(raw.length, 64);
  assert.deepEqual([...raw.slice(0, 32)], [...key]);

  await app.destroy();
});

test('an RSA public key is collected across reports', async () => {
  const modulus = Uint8Array.from({ length: 256 }, (_, i) => i & 0xff);
  const app = await start(fakeFirmware({ pubKeys: { 1: modulus } }));

  const got = await app.services.device.getPublicKey(1, { bytes: 256 });
  assert.equal(got.length, 256);
  assert.deepEqual([...got], [...modulus]);

  await app.destroy();
});

test('an empty slot is an error with the firmware own words, not an empty answer', async () => {
  /*
   * This is how a caller asks whether a slot is free, so the sentence is
   * the answer and must not be flattened into a null.
   */
  const app = await start(fakeFirmware({ pubKeys: {} }));
  await assert.rejects(
    () => app.services.device.getPublicKey(101, { bytes: 32 }),
    /no ECC Private Key set in this slot/,
  );
  await app.destroy();
});

test('OKGETPUBKEY goes out as one frame naming the slot', async () => {
  const pipe = fakeFirmware({ pubKeys: { 102: new Uint8Array(64) } });
  const app = await start(pipe);

  await app.services.device.getPublicKey(102, { bytes: 64 });
  const frames = vendor(pipe);
  assert.equal(frames.length, 1);
  assert.equal(frames[0].data[4], MSG.OKGETPUBKEY);
  assert.equal(frames[0].data[5], 102);
  /*
   * buffer[6] must be 0 for an RSA slot - okcrypto.cpp:274 dispatches on
   * `buffer[5] < 5 && !buffer[6]` - so the default keyType is 0 and not
   * something helpful-looking.
   */
  assert.equal(frames[0].data[6], 0);

  await app.destroy();
});

/* ----------------------------------------------------------- preferences */

test('preferences() describes the whole settings surface', async () => {
  const app = await start(fakeFirmware());
  const prefs = app.services.device.preferences();

  const names = prefs.map((p) => p.name);
  assert.ok(names.includes('lockout'));
  assert.ok(names.includes('keyboardLayout'));
  assert.ok(names.includes('modKeyMode'));
  assert.ok(prefs.every((p) => Number.isInteger(p.field) && Number.isInteger(p.max)));

  await app.destroy();
});

test('the user-input fields change SHAPE at 3.0.5, and the table follows', async () => {
  /*
   * THE SAME BYTE, READ TWO WAYS, and nothing on the wire says which.
   *
   * Before 3.0.5 field 21 is a bitmask whose BIT 3 (value 8) is the only way
   * to get a derive without a touch. From 3.0.5 it is a 0/1/2 enum and
   * set_slot() refuses anything above USER_INPUT_NONE with "Error invalid
   * user input mode" - so a screen still drawing the old shape offers a
   * toggle that writes 8 and is refused.
   *
   * That is not hypothetical. Writing 8 is what made five derives answer
   * OPERATION_DENIED for a whole session; the e2e was fixed for it and this
   * table, which the UI renders from, was not.
   */
  const app = await start(fakeFirmware({ version: 'v3.0.5-testc' }));
  const device = app.services.device;
  await device.connect();

  const byName = Object.fromEntries(device.preferences().map((p) => [p.name, p]));

  assert.equal(byName.derivedChallengeMode.max, 1,
    'field 21 still accepts 255, so the screen can still offer the refused 8');
  assert.equal(byName.derivedChallengeMode.bits, undefined,
    'the legacy bit toggles survived the overlay - a spread leaves untouched '
    + 'keys in place, so `bits` has to be cleared rather than omitted');
  assert.deepEqual(Object.keys(byName.derivedChallengeMode.choices), ['0', '1']);

  /* 22 gains named choices where it had a bare number box. */
  assert.deepEqual(Object.keys(byName.storedChallengeMode.choices), ['0', '1']);

  /* "No confirmation" is field 30's alone - 21 and 22 refuse it. */
  assert.deepEqual(Object.keys(byName.webAgentDeriveMode.choices), ['0', '1', '2']);
  assert.ok(!('2' in byName.derivedChallengeMode.choices),
    'offering "no confirmation" on field 21 offers an error the user cannot act on');

  await app.destroy();
});

test('an older key keeps the bitmask, because there the bits are correct', async () => {
  /*
   * THE OTHER HALF, and the half that makes it a gate rather than a rewrite.
   * This app has to keep working against older firmware, where bit 3 is not a
   * legacy curiosity - it is the only way to reach a touch-free derive at all.
   */
  const app = await start(fakeFirmware({ version: 'v3.0.4-prodc' }));
  const device = app.services.device;
  await device.connect();

  const p = Object.fromEntries(device.preferences().map((x) => [x.name, x]));

  assert.equal(p.derivedChallengeMode.max, 255);
  assert.deepEqual(Object.keys(p.derivedChallengeMode.bits), ['0', '3']);
  assert.equal(p.derivedChallengeMode.choices, undefined,
    'an older key was offered the enum, which would write bit 0 while the '
    + 'user believed they had chosen "challenge"');

  await app.destroy();
});

test('an unknown version falls to the legacy shape, which fails loudly', async () => {
  /*
   * A LOCKED DEVICE REPORTS NO VERSION (see session.observeStatus), so this
   * case is reachable on the ordinary path rather than being a curiosity.
   *
   * Legacy is the safe default: 3.0.5 REFUSES the bits with a message that
   * names the problem, whereas handing the enum to an older key writes bit 0
   * silently while the user believes they chose "challenge".
   */
  const app = await start(fakeFirmware({ pin: '1234561', version: 'v3.0.5-testc' }));
  const device = app.services.device;

  const before = await device.connect();
  assert.equal(before.identity.version, null, 'a locked device named a version');

  const locked = Object.fromEntries(device.preferences().map((x) => [x.name, x]));
  assert.deepEqual(Object.keys(locked.derivedChallengeMode.bits), ['0', '3']);

  /* And it corrects itself the moment the device says what it is. */
  await device.unlock('1234561');
  const after = Object.fromEntries(device.preferences().map((x) => [x.name, x]));
  assert.equal(after.derivedChallengeMode.bits, undefined);
  assert.deepEqual(Object.keys(after.derivedChallengeMode.choices), ['0', '1']);

  await app.destroy();
});

test('fields 30 and 31 are offered only where they exist', async () => {
  /*
   * v3.0.4 has no case 30 or 31 in set_slot() and answers neither - so the
   * rows are absent there, and a write names the version instead of retrying
   * into silence. Both sides, because the bug was offering them everywhere.
   */
  const NEW = ['webAgentDeriveMode', 'webcryptPolicy'];

  const old = await start(fakeFirmware({ version: 'v3.0.4-testc' }));
  await old.services.device.connect();
  const oldNames = old.services.device.preferences().map((p) => p.name);
  for (const n of NEW) assert.ok(!oldNames.includes(n), `${n} offered to v3.0.4`);
  assert.ok(oldNames.includes('derivedChallengeMode'), 'field 21 exists on both');
  await assert.rejects(
    old.services.device.setPreference('webcryptPolicy', 0),
    /needs firmware 3\.0\.5.*v3\.0\.4/,
  );
  await old.destroy();

  const cur = await start(fakeFirmware({ version: 'v3.0.5-testc' }));
  await cur.services.device.connect();
  const curNames = cur.services.device.preferences().map((p) => p.name);
  for (const n of NEW) assert.ok(curNames.includes(n), `${n} missing on v3.0.5`);
  await cur.destroy();
});

test('the table says which writes cannot be taken back', async () => {
  /*
   * WHICH SETTINGS ARE IRREVERSIBLE IS PROTOCOL, so it is described here and
   * not in whichever GUI happens to notice. ok-rn held this list privately for
   * a while; the nw desktop app and the CLI can write all three fields and
   * would each have had to rediscover the hazard.
   *
   * The test names them exhaustively rather than checking "at least these
   * three", so ADDING a one-way field to the table has to come here too. That
   * is the point: the next irreversible setting should not be able to arrive
   * quietly and be adopted by every screen that renders from this table.
   */
  const app = await start(fakeFirmware({ version: 'v3.0.5-testc' }));
  const device = app.services.device;
  await device.connect();

  const oneWay = device.preferences()
    .filter((p) => p.oneWay)
    .map((p) => p.name)
    .sort();

  assert.deepEqual(oneWay, ['backupKeyMode', 'webcryptPolicy', 'wipeMode']);

  /*
   * And every one of them needs config mode, which is not a coincidence worth
   * relying on silently: the firmware gates the dangerous value behind it.
   */
  for (const p of device.preferences().filter((x) => x.oneWay)) {
    assert.equal(p.requires, 'configMode', `${p.name} is one-way but ungated`);
    assert.ok(p.note, `${p.name} is one-way and says nothing about why`);
  }

  await app.destroy();
});

test('the webcrypt policy is a validated bitmask, not a free byte', async () => {
  /*
   * FIELD 31 REJECTS UNDEFINED BITS rather than masking them - the firmware
   * answers "Error invalid webcrypt policy" for anything outside
   * OKWC_VALID_MASK (okcore.cpp:2117). So `max` is the mask, 3, and not the
   * 255 a byte-sized preference would otherwise carry: a screen that offered
   * 0-255 here would be offering values the device refuses.
   *
   * It is also the one preference that is a ONE-WAY LATCH. While unwritten
   * (OKWC_UNSET 0xFF) the disable bit is inherited from legacy field 21 bit 1,
   * and the first write of this byte ends that inheritance permanently. There
   * is nothing to assert about that here - preferences are write-only and the
   * latch is invisible from the host - but the note has to SAY so, because it
   * is the only warning a GUI author will ever get.
   */
  /* A 3.0.5 key, connected: field 31 does not exist on anything older. */
  const app = await start(fakeFirmware({ version: 'v3.0.5-testc' }));
  await app.services.device.connect();
  const byName = Object.fromEntries(
    app.services.device.preferences().map((p) => [p.name, p]),
  );

  const wc = byName.webcryptPolicy;
  assert.ok(wc, 'field 31 is missing from the settings surface');
  assert.equal(wc.field, 31);
  assert.equal(wc.max, 3, 'max must be OKWC_VALID_MASK - undefined bits are refused');
  assert.equal(wc.requires, 'configMode');

  /* Two bits, and each names a separate code path rather than a level. */
  assert.deepEqual(Object.keys(wc.bits).sort(), ['0', '1']);

  assert.match(wc.note, /permanently|once/i,
    'the note is the only place a GUI author learns this write cannot be undone');

  /*
   * The form starts where an UNWRITTEN key is: stored keys allowed. Starting
   * at 0 makes an untouched save turn web PGP off, one-way (0c-coder's
   * OnlyKey-App 146e585 fixed the same thing in its form).
   */
  assert.equal(wc.unwritten, 1, 'an unwritten field 31 allows stored keys (bit 0)');
  assert.match(wc.note, /stored keys \(PGP\) YES/,
    'the note must not claim the unwritten default is "stored keys no"');

  await app.destroy();
});

test('every preference says which gate the firmware puts on it', async () => {
  /*
   * set_slot gates these field by field, and getting it wrong is invisible:
   * a challenge-mode write outside config mode is answered "Error not in
   * config mode", and secProfileMode is refused for ever once setup is done.
   * A settings screen that offered all twelve identically would present four
   * controls that silently do nothing.
   */
  const app = await start(fakeFirmware());
  const byName = Object.fromEntries(
    app.services.device.preferences().map((p) => [p.name, p]),
  );

  assert.equal(byName.lockout.requires, 'always');
  assert.equal(byName.keyboardLayout.requires, 'always');
  assert.equal(byName.storedChallengeMode.requires, 'configMode');
  assert.equal(byName.modKeyMode.requires, 'configMode');
  assert.equal(byName.secProfileMode.requires, 'firstUse');

  /* The two whose rule depends on the VALUE must explain themselves. */
  assert.match(byName.wipeMode.note, /config mode/i);
  assert.match(byName.backupKeyMode.note, /cannot be undone/i);

  const gates = new Set(Object.values(byName).map((p) => p.requires));
  assert.deepEqual([...gates].sort(), ['always', 'configMode', 'firstUse']);

  await app.destroy();
});

test('a preference is OKSETSLOT on the global slot with one byte', async () => {
  const pipe = fakeFirmware();
  const app = await start(pipe);

  const result = await app.services.device.setPreference('lockout', 30);
  assert.match(result.response, /^Success/i);

  const frames = vendor(pipe);
  assert.equal(frames.length, 1, 'one preference is one frame');
  const f = frames[0].data;
  assert.equal(f[4], MSG.OKSETSLOT);
  assert.equal(f[5], 0, 'the global slot is slot 0 (the "XX" the desktop app sends)');
  assert.equal(f[6], FIELD.LOCKOUT);
  assert.equal(f[7], 30);

  await app.destroy();
});

test('touch sensitivity is a real field, with the only floor in the table', async () => {
  /*
   * FIELD 28. The table copied from the desktop's client said 28 was
   * unassigned; okcore.cpp:2106 writes the touch offset there and accepts
   * only 2..100 ("Error touchsense value out of range"). Both halves are
   * pinned here: the frame that goes out, and the two values every other
   * preference would have let through.
   */
  const pipe = fakeFirmware();
  const app = await start(pipe);
  const { device } = app.services;

  const spec = device.preferences().find((p) => p.name === 'touchSense');
  assert.equal(spec.field, 28);
  assert.equal(spec.min, 2);
  assert.equal(spec.max, 100);
  assert.equal(spec.requires, 'configMode');

  await device.setPreference('touchSense', 50);
  const f = vendor(pipe)[0].data;
  assert.equal(f[6], 28);
  assert.equal(f[7], 50);

  await assert.rejects(() => device.setPreference('touchSense', 1), /must be an integer 2\.\.100/);
  await assert.rejects(() => device.setPreference('touchSense', 101), /must be an integer 2\.\.100/);
  /* 0 is the default floor everywhere else, and is refused here. */
  await assert.rejects(() => device.setPreference('touchSense', 0), /must be an integer 2\.\.100/);

  await app.destroy();
});

test('a preference is validated before anything is sent', async () => {
  const pipe = fakeFirmware();
  const app = await start(pipe);
  const { device } = app.services;

  await assert.rejects(
    () => device.setPreference('lockuot', 30),
    /unknown preference "lockuot"/,
  );
  await assert.rejects(
    () => device.setPreference('lockButton', 9),
    /must be an integer 0\.\.6/,
  );
  /*
   * The point of validating first: a value the firmware would clamp or ignore
   * leaves the app showing a setting the device does not have.
   */
  assert.equal(vendor(pipe).length, 0, 'a rejected preference reached the wire');

  await app.destroy();
});

/* ------------------------------------------------------------------ keys */

test('an ECC key is one frame and an RSA key is chunked', async () => {
  const pipe = fakeFirmware();
  const app = await start(pipe);
  const { device } = app.services;

  await device.loadKey(101, { type: 3, key: new Uint8Array(32).fill(0xab) });
  assert.equal(vendor(pipe).length, 1, 'a 32-byte scalar fits in one report');
  assert.equal(vendor(pipe)[0].data[4], MSG.OKSETPRIV);

  pipe.writes.length = 0;

  /* RSA 2048: p||q is 256 bytes, which is five 57-byte packets. */
  await device.loadKey(1, { type: 2, key: new Uint8Array(256).fill(0xcd) });
  assert.equal(vendor(pipe).length, 5, 'a 256-byte key must be chunked');
  assert.ok(
    vendor(pipe).every((w) => w.data[4] === MSG.OKSETPRIV),
    'every chunk is an OKSETPRIV',
  );

  await app.destroy();
});

test('a backup passphrase is derived here and never sent', async () => {
  const pipe = fakeFirmware();
  const app = await start(pipe);
  const { device } = app.services;

  const phrase = 'correct horse battery staple';
  await device.setBackupPassphrase(phrase);

  const f = vendor(pipe)[0].data;
  assert.equal(f[4], MSG.OKSETPRIV);

  /*
   * THE DERIVED KEY MUST ACTUALLY BE THERE.
   *
   * Asserting only that the passphrase is absent is not enough, and this test
   * proved it: the first version of setBackupPassphrase passed the whole
   * { slot, type, key } object as the payload, which builds an empty body -
   * and an empty body contains no passphrase, so the test passed while the
   * device was being sent thirty-two zero bytes as its backup key.
   */
  const expected = keys.backupKeyFromPassphrase(phrase);
  assert.equal(f[5], expected.slot);
  assert.equal(f[6], expected.type);
  assert.deepEqual(
    Array.from(f.slice(7, 7 + 32)), Array.from(expected.key),
    'the derived key is not in the frame',
  );

  /* And the passphrase itself never leaves. */
  const onWire = Buffer.from(f).toString('latin1');
  assert.equal(onWire.includes(phrase), false, 'the passphrase reached the wire');

  await app.destroy();
});

test('a silently dropped passphrase write is reported, not called success', async () => {
  /*
   * OKSETPRIV is accepted only in config mode or on first use, and the refusal
   * has NO ELSE BRANCH (okcore.cpp:452) - the frame is dropped and the device
   * says nothing at all.
   *
   * Writing without waiting therefore reports success for a passphrase that was
   * never taken, and the user finds out when a backup refuses itself for want
   * of the key they were told had been set. That happened on device before this
   * was awaited.
   */
  const pipe = fakeFirmware({ setPrivSilent: true });
  const app = await start(pipe);

  await assert.rejects(
    () => app.services.device.setBackupPassphrase(
      'correct horse battery staple', { timeoutMs: 300, retries: 0 },
    ),
    /no acknowledgement/,
  );

  await app.destroy();
});

test('a too-short backup passphrase is refused before the derivation', async () => {
  const pipe = fakeFirmware();
  const app = await start(pipe);

  await assert.rejects(() => app.services.device.setBackupPassphrase('short'));
  assert.equal(vendor(pipe).length, 0);

  await app.destroy();
});

/* ------------------------------------------------------------- PGP import */

test('a PGP key is loaded into the signature and decryption slots', async () => {
  const openpgp = require('../src/crypto/pgp');
  const { privateKey } = await openpgp.generateKey({
    type: 'ecc', curve: 'ed25519',
    userIDs: [{ name: 't', email: 't@e.st' }], format: 'object',
  });

  const pipe = fakeFirmware();
  const app = await start(pipe);

  const loaded = await app.services.device.loadPgpKey(privateKey);

  assert.deepEqual(loaded.map((l) => l.role).sort(), ['decryption', 'signature']);

  /* Both are ECC scalars, so both are one frame each and both land in the ECC
   * slot namespace (100 above RSA's). */
  const frames = vendor(pipe);
  assert.equal(frames.length, 2, 'two keys, two frames');
  assert.ok(frames.every((w) => w.data[4] === MSG.OKSETPRIV));
  assert.ok(
    loaded.every((l) => l.slot > keys.ECC_SLOT_OFFSET),
    `ECC keys must use the ECC slots, got ${loaded.map((l) => l.slot).join()}`,
  );

  await app.destroy();
});

test('an unreadable subkey aborts the import with nothing written', async () => {
  /*
   * The roles are positional, so a partially applied import is worse than a
   * failed one: it leaves the device signing with whichever key happened to
   * land in slot 2.
   */
  const openpgp = require('../src/crypto/pgp');
  const { privateKey } = await openpgp.generateKey({
    type: 'ecc', curve: 'ed25519',
    userIDs: [{ name: 't', email: 't@e.st' }], format: 'object',
  });
  privateKey.subkeys[0].keyPacket.publicParams.oid = { oid: [1, 2, 3, 4] };

  const pipe = fakeFirmware();
  const app = await start(pipe);

  await assert.rejects(
    () => app.services.device.loadPgpKey(privateKey),
    /subkey 1: unsupported ECC curve/,
  );
  assert.equal(vendor(pipe).length, 0, 'a key was written before the failure');

  await app.destroy();
});

/* --------------------------------------------------------------- restore */

test('a valid backup is verified and then streamed', async () => {
  const pipe = fakeFirmware();
  const app = await start(pipe);

  const text = makeBackup([[1, 2, 3, 4], [5, 6, 7, 8]]);
  const result = await app.services.device.restore(text);

  assert.equal(result.bytes, 8);
  const frames = vendor(pipe);
  assert.ok(frames.length >= 1, 'nothing was sent');
  assert.ok(
    frames.every((w) => w.data[4] === MSG.OKRESTORE),
    'every frame is an OKRESTORE',
  );

  await app.destroy();
});

test('a tampered backup sends NOTHING', async () => {
  /*
   * The assertion that matters most in this file.
   *
   * The digest is a chain over the lines in order, so this catches a reordering
   * as well as an edit. Verifying after the first packet is out is not
   * verifying - it is finding out halfway through a restore, with the device
   * already holding part of a file it cannot finish.
   */
  const pipe = fakeFirmware();
  const app = await start(pipe);

  const good = makeBackup([[1, 2, 3, 4], [5, 6, 7, 8]]);
  const lines = good.split('\n');
  lines[1] = toBase64(Uint8Array.from([9, 9, 9, 9]));   // one data line changed

  await assert.rejects(
    () => app.services.device.restore(lines.join('\n')),
    /failed verification/,
  );
  assert.equal(vendor(pipe).length, 0, 'a packet went out before verification');

  await app.destroy();
});

/* --------------------------------------------------------- backup capture */

test('a backup the device types is captured, decoded and verified', async () => {
  /*
   * There is no command that reads a backup out. The firmware TYPES it, which
   * on hardware means into whatever window has focus; here the reports arrive
   * in-process and the decoder turns them back into the file.
   *
   * The trigger is the caller's, because making the device do it is
   * platform-specific - a counted button hold on the emulator, a finger on
   * hardware - and the library has no business knowing which.
   */
  const pipe = fakeFirmware();
  const app = await start(pipe);

  const text = makeBackup([[0xde, 0xad, 0xbe, 0xef], [1, 2, 3]]);

  const captured = await app.services.device.captureBackup({
    trigger: () => {
      for (const report of typeText(text)) {
        pipe.deliver(report, { iface: IFACE.KEYBOARD });
      }
    },
    timeoutMs: 5000,
  });

  assert.equal(captured.verified, true, `digest mismatch: ${JSON.stringify(captured)}`);
  assert.ok(captured.text.includes(parsers.BACKUP_BEGIN));
  assert.ok(captured.text.includes(parsers.BACKUP_END));
  assert.equal(parsers.parseBackup(captured.text), parsers.parseBackup(text));

  await app.destroy();
});

test('a refusal on the vendor bus ends the capture at once', async () => {
  /*
   * The device does not always type a backup. With no backup key set it
   * hidprint()s "Error no backup key set" and then TYPES a sentence pointing
   * at the documentation (okcore.cpp:6802-6813).
   *
   * Watching only the keyboard, that is indistinguishable from a backup that
   * started and stopped: a hundred-odd characters and no end marker. Measured
   * on device before this was handled - the capture sat for its full two
   * minutes and then reported "139 characters and no end marker", which says
   * nothing about the cause. The device had explained itself immediately.
   */
  const pipe = fakeFirmware();
  const app = await start(pipe);

  const refusal = new Uint8Array(64);
  const words = 'Error no backup key set';
  for (let i = 0; i < words.length; i++) refusal[i] = words.charCodeAt(i);

  const started = Date.now();
  await assert.rejects(
    () => app.services.device.captureBackup({
      trigger: () => {
        /* The marker, then the refusal - the order the firmware uses. */
        for (const r of typeText(`${parsers.BACKUP_BEGIN}
`)) {
          pipe.deliver(r, { iface: IFACE.KEYBOARD });
        }
        pipe.deliver(refusal);
      },
      timeoutMs: 30000,
    }),
    (err) => {
      assert.match(err.message, /no backup key set/);
      assert.ok(err.partial.includes('BEGIN ONLYKEY BACKUP'), 'the partial was lost');
      return true;
    },
  );

  assert.ok(
    Date.now() - started < 5000,
    'the refusal was not acted on until the timeout',
  );

  await app.destroy();
});

test('a slow backup outlasting the timeout is not cut off while it types', async () => {
  /*
   * The timeout is for a device that has STOPPED, not a slow one. Found on
   * the bench: the app's 120 s was a fixed deadline, and a full backup typing
   * at ~12 characters a second was cut off mid-file while still arriving.
   *
   * Here the whole capture takes several times timeoutMs, but no gap between
   * keystrokes comes near it - so it must finish, and verify.
   */
  const pipe = fakeFirmware();
  const app = await start(pipe);
  const text = makeBackup([[0xde, 0xad, 0xbe, 0xef], [1, 2, 3]]);
  const reports = [...typeText(text)];
  const timeoutMs = 300;
  const gapMs = 40;
  assert.ok(reports.length * gapMs > 3 * timeoutMs, 'the test must outlast the timeout');

  const started = Date.now();
  const captured = await app.services.device.captureBackup({
    trigger: () => {
      reports.forEach((report, i) => {
        setTimeout(() => pipe.deliver(report, { iface: IFACE.KEYBOARD }), i * gapMs);
      });
    },
    timeoutMs,
  });

  assert.equal(captured.verified, true, `digest mismatch: ${JSON.stringify(captured)}`);
  assert.ok(Date.now() - started > timeoutMs, 'the capture did not outlast the timeout');

  await app.destroy();
});

test('a capture that never ends times out with what it has', async () => {
  /*
   * Ending on the END marker rather than on silence is what stops a backup
   * still arriving from being truncated into a file that verifies as damaged.
   * The other side of that choice is that a capture with no marker must fail
   * loudly, and hand back the partial so it can be looked at.
   */
  const pipe = fakeFirmware();
  const app = await start(pipe);

  await assert.rejects(
    () => app.services.device.captureBackup({
      trigger: () => {
        for (const report of typeText('-----BEGIN ONLYKEY BACKUP-----\nAQID\n')) {
          pipe.deliver(report, { iface: IFACE.KEYBOARD });
        }
      },
      timeoutMs: 300,
    }),
    (err) => {
      assert.match(err.message, /timed out/);
      assert.ok(err.partial.includes('BEGIN ONLYKEY BACKUP'), 'no partial was kept');
      return true;
    },
  );

  await app.destroy();
});

/* ------------------------------------------------------- Yubico OTP (legacy) */

/*
 * The desktop app's Advanced tab discards a wrong-format public id in TOTAL
 * SILENCE - the conversion throws inside a click handler, the throw escapes
 * into event dispatch, and the button appears to do nothing. Nothing is sent,
 * nothing is shown, and the fields keep the values that were rejected. See
 * onlykey-testing/FINDING-app-yubico-silent-discard.md.
 *
 * The trap is the form's shape: three adjacent fields, and only the first takes
 * modhex. These pin that the mistake is NAMED.
 */

const encoders = require('../src/device/encoders');
const { toHex } = require('../src/bytes');
const deviceKeys = require('../src/device/keys');

const GOOD = {
  publicId: 'ccccccbcgujh',                     // modhex, 6 bytes
  privateId: '0123456789ab',                    // hex, 6 bytes
  secretKey: '00112233445566778899aabbccddeeff', // hex, 16 bytes
};

test('a good per-slot credential validates', () => {
  const result = encoders.validateYubiCredential(GOOD);
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.deepEqual(result.errors, []);
});

test('hex in the modhex field is named as the mistake it is', () => {
  /*
   * The single most likely error - filling all three fields from one hex dump -
   * and the one the desktop swallows. "invalid character" would be true and
   * would not point at it.
   */
  const result = encoders.validateYubiCredential({ ...GOOD, publicId: '0123456789ab' });
  assert.equal(result.ok, false);
  assert.equal(result.errors.length, 1);
  assert.equal(result.errors[0].field, 'publicId');
  assert.match(result.errors[0].message, /HEX/);
  assert.match(result.errors[0].message, /MODHEX/);
});

test('every problem is reported at once, not just the first', () => {
  // A form marks all its bad fields. Throwing on the first would mean fixing
  // them one round trip at a time.
  const result = encoders.validateYubiCredential({
    publicId: '', privateId: 'zz', secretKey: 'abcd',
  });
  assert.equal(result.ok, false);
  assert.deepEqual(result.errors.map((e) => e.field).sort(),
    ['privateId', 'publicId', 'secretKey']);
});

test('the hex fields are checked for length, not sliced to it', () => {
  /*
   * A short private id shifts the secret in the original, producing a
   * credential the device accepts and which then authenticates against
   * nothing - expensive to diagnose from the far side of a one-way OTP.
   */
  const short = encoders.validateYubiCredential({ ...GOOD, privateId: '0123' });
  assert.equal(short.ok, false);
  assert.match(short.errors[0].message, /exactly 12/);

  const long = encoders.validateYubiCredential({ ...GOOD, secretKey: `${GOOD.secretKey}00` });
  assert.equal(long.ok, false);
  assert.match(long.errors[0].message, /exactly 32/);
});

test('the GLOBAL credential wants hex, and exactly six bytes', () => {
  /*
   * Different from the per-slot form in all three ways: hex not modhex, exactly
   * six bytes because the firmware memcpys that many, and the device-global
   * pseudo-slot. Modhex here is the mirror-image mistake.
   */
  const good = encoders.validateYubiCredential(
    { ...GOOD, publicId: '0123456789ab' }, { global: true },
  );
  assert.equal(good.ok, true, JSON.stringify(good.errors));

  const modhex = encoders.validateYubiCredential(GOOD, { global: true });
  assert.equal(modhex.ok, false);
  assert.match(modhex.errors[0].message, /HEX/);

  const wrongLength = encoders.validateYubiCredential(
    { ...GOOD, publicId: '0123' }, { global: true },
  );
  assert.equal(wrongLength.ok, false);
  assert.match(wrongLength.errors[0].message, /exactly 12/);
});

test('a valid credential encodes to the bytes the firmware reads', () => {
  // public(6) + private(6) + secret(16) concatenated, nothing else.
  const bytes = encoders.yubiGlobalCredential({ ...GOOD, publicId: '0123456789ab' });
  assert.equal(bytes.length, 28);
  assert.equal(toHex(bytes.subarray(0, 6)), '0123456789ab');
  assert.equal(toHex(bytes.subarray(6, 12)), GOOD.privateId);
  assert.equal(toHex(bytes.subarray(12)), GOOD.secretKey);
});

/* ------------------------------------------- the backup key from a PGP key */

test('a PGP-derived backup key lands on the same slot as a passphrase one', () => {
  /*
   * Setup Step 9. Same destination, different source - so the useful check is
   * that the Ed25519 case reproduces the constant the passphrase path uses.
   * If it did not, one of the two would be writing a type the device reads
   * differently.
   */
  const scalar = new Uint8Array(32).fill(9);
  const fromPgp = deviceKeys.backupKeyFromPgp(scalar, { curve: 1 });

  assert.equal(fromPgp.slot, deviceKeys.BACKUP_SLOT);
  assert.equal(fromPgp.type, deviceKeys.BACKUP_TYPE,
    'Ed25519 must give the same type byte the passphrase path hardcodes');
});

test('the curve changes the type byte, because the device cannot infer it', () => {
  const scalar = new Uint8Array(32).fill(9);
  // 0x80 backup | 0x20 decryption | curve
  assert.equal(deviceKeys.backupKeyFromPgp(scalar, { curve: 1 }).type, 161);
  assert.equal(deviceKeys.backupKeyFromPgp(scalar, { curve: 2 }).type, 162);
});

test('also-signature sets the signature modifier and nothing else', () => {
  const scalar = new Uint8Array(32).fill(9);
  const plain = deviceKeys.backupKeyFromPgp(scalar, { curve: 1 });
  const signing = deviceKeys.backupKeyFromPgp(scalar, { curve: 1, alsoSignature: true });
  assert.equal(signing.type ^ plain.type, 0x40);
});

test('an unknown curve is refused rather than defaulted', () => {
  /*
   * curveFromOid returns CURVE.NONE for a curve it does not recognise, and
   * writing that gives the device a key it cannot use - found at restore time,
   * which is the worst moment to find it.
   */
  const scalar = new Uint8Array(32).fill(9);
  assert.throws(() => deviceKeys.backupKeyFromPgp(scalar, { curve: 0 }), /Ed25519 or NIST P-256/);
  assert.throws(() => deviceKeys.backupKeyFromPgp(scalar, {}), /Ed25519 or NIST P-256/);
});

test('a backup key needs actual bytes', () => {
  assert.throws(() => deviceKeys.backupKeyFromPgp(null, { curve: 1 }), /private scalar/);
  assert.throws(() => deviceKeys.backupKeyFromPgp(new Uint8Array(0), { curve: 1 }), /private scalar/);
});

/* ------------------------------------ generating a key inside the device */

/** A stand-in public key of the right length, distinguishable from padding. */
function fakePublicKey(bytes) {
  const key = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i += 1) key[i] = (i * 7 + 3) & 0xff;
  return key;
}

test('generating an X-Wing key sends the trigger ONCE and waits for buttons', async () => {
  /*
   * The two things a client can get wrong here, both of which cost real
   * damage on a real key:
   *
   *   RE-SENDING the trigger after the challenge appears. The firmware
   *   replays the stored payload itself on the third press
   *   (OnlyKey.ino:846-859); a second write lands while CRYPTO_AUTH is 3 and
   *   is ignored, and the presses that follow it type slot contents at the
   *   keyboard of an unlocked device.
   *
   *   Reading an acknowledgement. There is none - ecc_priv_flash runs quiet -
   *   so a client expecting one waits out its timeout on a key that was
   *   generated perfectly well.
   */
  const expected = fakePublicKey(1216);
  const fw = fakeFirmware({ generates: { 105: expected } });
  const app = await start(fw);

  let sawDigits = null;
  const key = await app.services.device.generateKey(105, keys.KEY_TYPE.XWING, {
    confirm: async ({ digits }) => {
      sawDigits = digits;
      assert.equal(fw.awaitingChallenge, true, 'the device should be waiting');
      fw.confirmChallenge();
    },
  });

  assert.equal(key.length, 1216);
  assert.equal(toBase64(key), toBase64(expected));

  assert.equal(sawDigits.length, 3, 'three digits, one per button');
  for (const d of sawDigits) assert.ok(d >= 1 && d <= 6, `digit out of range: ${d}`);

  const writes = vendor(fw);
  const triggers = writes.filter((w) => w.data[4] === MSG.OKSETPRIV);
  assert.equal(triggers.length, 1, 'the trigger must be sent exactly once');
  assert.equal(triggers[0].data[5], 105, 'slot');
  assert.equal(triggers[0].data[6], keys.KEY_TYPE.XWING, 'key type');
  for (let i = 7; i <= 14; i += 1) {
    assert.equal(triggers[0].data[i], 0xff, `trigger byte ${i}`);
  }
});

test('ML-KEM-768 is 1184 bytes, and the length is what ends the read', async () => {
  /*
   * Nothing in the reply says how long it is - no length, no terminator, just
   * consecutive 64-byte reports. 1184 is not a multiple of 64, so the last
   * report is padded and the trailing bytes have to be cut by the expected
   * length rather than by where the reports stop.
   */
  const expected = fakePublicKey(1184);
  const fw = fakeFirmware({ generates: { 101: expected } });
  const app = await start(fw);

  const key = await app.services.device.generateKey(101, keys.KEY_TYPE.MLKEM768, {
    confirm: async () => fw.confirmChallenge(),
  });

  assert.equal(key.length, 1184);
  assert.equal(toBase64(key), toBase64(expected));
});

test('the challenge is hashed over the nine bytes the firmware hashes', async () => {
  /*
   * done_process_packets hashes what process_packets was GIVEN, and
   * ecc_priv_flash gives it `[keytype, FF x8]` with a length of 9
   * (okcore.cpp:5327-5334) - not the eight-byte payload on the wire.
   *
   * So the digits differ between the two key types, and a client that hashed
   * the payload alone would show the same three numbers for both and be
   * wrong for both.
   */
  const digitsFor = async (keyType, bytes) => {
    const fw = fakeFirmware({ generates: { 110: fakePublicKey(bytes) } });
    const app = await start(fw);
    let digits = null;
    await app.services.device.generateKey(110, keyType, {
      confirm: async (c) => { digits = c.digits; fw.confirmChallenge(); },
    });
    return digits.join('-');
  };

  const mlkem = await digitsFor(keys.KEY_TYPE.MLKEM768, 1184);
  const xwing = await digitsFor(keys.KEY_TYPE.XWING, 1216);
  assert.notEqual(mlkem, xwing, 'the key type is part of what is hashed');

  /* And the same request always shows the same numbers - it is a hash. */
  assert.equal(await digitsFor(keys.KEY_TYPE.XWING, 1216), xwing);
});

test('a slot the firmware would silently drop is refused here instead', async () => {
  /*
   * okcrypto.cpp has no else for a slot past 116, so the device answers
   * NOTHING - not an error, not a refusal. A caller would see a timeout and
   * have to guess whether the key was busy, absent, or asked something
   * impossible. Bounded here so the message names the real problem.
   */
  const fw = fakeFirmware({});
  const app = await start(fw);

  await assert.rejects(
    () => app.services.device.generateKey(133, keys.KEY_TYPE.XWING, {}),
    /slot 101\.\.116/,
  );
  await assert.rejects(
    () => app.services.device.generateKey(1, keys.KEY_TYPE.XWING, {}),
    /slot 101\.\.116/,
  );
  assert.equal(vendor(fw).length, 0, 'nothing should have been sent');
});

test('a key type the device cannot generate is named, not attempted', async () => {
  const fw = fakeFirmware({});
  const app = await start(fw);

  await assert.rejects(
    () => app.services.device.generateKey(105, keys.KEY_TYPE.ED25519, {}),
    /ML-KEM-768 \(5\), X-Wing \(6\)/,
  );
  assert.equal(vendor(fw).length, 0, 'nothing should have been sent');
});

test('a refusal after the press is reported as the device worded it', async () => {
  /*
   * Generation needs config mode, and outside it the firmware answers with a
   * sentence rather than a key. Read as an error rather than as the first 64
   * bytes of something.
   */
  const fw = fakeFirmware({});   // no `generates` entry: it refuses
  const app = await start(fw);

  await assert.rejects(
    () => app.services.device.generateKey(105, keys.KEY_TYPE.XWING, {
      confirm: async () => fw.confirmChallenge(),
      timeoutMs: 500,
    }),
    /not in config mode/i,
  );
});

test('a challenge nobody answers times out saying which buttons to press', async () => {
  const fw = fakeFirmware({ generates: { 105: fakePublicKey(1216) } });
  const app = await start(fw);

  await assert.rejects(
    () => app.services.device.generateKey(105, keys.KEY_TYPE.XWING, {timeoutMs: 300}),
    (e) => {
      assert.match(e.message, /produced no key within 300ms/);
      assert.match(e.message, /the challenge was \d-\d-\d/);
      return true;
    },
  );
});

/*
 * A BACKUP FROM BEFORE v2.1.2 HAS NO DIGEST LINE, and that is not a fault in
 * the file.
 *
 * The rolling digest arrived in firmware v2.1.2 - v2.1.1's okcore.cpp
 * base64-encodes each block and stops, and the symbol `backuphash` does not
 * occur in it. verifyBackup() therefore reports 'no digest line found' for
 * every backup taken from v2.1.1, v2.1.0 or v0.2-beta.8.
 *
 * restore() used to throw "backup failed verification" for that case, so the
 * library could not restore ANY of those backups and told the holder their file
 * was bad. That is precisely the population restore exists for: an old key that
 * has died, whose owner has one armoured text file and no other way back.
 *
 * The refusal is still the default - nothing is sent - but it now says what is
 * actually true, and a caller who knows the firmware can opt in.
 */
function makeBackupWithoutDigest(chunks) {
  return [
    parsers.BACKUP_BEGIN,
    ...chunks.map((c) => toBase64(Uint8Array.from(c))),
    parsers.BACKUP_END,
  ].join('\n');
}

test('a backup with no digest line is refused by default, and SENDS NOTHING', async () => {
  const pipe = fakeFirmware();
  const app = await start(pipe);

  const text = makeBackupWithoutDigest([[1, 2, 3, 4], [5, 6, 7, 8]]);

  await assert.rejects(
    () => app.services.device.restore(text),
    /carries no digest line/,
    'the refusal should name the missing digest, not claim the file failed',
  );
  assert.equal(vendor(pipe).length, 0, 'a packet went out before the refusal');

  await app.destroy();
});

test('the same backup restores when the caller opts in', async () => {
  const pipe = fakeFirmware();
  const app = await start(pipe);

  const text = makeBackupWithoutDigest([[1, 2, 3, 4], [5, 6, 7, 8]]);
  const result = await app.services.device.restore(text, { unverifiable: true });

  assert.equal(result.bytes, 8);
  const frames = vendor(pipe);
  assert.ok(frames.length >= 1, 'nothing was sent');
  assert.ok(
    frames.every((w) => w.data[4] === MSG.OKRESTORE),
    'every frame is an OKRESTORE',
  );

  await app.destroy();
});

test('the opt-in does NOT excuse a digest that is present and wrong', async () => {
  /*
   * The distinction the whole change rests on. `unverifiable` says "this file
   * predates the chain", not "skip the check" - a tampered file has a digest
   * and it does not match, which is a different claim and still refused.
   */
  const pipe = fakeFirmware();
  const app = await start(pipe);

  const lines = makeBackup([[1, 2, 3, 4], [5, 6, 7, 8]]).split('\n');
  lines[1] = toBase64(Uint8Array.from([9, 9, 9, 9]));

  await assert.rejects(
    () => app.services.device.restore(lines.join('\n'), { unverifiable: true }),
    /failed verification/,
  );
  assert.equal(vendor(pipe).length, 0, 'a tampered file was sent under the opt-in');

  await app.destroy();
});

/*
 * A REAL BACKUP, TYPED BY A REAL DEVICE, restored with no device present.
 *
 * test/fixtures/backup-v3.0.4.txt was captured from the v3.0.4 emulator slot -
 * `node tools/e2e.js --only deviceFlow,backupCapture` in ok-rn, cut out of the
 * log by tools/backup-fixture.js. 13 lines, 868 characters, 563 bytes of slot
 * data, digest 87722877dbf559ca...
 *
 * WHY A CAPTURED FILE AND NOT A SYNTHESISED ONE. Everything above builds
 * backups with makeBackup(), which hashes the same way parsers.js does - so it
 * proves the two halves of THIS repo agree and nothing about the firmware. A
 * file the device actually typed is the only evidence that the rolling digest,
 * the 57-byte line width and the base64 alphabet are what a real OnlyKey emits.
 * There is no command that reads a backup back; the device TYPES it, so this
 * cost a provisioned key, a passphrase, a button gesture and 95 seconds.
 *
 * It is from v3.0.4 deliberately: the last SIGNED release, and comfortably
 * above the v2.1.2 line where the digest chain begins
 * (capabilities().backupDigest).
 *
 * WHAT IT HOLDS: an emulated key's slots, encrypted under a passphrase that is
 * itself in this workspace - ok-rn's helpers/backupPassphrase.js, 'onlykey' six
 * times. A fixture, not a secret, and it must never be produced from a real key.
 */
const REAL_BACKUP = require('fs').readFileSync(
  require('path').join(__dirname, 'fixtures', 'backup-v3.0.4.txt'), 'utf8');

test('a backup a real device typed verifies and restores', async () => {
  const check = parsers.verifyBackup(REAL_BACKUP);
  assert.equal(check.ok, true, `the captured file does not verify: ${check.reason || ''}`);

  const pipe = fakeFirmware();
  const app = await start(pipe);
  const result = await app.services.device.restore(REAL_BACKUP);

  assert.equal(result.bytes, 563, 'the fixture is 563 bytes of slot data');
  assert.equal(result.digest, check.digest);

  const frames = vendor(pipe);
  assert.ok(frames.length >= 1, 'nothing was sent');
  assert.ok(
    frames.every((w) => w.data[4] === MSG.OKRESTORE),
    'every frame is an OKRESTORE',
  );

  await app.destroy();
});

test('one edited line in a real backup stops the restore dead', async () => {
  /*
   * The same guarantee the synthesised test pins, against a file whose digest
   * was computed by the FIRMWARE rather than by this repo. If the two ever
   * disagreed about the chain, a tampered real file would sail through.
   */
  const lines = REAL_BACKUP.trim().split('\n');
  const at = 2;                                   // a data line, not a marker
  assert.ok(!parsers.isMarker(lines[at]), 'picked a marker by mistake');
  lines[at] = toBase64(Uint8Array.from([9, 9, 9, 9]));

  const pipe = fakeFirmware();
  const app = await start(pipe);

  await assert.rejects(
    () => app.services.device.restore(lines.join('\n')),
    /failed verification/,
  );
  assert.equal(vendor(pipe).length, 0, 'a packet went out before verification');

  await app.destroy();
});
