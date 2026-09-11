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
