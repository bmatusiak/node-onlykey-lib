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

test('wipeKey sends OKWIPEPRIV for the slot', async () => {
  const pipe = fakeFirmware();
  const app = await start(pipe);

  await app.services.device.wipeKey(102);
  const f = vendor(pipe)[0].data;
  assert.equal(f[4], MSG.OKWIPEPRIV);
  assert.equal(f[5], 102);

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
