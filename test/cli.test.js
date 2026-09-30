/*
 * cli/index.js - onlykey-js, driven through main() against the fake firmware.
 *
 * Each test composes the SAME stack the bin does (startDesktop), with the fake
 * firmware as the pipe instead of node-hid, and reads what a person would see.
 * The output formats are python-onlykey's where a python command exists, so
 * these tests pin them line by line: a script that parsed onlykey-cli's
 * output should keep working against this one.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { execFileSync } = require('child_process');

const { main, COMMANDS, duoSlotName, classicSlotName } = require('../cli/index');
const { startDesktop } = require('../cli/desktop');
const { fakeFirmware } = require('./helpers/fake-firmware');
const PKG = require('../package.json');

/** Run one command line over a fake key; collect stdout, stderr and the code. */
async function run(argv, firmwareOpts = {}, extra = {}) {
  const out = [];
  const err = [];
  const firmware = fakeFirmware(firmwareOpts);
  const started = [];
  const code = await main(argv, {
    out: (line) => out.push(line),
    err: (line) => err.push(line),
    start: extra.start || (async (opts) => {
      const app = await startDesktop({ ...opts, pipe: firmware });
      started.push(app);
      return app;
    }),
  });
  return { code, out, err, firmware, started };
}

/* ------------------------------------------------------------ no device */

test('the bin file loads and `help` prints the command table (subprocess)', () => {
  /* The one subprocess: proves the shebang file runs as a program, not just a module. */
  const bin = path.resolve(__dirname, '..', PKG.bin['onlykey-js']);
  const text = execFileSync(process.execPath, [bin, 'help'], { encoding: 'utf8' });
  assert.match(text, new RegExp(`^onlykey-js v${PKG.version.replace(/\./g, '\\.')}`));
  for (const name of Object.keys(COMMANDS)) assert.match(text, new RegExp(`\\n  ${name} `));
});

test('help, -h, --help and no command all print help without touching a key', async () => {
  for (const argv of [['help'], ['-h'], ['--help'], [], ['getlabels', '--help']]) {
    const r = await run(argv, {}, { start: () => { throw new Error('opened a device'); } });
    assert.equal(r.code, 0, argv.join(' '));
    assert.match(r.out[0], /^onlykey-js v/);
  }
});

test('version is this program\'s, and needs no key (as python\'s does not)', async () => {
  const r = await run(['version'], {}, { start: () => { throw new Error('opened a device'); } });
  assert.equal(r.code, 0);
  assert.deepEqual(r.out, [`onlykey-js v${PKG.version} (node-onlykey-lib)`]);
});

test('an unknown command, an unknown option and extra arguments are usage errors', async () => {
  let r = await run(['bogus']);
  assert.equal(r.code, 2);
  assert.match(r.err[0], /unknown command "bogus"/);

  r = await run(['status', '--bogus']);
  assert.equal(r.code, 2);
  assert.match(r.err[0], /bogus/);

  r = await run(['getlabels', 'extra']);
  assert.equal(r.code, 2);
  assert.match(r.err[0], /takes no arguments/);
});

test('there is no firmware update command, by design', () => {
  const names = Object.keys(COMMANDS);
  assert.ok(!names.some((n) => /firmware|fwupdate|loadfirmware/i.test(n)), names.join(' '));
  const fs = require('fs');
  for (const f of fs.readdirSync(path.resolve(__dirname, '..', 'cli'))) {
    if (!f.endsWith('.js')) continue;
    const src = fs.readFileSync(path.resolve(__dirname, '..', 'cli', f), 'utf8');
    if (f === 'transport-ble.js') {
      /*
       * The one exception, and it is the opposite of a firmware path: the
       * Bluetooth pipe names OKFWUPDATE only to REFUSE it. Held to exactly
       * that - one mention in code, a comparison that rejects with EFIRMWARE.
       */
      const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
      assert.equal((code.match(/OKFWUPDATE/g) || []).length, 1, `${f}: OKFWUPDATE outside the refusal`);
      assert.match(code, /=== MSG\.OKFWUPDATE\) \{\s*return Promise\.reject\(bleError\('EFIRMWARE'/);
      continue;
    }
    assert.ok(!/OKFWUPDATE/.test(src), `${f} mentions OKFWUPDATE`);
  }
});

/* ------------------------------------------------------------ the device */

test('fwversion prints the version after the state word, as python does', async () => {
  const r = await run(['fwversion'], { version: 'v3.0.4-prodc' });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.deepEqual(r.out, ['v3.0.4-prodc']);
  assert.equal(r.firmware.isRunning(), false, 'the key was released');
});

test('fwversion on a locked key says why there is no version, instead of python\'s "ZED"', async () => {
  const r = await run(['fwversion'], { pin: '1234567' });
  assert.equal(r.code, 1);
  assert.deepEqual(r.out, []);
  assert.match(r.err[0], /locked key does not report its firmware version/);
});

test('status: status line, firmware, model, build and the capability flags', async () => {
  const r = await run(['status'], { version: 'v3.0.5-prodc' });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.equal(r.out[0], 'status         UNLOCKEDv3.0.5-prodc');
  assert.equal(r.out[1], 'state          unlocked');
  assert.equal(r.out[2], 'firmware       v3.0.5-prodc');
  assert.equal(r.out[3], 'model          classic');
  assert.equal(r.out[4], 'build          production');
  const caps = r.out.find((l) => l.startsWith('capabilities'));
  assert.match(caps, /\bagentDerivationV2\b/, '3.0.5 has agent v2');
});

test('status on a locked DUO reports what it can and claims no capabilities', async () => {
  /*
   * A locked key reports only INITIALIZED; the version-derived capabilities
   * would be the OLDEST firmware's, which is a confident wrong answer.
   */
  const firmware = fakeFirmware({ pin: '1234567' });
  const out = [];
  const code = await main(['status'], {
    out: (l) => out.push(l),
    err: () => {},
    start: (opts) => startDesktop({ ...opts, pipe: firmware }),
  });
  assert.equal(code, 0);
  assert.equal(out[1], 'state          locked');
  assert.equal(out[2], 'firmware       not reported while locked');
  assert.equal(out.at(-1), 'capabilities   unknown until unlocked');
});

test('capabilities lists flags both ways and says where they come from', async () => {
  const r = await run(['capabilities'], { version: 'v3.0.4-prodc' });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.equal(r.out[0], 'firmware       v3.0.4-prodc');
  assert.match(r.out[1], /^source +firmware version/);
  assert.match(r.out[2], /^flags +.*\bagentDerivation\b/);
  assert.match(r.out[3], /^not supported +.*\bagentDerivationV2\b/, '3.0.4 has no agent v2');
  assert.ok(r.out.includes('slots          12'));
});

test('getlabels on a classic: python\'s pairs, 1a with 1b, a blank line after each', async () => {
  /* null: the fake answers 'slotN' for it. */
  const r = await run(['getlabels'], { labels: ['GitHub', 'Email', null, null, null, null, 'Bank'] });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.equal(r.out.length, 18);
  assert.deepEqual(r.out.slice(0, 6), [
    'Slot 1a: GitHub',
    'Slot 1b: Bank',
    '',
    'Slot 2a: Email',
    'Slot 2b: slot8',
    '',
  ]);
  assert.equal(r.out[15], 'Slot 6a: slot6');
  assert.equal(r.out[16], 'Slot 6b: slot12');
});

test('getlabels on a DUO: 24 slots in python\'s colour runs of six', async () => {
  const r = await run(['getlabels'], { version: 'v3.1.0-prodp', labelSlots: 24 });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.equal(r.out.length, 28);
  assert.deepEqual(r.out.slice(0, 7), [
    'Slot Green 1a: slot1',
    'Slot Green 2a: slot2',
    'Slot Green 3a: slot3',
    'Slot Green 1b: slot4',
    'Slot Green 2b: slot5',
    'Slot Green 3b: slot6',
    '',
  ]);
  assert.equal(r.out[26], 'Slot Purple 3b: slot24');
});

test('getlabels on a locked key refuses at once instead of timing out', async () => {
  const t0 = Date.now();
  const r = await run(['getlabels'], { pin: '1234567' });
  assert.equal(r.code, 1);
  assert.match(r.err[0], /locked\. Enter your PIN/);
  assert.ok(Date.now() - t0 < 2000, 'no fifteen-second label timeout');
  assert.equal(r.firmware.isRunning(), false, 'released even on failure');
});

test('getkeylabels: RSA Key 1-4 then ECC Key 1-16, python\'s names', async () => {
  const r = await run(['getkeylabels'], { keyLabels: { 25: 'work rsa', 29: 'ssh' } });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.equal(r.out.length, 20);
  assert.equal(r.out[0], 'Slot RSA Key 1: work rsa');
  assert.equal(r.out[1], 'Slot RSA Key 2: <empty>');
  assert.equal(r.out[4], 'Slot ECC Key 1: ssh');
  assert.equal(r.out[19], 'Slot ECC Key 16: <empty>');
});

test('a missing node-hid reaches the user as one sentence naming it', async () => {
  const missing = () => {
    const e = new Error("Cannot find module 'node-hid'");
    e.code = 'MODULE_NOT_FOUND';
    throw e;
  };
  const r = await run(['status'], {}, { start: (opts) => startDesktop({ ...opts, loadHid: missing }) });
  assert.equal(r.code, 1);
  assert.equal(r.err.length, 1);
  assert.match(r.err[0], /^onlykey-js: .*"node-hid".*npm install node-hid/);
});

test('slot names match python-onlykey\'s SLOTS_NAME and SLOTS_NAME_DUO', () => {
  assert.deepEqual([1, 6, 7, 12].map(classicSlotName), ['1a', '6a', '1b', '6b']);
  assert.deepEqual([1, 3, 4, 6, 7, 13, 19, 24].map(duoSlotName), [
    'Green 1a', 'Green 3a', 'Green 1b', 'Green 3b', 'Blue 1a', 'Yellow 1a', 'Purple 1a', 'Purple 3b',
  ]);
});
