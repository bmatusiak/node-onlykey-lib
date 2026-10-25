'use strict';
/*
 * Audit F1-F4 (2026-10-20): what `pair` writes must be what every later
 * command finds. The pairing round trip itself runs over the Windows fake in
 * test/cli-clipair-pipe.test.js; here: the address each platform's link
 * reports (the key a pairing is filed under), and pair forget / pair list.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const store = require('../cli/clipair-store');
const { createBlePipe } = require('../cli/transport-ble');
const { fakeNoble, fakeDbus, piTree } = require('./helpers/fake-ble');
const { fakeFirmware } = require('./helpers/fake-firmware');

const FAST = { scanMs: 300, connectMs: 300, discoverMs: 300, subscribeMs: 300, helloMs: 400 };
const quiet = () => {};
const PHONE = '24:29:34:86:EA:AF';
const tmpHome = () => fs.mkdtempSync(path.join(os.tmpdir(), 'okt-clipair-rt-'));
const rec = (over = {}) => ({ id: 'aa', phoneId: 'bbccdd00', epoch: 0, renewedAt: 0, name: os.hostname(), ...over });

test('windows: the link reports the phone it reached, whatever --address said', async () => {
  for (const address of ['Pixel 6a', PHONE, undefined]) {
    const pipe = createBlePipe({ platform: 'win32', loadNoble: () => fakeNoble({ firmware: fakeFirmware() }), timeouts: FAST, log: quiet, ...(address ? { address } : {}) });
    await pipe.start();
    assert.strictEqual(String(pipe.phone.address).toUpperCase(), PHONE, `--address ${address}`);
    assert.strictEqual(pipe.phone.name, 'Pixel 6a');
    await pipe.stop();
  }
});

test('linux: the link reports the phone\'s real address, also when GATT sits under a rotating address', async () => {
  for (const rpaSplit of [false, true]) {
    const { tree, rpa } = piTree({ rpaSplit });
    const dbus = fakeDbus({ tree, firmware: fakeFirmware(), connect: 'already', ...(rpaSplit ? { gattUnder: rpa } : {}) });
    const pipe = createBlePipe({ platform: 'linux', loadDbus: () => dbus, timeouts: FAST, log: quiet });
    await pipe.start();
    assert.strictEqual(pipe.phone.address, PHONE, `rpaSplit ${rpaSplit}: not the identity address`);
    await pipe.stop();
  }
});

test('a pairing is never filed under no address (audit F2)', () => {
  assert.throws(() => store.savePairing('', rec(), tmpHome()), /address/);
  assert.throws(() => store.savePairing(undefined, rec(), tmpHome()), /address/);
});

test('forget matches the phone by address in any form or by its Bluetooth name, and says when nothing matched (audit F3)', () => {
  const home = tmpHome();
  store.savePairing(PHONE, rec(), home, 'Pixel 6a');
  assert.deepStrictEqual(store.removePairing('Galaxy A13 5G', home), [], 'another phone matched');
  assert.strictEqual(store.list(home).length, 1, 'a miss removed something');
  assert.strictEqual(store.removePairing('pixel 6A', home).length, 1, 'by name');
  assert.strictEqual(store.list(home).length, 0);
  store.savePairing(PHONE.toLowerCase(), rec(), home, 'Pixel 6a');
  assert.strictEqual(store.removePairing('24-29-34-86-EA-AF', home).length, 1, 'by address, other separators');
  assert.deepStrictEqual(store.removePairing(undefined, home), [], 'no phone named - nothing removed');
});

/* The CLI reads the default home: point HOME (USERPROFILE on Windows) at a scratch folder for these. */
async function cli(argv, home) {
  const { main } = require('../cli/index');
  const keep = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  const out = [];
  const err = [];
  try {
    const code = await main(argv, { out: (l) => out.push(l), err: (l) => err.push(l) });
    return { code, out, err };
  } finally {
    for (const [k, v] of Object.entries(keep)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}

test('pair forget: a miss is an error, a hit names the phone; no --address is a usage error', async () => {
  const home = tmpHome();
  store.savePairing(PHONE, rec(), home, 'Pixel 6a');
  let r = await cli(['--ble', '--address', 'Galaxy A13 5G', 'pair', 'forget'], home);
  assert.notStrictEqual(r.code, 0);
  assert.match(r.err.join('\n'), /no pairing matches Galaxy A13 5G - nothing forgotten/);
  r = await cli(['--ble', 'pair', 'forget'], home);
  assert.strictEqual(r.code, 2);
  r = await cli(['--ble', '--address', 'Pixel 6a', 'pair', 'forget'], home);
  assert.strictEqual(r.code, 0);
  assert.match(r.out.join('\n'), /forgot the pairing with Pixel 6a 24:29:34:86:EA:AF/);
});

test('pair list: one row per phone, and a row that cannot work says so (audit F4)', async () => {
  const home = tmpHome();
  store.savePairing(PHONE, rec(), home, 'Pixel 6a');
  store.savePairing('8C:6A:3B:71:C6:72', rec({ phoneId: '11223344', name: 'zbox' }), home, 'Galaxy A13 5G');
  const r = await cli(['pair', 'list'], home);
  assert.strictEqual(r.code, 0);
  const text = r.out.join('\n');
  assert.match(text, /Pixel 6a 24:29:34:86:EA:AF {2}phone id bbccdd00/);
  assert.match(text, /Galaxy A13 5G 8C:6A:3B:71:C6:72 {2}phone id 11223344/);
  assert.match(text, /WILL NOT WORK: made as "zbox"/);
  assert.strictEqual((text.match(/WILL NOT WORK/g) || []).length, 1, 'only the zbox row');
});
