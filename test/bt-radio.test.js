'use strict';
/*
 * cli/bt-radio.js: this computer's Bluetooth version and the 5.0 minimum (Brad, 2026-10-20: "no
 * support for bt4"). The outputs below are the ones read on the ZBOX (btmgmt, 4.0) and NITRO16
 * (the LMP version property, 5.4) that night.
 */
const test = require('node:test');
const assert = require('node:assert');
const radio = require('../cli/bt-radio');

const ZBOX_BTMGMT = [
  'Index list with 1 item',
  'hci1:\tPrimary controller',
  '\taddr 00:1E:64:F0:67:B0 version 6 manufacturer 2 class 0x000104',
  '\tsupported settings: powered connectable fast-connectable discoverable bondable link-security ssp br/edr le advertising secure-conn debug-keys privacy configuration static-addr phy-configuration',
  '\tcurrent settings: powered ssp br/edr le',
  '\tname bmatusiak-ZBOX-MI531',
].join('\n');
const DONGLE_TOO = `${ZBOX_BTMGMT}\nhci2:\tPrimary controller\n\taddr 00:1A:7D:DA:71:13 version 10 manufacturer 10 class 0x000000\n`;

const execOf = (map) => async (file) => (file in map ? map[file] : null);

test('btmgmt: each controller with its HCI version', () => {
  assert.deepStrictEqual(radio.parseBtmgmt(ZBOX_BTMGMT), [{ index: 1, address: '00:1E:64:F0:67:B0', version: 6 }]);
  assert.strictEqual(radio.parseBtmgmt(DONGLE_TOO).length, 2);
  assert.deepStrictEqual(radio.parseBtmgmt(''), []);
});

test('the ZBOX (Bluetooth 4.0) is refused, and the words say what to do', async () => {
  const r = await radio.checkRadio({ platform: 'linux', exec: execOf({ btmgmt: ZBOX_BTMGMT }) });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.known, true);
  assert.match(r.message, /Bluetooth 4\.0 \(hci1 00:1E:64:F0:67:B0\) - not supported: onlykey-js --ble needs Bluetooth 5\.0 or newer/);
  assert.match(r.message, /USB Bluetooth 5 adapter/);
});

test('a Bluetooth 5 dongle beside the built-in 4.0 is ok, with a note to use it', async () => {
  const r = await radio.checkRadio({ platform: 'linux', exec: execOf({ btmgmt: DONGLE_TOO }) });
  assert.strictEqual(r.ok, true);
  assert.match(r.message, /Bluetooth 5\.1 \(hci2.*\) is supported; Bluetooth 4\.0 \(hci1.*\) is not - make sure Bluetooth uses the newer one/);
});

test('NITRO16 (Windows, LMP version 13) is Bluetooth 5.4 and supported', async () => {
  const r = await radio.checkRadio({ platform: 'win32', exec: execOf({ 'powershell.exe': '13\r\n' }) });
  assert.strictEqual(r.ok, true);
  assert.match(r.message, /Bluetooth 5\.4 - supported/);
});

test('the minimum is 5.0 exactly: 4.2 refused, 5.0 supported', () => {
  assert.strictEqual(radio.judge({ radios: [{ version: 8, name: '4.2' }] }).ok, false);
  assert.strictEqual(radio.judge({ radios: [{ version: 9, name: '5.0' }] }).ok, true);
});

test('a radio that cannot be read is said, not refused', async () => {
  for (const platform of ['linux', 'win32', 'darwin']) {
    const r = await radio.checkRadio({ platform, exec: execOf({}) });
    assert.strictEqual(r.ok, true, platform);
    assert.strictEqual(r.known, false, platform);
    assert.match(r.message, /could not be read.*needs Bluetooth 5\.0 or newer/);
  }
});

test('onlykey-js --ble pair stops on an unsupported radio, before any Bluetooth', async () => {
  const { main } = require('../cli/index');
  const keep = radio.checkRadio;
  radio.checkRadio = async () => ({ ok: false, known: true, message: 'this computer\'s Bluetooth radio is Bluetooth 4.0 - not supported' });
  try {
    const err = [];
    const code = await main(['--ble', 'pair'], { out: () => {}, err: (l) => err.push(l) });
    assert.notStrictEqual(code, 0);
    assert.match(err.join('\n'), /Bluetooth 4\.0 - not supported/);
  } finally {
    radio.checkRadio = keep;
  }
});
