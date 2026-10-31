/*
 * `onlykey-js devices` (Brad, 2026-10-08: "onlykey-js devices helps us pick a
 * target"; "normal onlykey-js devices will just be usb"; "locked is connectable,
 * include that, show details about the device state"). Every key found is asked;
 * each row ends with its target. (The phones over Bluetooth, --ble, were removed
 * 2026-10-30.)
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { main } = require('../cli/index');
const { startDesktop } = require('../cli/desktop');
const { fakeFirmware } = require('./helpers/fake-firmware');

async function run(argv, { usb = [] } = {}) {
  const out = [];
  const err = [];
  const opened = [];
  const code = await main(argv, {
    out: (l) => out.push(l),
    err: (l) => err.push(l),
    findUsb: async () => usb.map((u) => ({ path: u.path, product: 'ONLYKEY' })),
    start: (opts) => {
      opened.push(opts);
      const dev = usb.find((u) => u.path === opts.path);
      return startDesktop({ ...opts, pipe: dev.pipe() });
    },
  });
  return { code, out: out.join('\n'), err: err.join('\n'), opened };
}

test('devices: USB - each key asked; locked is connectable, with its details and its --path', async () => {
  const r = await run(['devices'], {
    usb: [{ path: 'hid-1', pipe: () => fakeFirmware({ pin: '1234567' }) }, { path: 'hid-2', pipe: () => fakeFirmware() }],
  });
  assert.equal(r.code, 0);
  assert.match(r.out, / 1\. usb {2}ONLYKEY - connectable\n {5}state locked · model classic · firmware not reported while locked\n {5}--path "hid-1"/);
  assert.match(r.out, / 2\. usb {2}ONLYKEY - connectable\n {5}state unlocked/);
  assert.deepEqual(r.opened, [{ path: 'hid-1' }, { path: 'hid-2' }]);
});

test('devices with nothing found says so', async () => {
  const r = await run(['devices']);
  assert.equal(r.code, 1);
  assert.match(r.out, /^no OnlyKey on USB$/m);
});

test('devices --json: one array on stdout - the same facts as fields, numbered, each with its target', async () => {
  const r = await run(['devices', '--json'], {
    usb: [{ path: 'hid-1', pipe: () => fakeFirmware({ pin: '1234567' }) }, { path: 'hid-2', pipe: () => fakeFirmware() }],
  });
  assert.equal(r.code, 0);
  const rows = JSON.parse(r.out);
  assert.deepEqual(rows.map((x) => [x.n, x.transport, x.verdict]), [[1, 'usb', 'connectable'], [2, 'usb', 'connectable']]);
  assert.equal(rows[0].state, 'locked');
  assert.equal(rows[0].model, 'classic');
  assert.equal(rows[0].firmware, null);
  assert.deepEqual(rows[0].target, { path: 'hid-1' });
  assert.equal(rows[0].arg, '--path "hid-1"');
  assert.equal(rows[1].state, 'unlocked');
});

test('devices --ble and --seconds are gone (2026-10-30): a usage error, nothing opened', async () => {
  for (const argv of [['devices', '--ble'], ['devices', '--seconds', '4'], ['--ble', 'status'], ['--address', 'x', 'status']]) {
    const r = await run(argv, { usb: [{ path: 'hid-1', pipe: () => { throw new Error('opened a key'); } }] });
    assert.equal(r.code, 2, argv.join(' '));
    assert.deepEqual(r.opened, [], argv.join(' '));
  }
});
