/*
 * `onlykey-js devices [--ble]` (Brad, 2026-10-08: "onlykey-js devices helps us pick a
 * target"; "normal onlykey-js devices will just be usb"; "--ble will just add
 * bluetooth to the list"; "locked is connectable, include that, show details about
 * the device state"). Every key found is asked; each row ends with its target.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { main } = require('../cli/index');
const { startDesktop } = require('../cli/desktop');
const { fakeFirmware } = require('./helpers/fake-firmware');
const { fakePipe } = require('./helpers/fake-pipe');
const { IFACE } = require('../src/transport/contract');

/* a phone whose soft key halted: the bridge answers for it (ok-rn vendorBridge KEY_STOPPED) */
function haltedPhone() {
  const pipe = fakePipe({ autoStart: true });
  const write = pipe.write;
  pipe.write = async (iface, bytes) => {
    const n = await write(iface, bytes);
    if (iface === IFACE.VENDOR) setImmediate(() => pipe.deliverText('Error soft key stopped, restart ok-rn on the phone', { iface: IFACE.VENDOR }));
    return n;
  };
  return pipe;
}

async function run(argv, { usb = [], phones = [], paired = [] } = {}) {
  const out = [];
  const opened = [];
  const scans = [];
  const code = await main(argv, {
    out: (l) => out.push(l),
    err: () => {},
    findUsb: async () => usb.map((u) => ({ path: u.path, product: 'ONLYKEY' })),
    scanPhones: async (o) => { scans.push(o); return phones; },
    pairingFor: (key) => paired.includes(key),
    start: (opts) => {
      opened.push(opts);
      const dev = opts.ble ? phones.find((p) => p.address === opts.address) : usb.find((u) => u.path === opts.path);
      return startDesktop({ ...opts, ble: false, pipe: dev.pipe() });
    },
  });
  return { code, out: out.join('\n'), opened, scans };
}

test('devices: USB only - each key asked; locked is connectable, with its details and its --path', async () => {
  const r = await run(['devices'], {
    usb: [{ path: 'hid-1', pipe: () => fakeFirmware({ pin: '1234567' }) }, { path: 'hid-2', pipe: () => fakeFirmware() }],
    phones: [{ address: '7e:ba:d3:da:ce:22', name: 'A13', rssi: -42, pipe: () => fakeFirmware() }],
  });
  assert.equal(r.code, 0);
  assert.match(r.out, / 1\. usb {2}ONLYKEY - connectable\n {5}state locked · model classic · firmware not reported while locked\n {5}--path "hid-1"/);
  assert.match(r.out, / 2\. usb {2}ONLYKEY - connectable\n {5}state unlocked/);
  assert.ok(!/^ *\d+\. ble /m.test(r.out), 'no phones without --ble');
  assert.ok(r.opened.every((o) => !o.ble));
});

test('devices --ble adds the phones: a paired one asked, a halted one said plainly, an unpaired one not opened', async () => {
  const r = await run(['devices', '--ble'], {
    usb: [{ path: 'hid-1', pipe: () => fakeFirmware() }],
    phones: [
      { address: '7e:ba:d3:da:ce:22', name: 'A13', rssi: -42, pipe: () => fakeFirmware() },
      { address: '24:29:34:86:ea:af', name: 'Pixel', rssi: -50, pipe: haltedPhone },
      { address: '11:22:33:44:55:66', name: 'Other', rssi: -70, pipe: () => { throw new Error('opened an unpaired phone'); } },
    ],
    paired: ['7EBAD3DACE22', '24293486EAAF'],
  });
  assert.equal(r.code, 0);
  assert.match(r.out, / 2\. ble {2}A13 \(-42 dBm\) - connectable\n {5}state unlocked[^\n]*\n {5}--ble --address 7E:BA:D3:DA:CE:22/);
  assert.match(r.out, / 3\. ble {2}Pixel \(-50 dBm\) - not connectable\n {5}the soft key stopped/);
  assert.match(r.out, / 4\. ble {2}Other \(-70 dBm\) - not paired\n {5}this computer has no pairing with it - onlykey-js pair --ble --address 11:22:33:44:55:66/);
  assert.equal(r.opened.filter((o) => o.ble).length, 2);
});

test('devices with nothing found says so, and how to add the phones', async () => {
  const r = await run(['devices']);
  assert.equal(r.code, 1);
  assert.match(r.out, /no OnlyKey on USB \(onlykey-js devices --ble adds the phones in reach\)/);
});

test('devices --ble --json: one array on stdout - the same facts as fields, numbered, each with its target', async () => {
  const r = await run(['devices', '--ble', '--json'], {
    usb: [{ path: 'hid-1', pipe: () => fakeFirmware({ pin: '1234567' }) }],
    phones: [
      { address: '7e:ba:d3:da:ce:22', name: 'A13', rssi: -42, pipe: () => fakeFirmware() },
      { address: '11:22:33:44:55:66', name: 'Other', rssi: -70, pipe: () => { throw new Error('opened an unpaired phone'); } },
    ],
    paired: ['7EBAD3DACE22'],
  });
  assert.equal(r.code, 0);
  const rows = JSON.parse(r.out);
  assert.deepEqual(rows.map((x) => [x.n, x.transport, x.verdict]), [[1, 'usb', 'connectable'], [2, 'ble', 'connectable'], [3, 'ble', 'not paired']]);
  assert.equal(rows[0].state, 'locked');
  assert.equal(rows[0].model, 'classic');
  assert.equal(rows[0].firmware, null);
  assert.deepEqual(rows[0].target, { path: 'hid-1' });
  assert.equal(rows[1].state, 'unlocked');
  assert.equal(rows[1].rssi, -42);
  assert.equal(rows[1].paired, true);
  assert.deepEqual(rows[1].target, { ble: true, address: '7E:BA:D3:DA:CE:22' });
  assert.equal(rows[2].paired, false);
  assert.equal(rows[2].arg, '--ble --address 11:22:33:44:55:66');
});

test('devices --ble --seconds: the search runs that long; 10 s without it; refused when not 1-120, or without --ble', async () => {
  const phones = [{ address: '7e:ba:d3:da:ce:22', name: 'A13', rssi: -42, pipe: () => fakeFirmware() }];
  const paired = ['7EBAD3DACE22'];
  assert.deepEqual((await run(['devices', '--ble', '--seconds', '4'], { phones, paired })).scans, [{ seconds: 4 }]);
  assert.deepEqual((await run(['devices', '--ble'], { phones, paired })).scans, [{ seconds: 10 }]);
  for (const bad of [['devices', '--ble', '--seconds', 'soon'], ['devices', '--ble', '--seconds', '0'], ['devices', '--ble', '--seconds', '500'], ['devices', '--seconds', '4']]) {
    const r = await run(bad, { phones, paired });
    assert.equal(r.code, 2, bad.join(' '));
    assert.deepEqual(r.scans, [], `no search for ${bad.join(' ')}`);
  }
});
