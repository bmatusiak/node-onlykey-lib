/*
 * cli/transport-hid - the node-hid pipe, and cli/desktop - the stack over it.
 *
 * Driven entirely by a fake node-hid MODULE (helpers/fake-node-hid.js), so
 * this runs on a machine with no key and no node-hid, and cannot reach a real
 * device even on one that has both. What is under test is the part that is
 * NOT the shared transport: which device gets opened, the report ID byte, the
 * echo, and the errors a person sees when there is no key, two keys, or no
 * node-hid.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { createHidPipe, loadNodeHid } = require('../cli/transport-hid');
const { startDesktop } = require('../cli/desktop');
const { fakeNodeHid, onlykeyInterfaces } = require('./helpers/fake-node-hid');
const { fakeFirmware } = require('./helpers/fake-firmware');
const { IFACE, DIR } = require('../src/transport/contract');

const notInstalled = () => {
  const err = new Error("Cannot find module 'node-hid'\nRequire stack:\n- cli/transport-hid.js");
  err.code = 'MODULE_NOT_FOUND';
  throw err;
};

/* ------------------------------------------------------------ node-hid */

test('a missing node-hid is named, with the command that installs it', () => {
  assert.throws(() => loadNodeHid(notInstalled), (err) => {
    assert.equal(err.code, 'ENOHID');
    assert.match(err.message, /optional dependency "node-hid"/);
    assert.match(err.message, /npm install node-hid/);
    return true;
  });
});

test('a node-hid that is present but broken is not called "not installed"', () => {
  /*
   * MODULE_NOT_FOUND for one of node-hid's OWN dependencies must not send
   * someone to reinstall a package that is there.
   */
  const brokenDep = () => {
    const err = new Error("Cannot find module 'pkg-prebuilds'");
    err.code = 'MODULE_NOT_FOUND';
    throw err;
  };
  assert.throws(() => loadNodeHid(brokenDep), { code: 'EHIDLOAD' });
  assert.throws(() => loadNodeHid(() => { throw new Error('invalid ELF header'); }),
    (err) => err.code === 'EHIDLOAD' && /node-hid/.test(err.message) && /rebuild/.test(err.message));
});

test('node-hid is not loaded until the pipe starts', async () => {
  /* Composing, and --help, must work on a machine without it. */
  let loads = 0;
  const pipe = createHidPipe({ loadHid: () => { loads += 1; return notInstalled(); } });
  assert.equal(loads, 0);
  assert.equal(pipe.isRunning(), false);
  await assert.rejects(() => pipe.start(), { code: 'ENOHID' });
  assert.equal(loads, 1);
});

/* ------------------------------------------------------------ which device */

test('opens the VENDOR interface, chosen by usage page, not by position', async () => {
  /* Listed out of order: position would pick the keyboard or FIDO. */
  const devices = onlykeyInterfaces().reverse();
  const HID = fakeNodeHid({ devices });
  const pipe = createHidPipe({ loadHid: () => HID });
  await pipe.start();
  assert.equal(HID.opened.length, 1);
  assert.equal(HID.opened[0].path, 'key1-if2');
  assert.equal(pipe.device.usagePage, 0xffab);
  await pipe.stop();
  assert.equal(HID.opened[0].closed, true);
  assert.equal(pipe.isRunning(), false);
});

test('no OnlyKey on the bus is a sentence, not a stack trace', async () => {
  const other = [{ vendorId: 0x046d, productId: 0xc52b, path: 'mouse', usagePage: 1, usage: 2 }];
  const pipe = createHidPipe({ loadHid: () => fakeNodeHid({ devices: other }) });
  await assert.rejects(() => pipe.start(), (err) => {
    assert.equal(err.code, 'ENOONLYKEY');
    assert.match(err.message, /No OnlyKey found \(USB 1d50:60fc\)/);
    return true;
  });
});

test('two OnlyKeys are refused, listing the paths to choose between', async () => {
  /* Enumeration order is the OS's; "the first" would be a different key tomorrow. */
  const devices = [...onlykeyInterfaces('keyA'), ...onlykeyInterfaces('keyB')];
  const HID = fakeNodeHid({ devices });
  await assert.rejects(() => createHidPipe({ loadHid: () => HID }).start(), (err) => {
    assert.equal(err.code, 'EMANYONLYKEY');
    assert.match(err.message, /2 OnlyKeys/);
    assert.match(err.message, /keyA-if2/);
    assert.match(err.message, /keyB-if2/);
    assert.match(err.message, /--path/);
    return true;
  });
  assert.equal(HID.opened.length, 0, 'nothing opened');

  const pipe = createHidPipe({ loadHid: () => HID, path: 'keyB-if2' });
  await pipe.start();
  assert.equal(HID.opened[0].path, 'keyB-if2');
  await pipe.stop();
});

test('--path must name an OnlyKey vendor interface, never an arbitrary device', async () => {
  const HID = fakeNodeHid();
  for (const path of ['key1-if1', 'some-other-device']) {
    await assert.rejects(() => createHidPipe({ loadHid: () => HID, path }).start(),
      { code: 'ENOTONLYKEY' });
  }
  assert.equal(HID.opened.length, 0);
});

test('a key whose usage pages hidapi cannot read is not guessed at', async () => {
  const HID = fakeNodeHid({ devices: onlykeyInterfaces('key1', { usagePages: false }) });
  await assert.rejects(() => createHidPipe({ loadHid: () => HID }).start(), (err) => {
    assert.equal(err.code, 'ENOVENDORIFACE');
    assert.match(err.message, /usage page 0xffab/);
    return true;
  });
  assert.equal(HID.opened.length, 0);
});

test('a listed key that will not open says so', async () => {
  const HID = fakeNodeHid({ openError: 'could not open device' });
  await assert.rejects(() => createHidPipe({ loadHid: () => HID }).start(),
    (err) => err.code === 'EOPEN' && /could not open device/.test(err.message));
});

/* ------------------------------------------------------------ the bytes */

test('writes carry a 0x00 report ID for hidapi; the echo does not', async () => {
  const HID = fakeNodeHid();
  const pipe = createHidPipe({ loadHid: () => HID });
  const seen = [];
  pipe.on('stream', (e) => seen.push(e));
  await pipe.start();

  const frame = new Uint8Array(64).fill(0xff);
  frame[4] = 0xe5;
  await pipe.write(IFACE.VENDOR, frame);

  const raw = HID.opened[0].writes[0];
  assert.equal(raw.length, 65);
  assert.equal(raw[0], 0x00, 'report ID first');
  assert.deepEqual(raw.slice(1), Array.from(frame), 'then the frame, unshifted');

  /* The echo is the contract's payload: no report ID, dir IN. */
  assert.equal(seen.length, 1);
  assert.equal(seen[0].dir, DIR.IN);
  assert.equal(seen[0].iface, IFACE.VENDOR);
  assert.deepEqual(Array.from(seen[0].bytes), Array.from(frame));
  await pipe.stop();
});

test('only the vendor interface is writable, and a closed pipe says so', async () => {
  const pipe = createHidPipe({ loadHid: () => fakeNodeHid() });
  await assert.rejects(() => pipe.write(IFACE.VENDOR, new Uint8Array(64)), { code: 'ENOTOPEN' });
  await pipe.start();
  await assert.rejects(() => pipe.write(IFACE.FIDO, new Uint8Array(64)), /only the vendor interface/);
  await assert.rejects(() => pipe.write(IFACE.SEREMU, new Uint8Array(8)), /only the vendor interface/);
  await pipe.stop();
});

test('a report read with its ID still attached is realigned', async () => {
  const firmware = fakeFirmware();
  const pipe = createHidPipe({ loadHid: () => fakeNodeHid({ firmware, readWithReportId: true }) });
  const inbound = [];
  pipe.on('stream', (e) => { if (e.dir === DIR.OUT) inbound.push(e); });
  await pipe.start();
  const report = new Uint8Array(64);
  report.set([0x55, 0x4e, 0x4c]);
  firmware.deliver(report);
  await new Promise((r) => setImmediate(r));
  assert.equal(inbound.length, 1);
  assert.equal(inbound[0].bytes.length, 64);
  assert.equal(inbound[0].bytes[0], 0x55, 'first byte is the report, not the ID');
  await pipe.stop();
});

test('an hidapi error (unplugged) stops the pipe and the next write names it', async () => {
  const HID = fakeNodeHid();
  const pipe = createHidPipe({ loadHid: () => HID });
  await pipe.start();
  HID.opened[0].emit('error', new Error('could not read from HID device'));
  assert.equal(pipe.isRunning(), false);
  assert.equal(HID.opened[0].closed, true);
  await assert.rejects(() => pipe.write(IFACE.VENDOR, new Uint8Array(64)),
    /went away: could not read from HID device/);
});

/* ------------------------------------------------------------ the stack */

test('startDesktop over the node-hid pipe: connect and read labels end to end', async () => {
  /*
   * The whole desktop path except the native addon: device plugin -> session
   * -> transport/usb -> this pipe -> "node-hid" -> the fake firmware. The
   * firmware sees frames without the report ID, or it would not answer.
   */
  const firmware = fakeFirmware({ labels: ['GitHub', '', 'Email'] });
  const HID = fakeNodeHid({ firmware });
  const app = await startDesktop({ loadHid: () => HID });
  try {
    assert.equal(app.services.transport.name, 'usb');
    assert.equal(app.services.transport.isOpen(), true, 'opened by the helper');
    const { status, identity } = await app.services.device.connect();
    assert.equal(status, 'UNLOCKEDv3.0.4-prodc');
    assert.equal(identity.state, 'unlocked');
    const { labels, complete } = await app.services.device.readLabels({ timeoutMs: 2000 });
    assert.equal(complete, true);
    assert.deepEqual(labels.slice(0, 3), ['GitHub', 'slot2', 'Email']);
  } finally {
    await app.destroy();
  }
  assert.equal(HID.opened[0].closed, true, 'destroy releases the key');
});

test('startDesktop without node-hid fails with the clear message, and leaves nothing open', async () => {
  await assert.rejects(() => startDesktop({ loadHid: notInstalled }),
    (err) => err.code === 'ENOHID' && /node-hid/.test(err.message));
});
