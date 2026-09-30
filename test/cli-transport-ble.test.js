/*
 * cli/transport-ble - the Bluetooth pipe, over a fake noble (Windows) and a
 * fake dbus-next + BlueZ (Linux), each with a fake ok-rn phone relaying to
 * the fake firmware (helpers/fake-ble.js).
 *
 * No radio, no phone, no native module: this runs anywhere, and cannot reach
 * a real device even on a machine that has one. Under test is what is NOT
 * the shared transport: the framing both ways, reassembly of a multi-report
 * answer, the echo-before-reply order when a reply beats its write, how each
 * platform link finds and connects the phone - including the BlueZ states the
 * Pi was found in - and the errors a person sees.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const {
  createBlePipe, fragment, createAssembler, loadNoble, loadDbus,
} = require('../cli/transport-ble');
const { startDesktop } = require('../cli/desktop');
const { main } = require('../cli/index');
const { fakeNoble, fakeDbus, piTree } = require('./helpers/fake-ble');
const { fakeFirmware } = require('./helpers/fake-firmware');
const { IFACE, DIR } = require('../src/transport/contract');
const { MSG } = require('../src/protocol/msg');

const FAST = { powerMs: 200, scanMs: 300, connectMs: 300, resolveMs: 400 };
const quiet = () => {};

const notInstalled = (name) => () => {
  const err = new Error(`Cannot find module '${name}'\nRequire stack:\n- cli/transport-ble.js`);
  err.code = 'MODULE_NOT_FOUND';
  throw err;
};

function report(msg, payload = []) {
  const r = new Uint8Array(64);
  r.set([0xff, 0xff, 0xff, 0xff, msg, ...payload]);
  return r;
}

const winPipe = (noble, opts = {}) => createBlePipe({
  platform: 'win32', loadNoble: () => noble, timeouts: FAST, log: quiet, ...opts,
});
const linuxPipe = (dbus, opts = {}) => createBlePipe({
  platform: 'linux', loadDbus: () => dbus, timeouts: FAST, log: quiet, ...opts,
});

async function stackOver(pipe) {
  return startDesktop({ ble: true, pipe });
}

/* ------------------------------------------------------------ framing */

test('framing: a report is one 67-byte write at a large MTU, python\'s 20-byte fragments at the floor', () => {
  const r = report(MSG.OKCONNECT, [1, 2, 3]);
  const whole = fragment(r, 67);
  assert.equal(whole.length, 1);
  assert.deepEqual(Array.from(whole[0].subarray(0, 3)), [0x83, 0x00, 0x40]);
  assert.deepEqual(Array.from(whole[0].subarray(3)), Array.from(r));

  const small = fragment(r, 20);
  /* 17 bytes in the first, 19 in each continuation: 17 + 19 + 19 + 9 = 64. */
  assert.deepEqual(small.map((f) => f.length), [20, 20, 20, 10]);
  assert.deepEqual(small.map((f) => f[0]), [0x83, 0, 1, 2]);
  assert.deepEqual(Array.from(small[0].subarray(0, 8)), [0x83, 0x00, 0x40, 0xff, 0xff, 0xff, 0xff, MSG.OKCONNECT]);
});

test('reassembly: fragments in, whole reports out; a new first fragment drops an unfinished one', () => {
  const a = createAssembler();
  const r = report(0x55, [9, 8, 7]);
  const pieces = fragment(r, 20);
  assert.equal(a.push(pieces[0]), null);
  assert.equal(a.push(pieces[1]), null);
  assert.equal(a.push(pieces[2]), null);
  assert.deepEqual(Array.from(a.push(pieces[3])), Array.from(r));
  /* A lost continuation costs that message only. */
  assert.equal(a.push(pieces[0]), null);
  assert.deepEqual(Array.from(a.push(fragment(r, 67)[0])), Array.from(r));
  /* A continuation with no start (from before we subscribed) is ignored. */
  assert.equal(createAssembler().push(pieces[1]), null);
});

test('the phone refusal (CMD_ERROR 0xbf) is told apart from a key report', () => {
  /*
   * ok-rn diverts a gated vendor write and answers [0xbf][00][01][0x7f]. The
   * assembler keeps each message's command so the pipe can refuse instead of
   * handing the byte 0x7f up as if the key had said it.
   */
  const { CMD_ERROR } = require('../cli/transport-ble');
  const a = createAssembler();
  const refusal = a.push(Uint8Array.from([CMD_ERROR, 0x00, 0x01, 0x7f]));
  assert.equal(refusal.command, CMD_ERROR);
  assert.deepEqual(Array.from(refusal), [0x7f]);
  const r = report(0x55, [1]);
  assert.equal(a.push(fragment(r, 67)[0]).command, 0x83);
});

/* ------------------------------------------------------------ optional deps */

test('a missing noble or dbus-next is named, with the command that installs it', () => {
  assert.throws(() => loadNoble(notInstalled('@stoprocent/noble')), (err) => {
    assert.equal(err.code, 'ENOBLE');
    assert.match(err.message, /OPTIONAL PEER.*npm install @stoprocent\/noble@2\.8\.0/);
    return true;
  });
  assert.throws(() => loadDbus(notInstalled('dbus-next')), (err) => {
    assert.equal(err.code, 'ENOBLE');
    assert.match(err.message, /npm install dbus-next/);
    return true;
  });
  /* Present, but one of ITS dependencies is missing: not "not installed". */
  assert.throws(() => loadNoble(notInstalled('@stoprocent/bluetooth-hci-socket')), { code: 'EBLELOAD' });
});

test('the Bluetooth stack is not loaded until the pipe starts, and a missing one fails start by name', async () => {
  let loads = 0;
  const pipe = createBlePipe({ platform: 'win32', loadNoble: () => { loads += 1; return notInstalled('@stoprocent/noble')(); } });
  assert.equal(loads, 0);
  await assert.rejects(() => pipe.start(), { code: 'ENOBLE' });
  await assert.rejects(() => startDesktop({ ble: true, pipe: createBlePipe({ platform: 'linux', loadDbus: notInstalled('dbus-next') }) }),
    { code: 'ENOBLE' });
});

test('a platform the pipe was not built for is refused by name', async () => {
  await assert.rejects(() => createBlePipe({ platform: 'darwin' }).start(), { code: 'EBLEPLATFORM' });
});

/* ------------------------------------------------------------ Windows: noble */

test('win32: found by the FIDO advert, one write per report, echo IN then the reply OUT', async () => {
  const firmware = fakeFirmware();
  const noble = fakeNoble({
    firmware,
    adverts: [
      { id: 'aabbccddeeff', address: 'aa:bb:cc:dd:ee:ff', localName: 'Speaker', serviceUuids: [] },
      { id: '24293486eaaf', address: '24:29:34:86:ea:af', localName: 'Pixel 6a', serviceUuids: ['fffd'] },
    ],
    phoneId: '24293486eaaf',
  });
  const pipe = winPipe(noble);
  const seen = [];
  pipe.on('stream', (e) => seen.push(e));
  await pipe.start();
  assert.match(pipe.link, /Pixel 6a/);
  /* Vendor-only discovery, subscribed BEFORE any write. */
  const kinds = noble.log.map((l) => l[0]);
  assert.ok(kinds.indexOf('subscribe') < kinds.indexOf('write') || !kinds.includes('write'));
  assert.deepEqual(noble.log.find((l) => l[0] === 'discover').slice(1), [
    ['0c0ffab09f1e4b1d9c6a0f0e1d2c3b4a'],
    ['0c0ffab19f1e4b1d9c6a0f0e1d2c3b4a', '0c0ffab29f1e4b1d9c6a0f0e1d2c3b4a']]);

  const frame = report(MSG.OKCONNECT, [0x66, 0x00, 0x00, 0x00]);
  await pipe.write(IFACE.VENDOR, frame);
  const writes = noble.log.filter((l) => l[0] === 'write');
  assert.equal(writes.length, 1, 'MTU 517: the whole report in one write');
  assert.equal(writes[0][2], false, 'with response');
  assert.equal(writes[0][1].slice(0, 6), '830040');
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(seen[0].dir, DIR.IN);
  assert.deepEqual(Array.from(seen[0].bytes), Array.from(frame));
  assert.equal(seen[1].dir, DIR.OUT);
  assert.equal(seen[1].iface, IFACE.VENDOR);
  assert.equal(seen[1].bytes.length, 64);
  await pipe.stop();
  assert.ok(noble.log.some((l) => l[0] === 'disconnect'));
  /* Its own instance, stopped on close: otherwise the WinRT manager keeps the process alive. */
  assert.deepEqual(noble.log.find((l) => l[0] === 'withBindings'), ['withBindings', 'win']);
  assert.equal(noble.log.at(-1)[0], 'stop');
});

test('win32: a reply that arrives before its write resolves is held until after the echo', async () => {
  const firmware = fakeFirmware();
  const noble = fakeNoble({ firmware, notifyBeforeWriteResolves: true });
  const pipe = winPipe(noble);
  const seen = [];
  pipe.on('stream', (e) => seen.push(e.dir));
  await pipe.start();
  await pipe.write(IFACE.VENDOR, report(MSG.OKCONNECT, [0x66, 0, 0, 0]));
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(seen.slice(0, 2), [DIR.IN, DIR.OUT]);
  await pipe.stop();
});

test('win32 stack: OKCONNECT and all twelve labels, at MTU 517 and at the 20-byte floor', async () => {
  for (const [mtu, phoneFragment] of [[517, 67], [23, 20]]) {
    const firmware = fakeFirmware({ labels: ['GitHub', '', 'Email'] });
    const noble = fakeNoble({ firmware, mtu, phoneFragment });
    const app = await stackOver(winPipe(noble));
    try {
      assert.equal(app.services.transport.name, 'ble');
      const { status, identity } = await app.services.device.connect();
      assert.equal(status, 'UNLOCKEDv3.0.4-prodc');
      assert.equal(identity.state, 'unlocked');
      const { labels, complete } = await app.services.device.readLabels({ timeoutMs: 3000 });
      assert.equal(complete, true, `mtu ${mtu}`);
      assert.equal(labels.length, 12);
      assert.deepEqual(labels.slice(0, 3), ['GitHub', 'slot2', 'Email']);
      const sizes = new Set(noble.phone.fragments.map((f) => f.length));
      assert.ok(mtu === 517 ? sizes.has(67) : Math.max(...sizes) === 20, `write size at mtu ${mtu}`);
    } finally {
      await app.destroy();
    }
  }
});

test('firmware update is refused over Bluetooth, before anything is sent', async () => {
  const noble = fakeNoble({ firmware: fakeFirmware() });
  const pipe = winPipe(noble);
  await pipe.start();
  await assert.rejects(() => pipe.write(IFACE.VENDOR, report(MSG.OKFWUPDATE, [0x12, 0x34])),
    (err) => err.code === 'EFIRMWARE' && /refused over Bluetooth/.test(err.message));
  assert.equal(noble.log.filter((l) => l[0] === 'write').length, 0);
  await assert.rejects(() => pipe.write(IFACE.FIDO, new Uint8Array(64)), /only the vendor interface/);
  await pipe.stop();
});

test('win32: --address by name or by address; a scan timeout names what it saw', async () => {
  const adverts = [
    { id: 'aabbccddeeff', address: 'aa:bb:cc:dd:ee:ff', localName: 'Other phone', serviceUuids: ['fffd'] },
    { id: '24293486eaaf', address: '24:29:34:86:ea:af', localName: 'Pixel 6a', serviceUuids: ['fffd'] },
  ];
  for (const address of ['Pixel 6a', '24:29:34:86:EA:AF', '24293486EAAF']) {
    const noble = fakeNoble({ firmware: fakeFirmware(), adverts, phoneId: '24293486eaaf' });
    const pipe = winPipe(noble, { address });
    await pipe.start();
    assert.match(pipe.link, /24293486eaaf/, address);
    await pipe.stop();
  }
  const noble = fakeNoble({ adverts });
  await assert.rejects(() => winPipe(noble, { address: 'Pixel 7' }).start(), (err) => {
    assert.equal(err.code, 'ENOPHONE');
    assert.match(err.message, /matching "Pixel 7"/);
    assert.match(err.message, /Saw 2 Bluetooth devices; FIDO: Other phone aabbccddeeff, Pixel 6a 24293486eaaf/);
    return true;
  });
});

test('win32: Bluetooth off, a FIDO device without the vendor service, a connect that hangs', async () => {
  await assert.rejects(() => winPipe(fakeNoble({ state: 'poweredOff' })).start(),
    (err) => err.code === 'EBLEOFF' && /poweredOff/.test(err.message));
  const noVendor = fakeNoble({ vendor: false });
  await assert.rejects(() => winPipe(noVendor).start(),
    (err) => err.code === 'ENOVENDOR' && /--address/.test(err.message));
  assert.ok(noVendor.log.some((l) => l[0] === 'disconnect'), 'let go of the wrong device');
  const hangs = fakeNoble({ connectHangs: true });
  await assert.rejects(() => winPipe(hangs).start(),
    (err) => err.code === 'ECONNECT' && /one computer at a time/.test(err.message));
  assert.ok(hangs.log.some((l) => l[0] === 'cancelConnect'));
});

test('win32: the phone dropping the link stops the pipe, and the next write says why', async () => {
  const noble = fakeNoble({ firmware: fakeFirmware() });
  const pipe = winPipe(noble);
  await pipe.start();
  noble.peripheral('24293486eaaf').emit('disconnect', 'timeout');
  assert.equal(pipe.isRunning(), false);
  await assert.rejects(() => pipe.write(IFACE.VENDOR, report(MSG.OKCONNECT)),
    (err) => err.code === 'ENOTOPEN' && /dropped the Bluetooth link \(timeout\)/.test(err.message));
});

/* ------------------------------------------------------------ Linux: BlueZ over D-Bus */

test('linux: the LE link already up - no Connect(), GATT objects under the RPA path, labels read', async () => {
  const { tree, rpa } = piTree({ live: true });
  const dbus = fakeDbus({ tree, firmware: fakeFirmware({ labels: ['GitHub'] }) });
  dbus.addGatt(rpa);
  const app = await stackOver(linuxPipe(dbus));
  try {
    const { status } = await app.services.device.connect();
    assert.equal(status, 'UNLOCKEDv3.0.4-prodc');
    const { complete, labels } = await app.services.device.readLabels({ timeoutMs: 3000 });
    assert.equal(complete, true);
    assert.equal(labels[0], 'GitHub');
  } finally {
    await app.destroy();
  }
  assert.equal(dbus.calls.filter((c) => c[0] === 'Connect').length, 0);
  const writes = dbus.calls.filter((c) => c[0] === 'WriteValue');
  assert.ok(writes.length >= 2);
  assert.ok(writes.every((c) => c[1] === `${rpa}/service00a7/char00a8` && c[3] === 'request'), 'write with response, to the request char');
  const order = dbus.calls.map((c) => c[0]);
  assert.ok(order.indexOf('StartNotify') < order.indexOf('WriteValue'), 'subscribed before the first write');
  assert.ok(order.includes('StopNotify') && order.includes('bus.disconnect'));
  assert.ok(!order.includes('Disconnect'), 'never Device1.Disconnect: that would drop the classic keyboard too');
});

test('linux: classic-only (the keyboard), cached GATT - PreferredBearer le, Connect(), then the table resolves', async () => {
  /*
   * The Pi as found: Connected (the keyboard), ServicesResolved false, the
   * vendor characteristics EXPORTED from BlueZ's cache. They are not live, so
   * the pipe must connect rather than write into the cache.
   */
  const { tree, rpa } = piTree({ preferredBearer: 'bredr' });
  const dbus = fakeDbus({ tree, firmware: fakeFirmware() });
  dbus.addGatt(rpa);
  const pipe = linuxPipe(dbus);
  await pipe.start();
  const set = dbus.calls.find((c) => c[0] === 'Set');
  assert.deepEqual(set.slice(1), [rpa, 'org.bluez.Device1', 'PreferredBearer', 'le']);
  const conn = dbus.calls.find((c) => c[0] === 'Connect');
  assert.deepEqual(conn.slice(1), [rpa, 'le'], 'Connect() after the bearer is set');
  /* Inside an LE discovery session, stopped once the table resolved. */
  const order = dbus.calls.map((c) => c[0]);
  assert.deepEqual(dbus.calls.find((c) => c[0] === 'SetDiscoveryFilter').slice(1), ['/org/bluez/hci0', 'le']);
  assert.ok(order.indexOf('StartDiscovery') < order.indexOf('Connect'));
  assert.ok(order.indexOf('StopDiscovery') > order.indexOf('Connect'));
  await pipe.write(IFACE.VENDOR, report(MSG.OKCONNECT, [0x66, 0, 0, 0]));
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(dbus.phone.received.length, 1, 'the report reached the phone whole');
  await pipe.stop();
});

test('linux: the RPA split - bonded identity object, GATT under a private-address object', async () => {
  const { tree, rpa, identity } = piTree({ rpaSplit: true });
  const dbus = fakeDbus({ tree, firmware: fakeFirmware(), connect: 'already', gattUnder: rpa });
  const seen = [];
  const pipe = linuxPipe(dbus);
  pipe.on('stream', (e) => seen.push(e.dir));
  await pipe.start();
  assert.equal(dbus.calls.find((c) => c[0] === 'Connect')[1], identity, 'Connect() on the bonded one');
  assert.match(pipe.link, /dev_78_8B_B8_DC_65_05/, 'talks to the characteristics wherever they are');
  await pipe.write(IFACE.VENDOR, report(MSG.OKCONNECT, [0x66, 0, 0, 0]));
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(seen.slice(0, 2), [DIR.IN, DIR.OUT]);
  await pipe.stop();
});

test('linux: named errors - no PreferredBearer, never resolves, classic socket, phone busy, off, not paired', async () => {
  const cases = [
    [{ preferredBearer: null }, {}, 'EBEARER', /Experimental = true.*ble-linux-connect\.sh.*--fix/s],
    [{}, { connect: 'never' }, 'ECLASSIC', /never resolved.*ServicesResolved false.*classic only, or an LE link .* is stale.*hcitool ledc/s],
    [{}, { connect: 'br-socket' }, 'ECLASSIC', /br-connection-create-socket/],
    [{}, { connect: 'abort' }, 'EBUSY', /le-connection-abort-by-local.*one computer at a time/s],
    [{ powered: false }, {}, 'EBLEOFF', /rfkill.*--fix/s],
    [{ paired: false }, {}, 'ENOBOND', /Pair it first: scripts\/ble-linux-connect\.sh/],
  ];
  for (const [treeOpts, dbusOpts, code, message] of cases) {
    const { tree } = piTree(treeOpts);
    const dbus = fakeDbus({ tree, ...dbusOpts });
    await assert.rejects(() => linuxPipe(dbus).start(), (err) => {
      assert.equal(err.code, code, `${JSON.stringify(treeOpts)} ${JSON.stringify(dbusOpts)}: ${err.message}`);
      assert.match(err.message, message);
      return true;
    });
    assert.ok(dbus.calls.some((c) => c[0] === 'bus.disconnect'), `${code}: the bus is let go`);
  }
  const noBluez = fakeDbus({ tree: {} });
  noBluez.systemBus().getProxyObject = async () => {
    const e = new Error('The name org.bluez was not provided by any .service files');
    e.type = 'org.freedesktop.DBus.Error.ServiceUnknown';
    throw e;
  };
  const bus = noBluez.systemBus();
  await assert.rejects(() => linuxPipe({ ...noBluez, systemBus: () => bus }).start(),
    (err) => err.code === 'ENOBLUEZ' && /systemctl start bluetooth/.test(err.message));
});

test('linux: --address by address or name; two paired phones are refused, not guessed', async () => {
  for (const address of ['24:29:34:86:ea:af', 'pixel 6a']) {
    const { tree, rpa } = piTree({ live: true });
    const dbus = fakeDbus({ tree, firmware: fakeFirmware() });
    dbus.addGatt(rpa);
    const pipe = linuxPipe(dbus, { address });
    await pipe.start();
    await pipe.stop();
  }
  const { tree } = piTree();
  tree['/org/bluez/hci0/dev_11_22_33_44_55_66'] = { 'org.bluez.Device1': {
    Address: '11:22:33:44:55:66', Name: 'Pixel 8', Paired: true, Connected: false,
    UUIDs: ['0c0ffab0-9f1e-4b1d-9c6a-0f0e1d2c3b4a'] } };
  await assert.rejects(() => linuxPipe(fakeDbus({ tree })).start(),
    (err) => err.code === 'EMANYPHONE' && /--address/.test(err.message) && /Pixel 8/.test(err.message));
});

/* ------------------------------------------------------------ the CLI */

test('--ble reaches every device command: status, agent (the ssh key line), and gpg init\'s agent script', async () => {
  const K132 = new Uint8Array(32).map((_, i) => (i * 29 + 7) & 0xff);
  const starts = [];
  const start = (opts) => {
    starts.push(opts);
    assert.equal(opts.ble, true);
    const noble = fakeNoble({ firmware: fakeFirmware({ agent: { k132: K132 } }) });
    return startDesktop({ ...opts, pipe: winPipe(noble, { address: opts.address }) });
  };
  const run = async (argv, extra = {}) => {
    const out = [];
    const err = [];
    const code = await main(argv, { out: (l) => out.push(l), err: (l) => err.push(l), start, ...extra });
    return { code, out, err };
  };

  const st = await run(['--ble', 'status']);
  assert.equal(st.code, 0, st.err.join('\n'));
  assert.ok(st.out.some((l) => /UNLOCKED/.test(l)));
  assert.deepEqual(starts[0], { ble: true, address: undefined });

  const ag = await run(['agent', 'test@example.com', '--ble', '--address', 'Pixel 6a']);
  assert.equal(ag.code, 0, ag.err.join('\n'));
  assert.match(ag.out.join('\n'), /^ssh-ed25519 AAAA\S+ <ssh:\/\/test@example\.com\|ed25519>$/m);
  assert.deepEqual(starts[1], { ble: true, address: 'Pixel 6a' });

  /* gpg starts the agent LATER, with none of our options: the home must carry --ble. */
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'okjs-ble-'));
  try {
    const home = path.join(parent, 'home');
    const gpg = async (args) => (args[0] === '--version'
      ? { code: 0, stdout: 'gpg (GnuPG) 2.4.4\n', stderr: '' } : { code: 0, stdout: '', stderr: '' });
    const r = await run(['gpg', 'init', 'OnlyKey Test <okt@example.com>', '--homedir', home, '-t', '1700000000',
      '--ble', '--address', 'Pixel 6a'], { gpg });
    assert.equal(r.code, 0, r.err.join('\n'));
    const script = fs.readFileSync(path.join(home, process.platform === 'win32' ? 'run-agent.cmd' : 'run-agent.sh'), 'utf8');
    assert.match(script, /--dkey'? '?ECC32'? '?--ble'? '?--address'? ["']Pixel 6a["'] '?--daemon/);

    /* And gpg-agent --daemon hands --ble to the background agent it starts. */
    const { EventEmitter } = require('events');
    let spawned = null;
    fs.writeFileSync(path.join(parent, 'pubkey.asc'), fs.readFileSync(path.join(home, 'pubkey.asc')));
    const d = await run(['gpg-agent', '--homedir', parent, '--daemon', '--ble', '--address', 'Pixel 6a'], {
      start: () => assert.fail('the parent opened the key'),
      spawnDaemon: (file, args) => {
        spawned = args;
        const c = new EventEmitter();
        c.unref = () => {};
        setImmediate(() => c.emit('message', 'ready'));
        return c;
      },
    });
    assert.equal(d.code, 0, d.err.join('\n'));
    assert.deepEqual(spawned.slice(-3), ['--ble', '--address', 'Pixel 6a']);
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test('--path with --ble, or --address without it, is a usage error', async () => {
  const err = [];
  const io = { out: () => {}, err: (l) => err.push(l), start: () => assert.fail('opened a key') };
  assert.equal(await main(['--ble', '--path', 'x', 'status'], io), 2);
  assert.equal(await main(['--address', 'Pixel 6a', 'status'], io), 2);
  assert.match(err.join('\n'), /use one[\s\S]*add --ble/);
});
