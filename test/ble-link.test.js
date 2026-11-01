/*
 * cli/ble-link + src/transport/ble-socket - the Bluetooth link the mcp-server holds to a phone, and the room's socket
 * messages over it, on a fake noble (Windows) and a fake dbus-next + BlueZ (Linux), each with a fake phone
 * (helpers/fake-ble.js).
 *
 * No radio, no phone, no native module: this runs anywhere, and cannot reach a real device even on a machine that has
 * one. Under test: the socket messages (open, opened, text in pieces, close), the framing both ways at any MTU, and how
 * each platform link finds and connects the phone - including the BlueZ states the Pi and the box were found in - and
 * the errors a person sees. (The platform-link tests came from the removed cli/transport-ble tests, 2026-10-30.)
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const {
  createBleLink, fragment, createAssembler, loadNoble, loadDbus, pickBluezDevice, CMD_SOCKET,
} = require('../cli/ble-link');
const sock = require('../src/transport/ble-socket');
const { fakeNoble, fakeDbus, piTree } = require('./helpers/fake-ble');

const FAST = { powerMs: 200, scanMs: 300, connectMs: 300, resolveMs: 400 };
const quiet = () => {};

const notInstalled = (name) => () => {
  const err = new Error(`Cannot find module '${name}'\nRequire stack:\n- cli/ble-link.js`);
  err.code = 'MODULE_NOT_FOUND';
  throw err;
};

const winLink = (noble, opts = {}) => createBleLink({ platform: 'win32', loadNoble: () => noble, timeouts: FAST, log: quiet, ...opts });
const linuxLink = (dbus, opts = {}) => createBleLink({ platform: 'linux', loadDbus: () => dbus, timeouts: FAST, log: quiet, ...opts });
const tick = (ms = 20) => new Promise((r) => setTimeout(r, ms));

/*
 * A phone that answers the room's socket as the app does at its simplest: OPEN -> OPENED {host}, each TEXT echoed back
 * as "echo:<text>" (in pieces when long), CLOSE answered with CLOSE.
 */
function socketPhone() {
  const dec = sock.createDecoder();
  const seen = [];
  const onMessage = (cmd, bytes) => {
    if ((cmd & 0x7f) !== (CMD_SOCKET & 0x7f)) return [];
    const ev = dec.push(bytes);
    if (!ev) return [];
    seen.push(ev);
    if (ev.kind === 'open') return [{ cmd: CMD_SOCKET, bytes: sock.encodeOpened({ host: 'ble.test' }) }];
    if (ev.kind === 'text') return sock.encodeText(`echo:${ev.text}`).map((b) => ({ cmd: CMD_SOCKET, bytes: b }));
    if (ev.kind === 'close') return [{ cmd: CMD_SOCKET, bytes: sock.encodeClose({ code: 1000, reason: 'bye' }) }];
    return [];
  };
  return { onMessage, seen };
}

/* sends one socket event's payloads and collects the phone's answers, decoded */
function socketOver(link) {
  const dec = sock.createDecoder();
  const got = [];
  link.on('message', (m) => { if (m.command === CMD_SOCKET) { const ev = dec.push(m.bytes); if (ev) got.push(ev); } });
  return {
    got,
    async send(payloads) { for (const p of payloads) await link.send(CMD_SOCKET, p); },
  };
}

/* ------------------------------------------------------------ the socket messages */

test('socket messages: open, opened, close round-trip; anything else is dropped', () => {
  const d = sock.createDecoder();
  assert.deepEqual(d.push(sock.encodeOpen({ room: 'abc123' })), { kind: 'open', room: 'abc123' });
  assert.deepEqual(d.push(sock.encodeOpened({ host: 'ble:box' })), { kind: 'opened', host: 'ble:box' });
  assert.deepEqual(d.push(sock.encodeClose({ code: 4401, reason: 'refused' })), { kind: 'close', code: 4401, reason: 'refused' });
  assert.equal(d.push(Uint8Array.of(0x7e, 1, 2)), null, 'an unknown kind');
  assert.equal(d.push(Uint8Array.of(sock.KIND.OPEN, 0x7b)), null, 'a broken OPEN');
  assert.equal(d.push(new Uint8Array(0)), null);
});

test('socket messages: a long room message goes in pieces and comes back whole (UTF-8 kept)', () => {
  const text = `{"t":"sealed","rows":"${'é'.repeat(70000)}${'x'.repeat(50000)}"}`;
  const payloads = sock.encodeText(text);
  assert.ok(payloads.length >= 3, 'pieces');
  assert.ok(payloads.every((p) => p.length <= sock.PART_MAX + 1), 'each fits one frame');
  assert.deepEqual(payloads.slice(0, -1).map((p) => p[0]), payloads.slice(0, -1).map(() => sock.KIND.PART));
  assert.equal(payloads.at(-1)[0], sock.KIND.TEXT);
  const d = sock.createDecoder();
  const out = payloads.map((p) => d.push(p));
  assert.ok(out.slice(0, -1).every((x) => x === null));
  assert.deepEqual(out.at(-1), { kind: 'text', text });
  /* a short one is a single TEXT */
  assert.deepEqual(sock.encodeText('{"t":"ping"}').map((p) => p[0]), [sock.KIND.TEXT]);
});

/* ------------------------------------------------------------ framing */

test('framing: a socket message is one write at a large MTU, 20-byte fragments at the floor', () => {
  const msg = sock.encodeText('{"t":"join","x":"' + 'a'.repeat(40) + '"}')[0];
  const whole = fragment(msg, 512);
  assert.equal(whole.length, 1);
  assert.deepEqual(Array.from(whole[0].subarray(0, 3)), [CMD_SOCKET, msg.length >> 8, msg.length & 0xff]);
  const small = fragment(msg, 20);
  assert.ok(small.length > 1);
  assert.equal(small[0][0], CMD_SOCKET);
  assert.deepEqual(small.slice(1).map((f) => f[0]), small.slice(1).map((_, i) => i));
  const a = createAssembler();
  const back = small.map((f) => a.push(f)).at(-1);
  assert.deepEqual(Array.from(back), Array.from(msg));
  assert.equal(back.command, CMD_SOCKET);
});

/* ------------------------------------------------------------ the stacks */

test('a missing noble or dbus-next is named, with the command that installs it', () => {
  assert.throws(() => loadNoble(notInstalled('@stoprocent/noble')), (err) => {
    assert.equal(err.code, 'ENOBLE');
    /* the patched fork, pinned to its commit (2.8.0 hangs on Android 17 phones) */
    assert.match(err.message, /OPTIONAL PEER.*npm install github:bmatusiak\/noble-ble#[0-9a-f]{40}/);
    return true;
  });
  assert.throws(() => loadDbus(notInstalled('dbus-next')), (err) => err.code === 'ENOBLE' && /npm install dbus-next/.test(err.message));
  /* present, but one of ITS dependencies is missing: not "not installed" */
  assert.throws(() => loadNoble(notInstalled('@stoprocent/bluetooth-hci-socket')), { code: 'EBLELOAD' });
});

test('the Bluetooth stack is not loaded until the link opens; another platform is refused by name', async () => {
  let loads = 0;
  const link = createBleLink({ platform: 'win32', loadNoble: () => { loads += 1; return notInstalled('@stoprocent/noble')(); } });
  assert.equal(loads, 0);
  await assert.rejects(() => link.open(), { code: 'ENOBLE' });
  await assert.rejects(() => createBleLink({ platform: 'linux', loadDbus: notInstalled('dbus-next') }).open(), { code: 'ENOBLE' });
  await assert.rejects(() => createBleLink({ platform: 'darwin' }).open(), { code: 'EBLEPLATFORM' });
});

/* ------------------------------------------------------------ Windows: noble */

test('win32: the room socket over the link - open, opened, a message and its answer, close', async () => {
  for (const [mtu, phoneFragment] of [[517, 67], [23, 20]]) {
    const phone = socketPhone();
    const noble = fakeNoble({ onMessage: phone.onMessage, mtu, phoneFragment });
    const link = winLink(noble);
    const s = socketOver(link);
    const p = await link.open();
    assert.equal(p.name, 'Pixel 6a');
    /* vendor-only discovery, subscribed BEFORE any write */
    const kinds = noble.log.map((l) => l[0]);
    assert.ok(kinds.indexOf('subscribe') < kinds.indexOf('write') || !kinds.includes('write'));
    await s.send([sock.encodeOpen({ room: 'r1' })]);
    await s.send(sock.encodeText('{"t":"join"}'));
    await tick();
    assert.deepEqual(phone.seen.map((e) => e.kind), ['open', 'text'], `mtu ${mtu}`);
    assert.deepEqual(s.got, [{ kind: 'opened', host: 'ble.test' }, { kind: 'text', text: 'echo:{"t":"join"}' }], `mtu ${mtu}`);
    const writes = noble.log.filter((l) => l[0] === 'write');
    assert.ok(writes.every((w) => w[2] === false), 'with response');
    assert.equal(writes[0][1].slice(0, 2), '86', 'frame command 0x86');
    await link.close();
    assert.ok(noble.log.some((l) => l[0] === 'disconnect'));
  }
});

test('win32: a long room message crosses the link in pieces, both ways', async () => {
  const phone = socketPhone();
  const link = winLink(fakeNoble({ onMessage: phone.onMessage }));
  const s = socketOver(link);
  await link.open();
  const big = JSON.stringify({ t: 'sealed', rows: 'z'.repeat(130000) });
  await s.send(sock.encodeText(big));
  /* the answer is ~2000 notifications: waited for, 3 s at most */
  for (let i = 0; i < 150 && !s.got.some((e) => e.kind === 'text'); i++) await tick(20);
  assert.equal(phone.seen.at(-1).text, big);
  assert.equal(s.got.at(-1).text, `echo:${big}`);
  await link.close();
});

test('win32: a message longer than one frame allows is refused before anything is sent - 65535 bytes, or 128 continuations at the MTU', async () => {
  const noble = fakeNoble({});
  const link = winLink(noble);
  await link.open();
  await assert.rejects(() => link.send(CMD_SOCKET, new Uint8Array(70000)), { code: 'ETOOLONG' });
  await link.close();
  const small = fakeNoble({ mtu: 23, phoneFragment: 20 });
  const l2 = winLink(small);
  await l2.open();
  /* 17 + 128 x 19 = 2449 bytes fit a 20-byte fragment; 2450 do not */
  await assert.rejects(() => l2.send(CMD_SOCKET, new Uint8Array(2450)), (err) => err.code === 'ETOOLONG' && /128/.test(err.message));
  assert.equal(small.log.filter((l) => l[0] === 'write').length, 0);
  await l2.send(CMD_SOCKET, sock.encodeText('y'.repeat(sock.PART_MAX))[0]);
  await l2.close();
  assert.ok(sock.PART_MAX + 1 <= 17 + 128 * 19, 'a socket piece fits the smallest MTU');
});

test('win32: --address by name or by address; a scan timeout names what it saw', async () => {
  const adverts = [
    { id: 'aabbccddeeff', address: 'aa:bb:cc:dd:ee:ff', localName: 'Other phone', serviceUuids: ['fffd'] },
    { id: '24293486eaaf', address: '24:29:34:86:ea:af', localName: 'Pixel 6a', serviceUuids: ['fffd'] },
  ];
  for (const address of ['Pixel 6a', '24:29:34:86:EA:AF', '24293486EAAF']) {
    const link = winLink(fakeNoble({ adverts, phoneId: '24293486eaaf' }), { address });
    const p = await link.open();
    assert.match(p.address, /24:29:34:86:ea:af/i, address);
    await link.close();
  }
  await assert.rejects(() => winLink(fakeNoble({ adverts }), { address: 'Pixel 7' }).open(), (err) => {
    assert.equal(err.code, 'ENOPHONE');
    assert.match(err.message, /matching "Pixel 7"/);
    assert.match(err.message, /Saw 2 Bluetooth devices; FIDO: Other phone aabbccddeeff, Pixel 6a 24293486eaaf/);
    return true;
  });
});

test('win32: Bluetooth off, a FIDO device without the vendor service, a connect that hangs, a stale cache', async () => {
  await assert.rejects(() => winLink(fakeNoble({ state: 'poweredOff' })).open(), (err) => err.code === 'EBLEOFF' && /poweredOff/.test(err.message));
  const noVendor = fakeNoble({ vendor: false });
  await assert.rejects(() => winLink(noVendor).open(), (err) => err.code === 'ENOVENDOR');
  assert.ok(noVendor.log.some((l) => l[0] === 'disconnect'), 'let go of the wrong device');
  assert.ok(noVendor.log.some((l) => l[0] === 'discoverAll'), 'looked again before giving up');
  /* Windows' cached table lacked the service (2026-10-06): the fresh discovery asks the phone and finds it */
  const cached = fakeNoble({});
  cached.cacheMissesVendor = true;
  const c = winLink(cached);
  await c.open();
  assert.ok(cached.log.some((l) => l[0] === 'discoverAll'));
  await c.close();
  const stale = fakeNoble({});
  stale.staleCache = true;
  const st = winLink(stale);
  await st.open();
  assert.ok(stale.log.some((l) => l[0] === 'discoverAll'));
  await st.close();
  const hangs = fakeNoble({ connectHangs: true });
  await assert.rejects(() => winLink(hangs).open(), (err) => err.code === 'ECONNECT' && /one computer at a time/.test(err.message));
  assert.ok(hangs.log.some((l) => l[0] === 'cancelConnect'));
});

test('win32: a discovery that fails once ("unreachable") reconnects and works', async () => {
  const noble = fakeNoble({ discoverFailsOnce: true });
  const link = winLink(noble);
  await link.open();
  assert.equal(noble.log.filter((l) => l[0] === 'discover').length, 1, 'the quick discovery once');
  assert.equal(noble.log.filter((l) => l[0] === 'discoverAll').length, 1, 'then the whole table');
  assert.equal(link.isUp(), true, 'our own disconnect was not taken as the phone dropping the link');
  await link.close();
});

test('win32: the phone dropping the link says so (down), and a send then fails by name', async () => {
  const noble = fakeNoble({});
  const link = winLink(noble);
  const downs = [];
  link.on('down', (why) => downs.push(why));
  await link.open();
  noble.peripheral('24293486eaaf').emit('disconnect', 'timeout');
  await tick();
  assert.equal(link.isUp(), false);
  assert.equal(downs.length, 1);
  await assert.rejects(() => link.send(CMD_SOCKET, sock.encodeText('{}')[0]), { code: 'ENOTOPEN' });
  /* opened again by its holder, it works */
  await link.open();
  assert.equal(link.isUp(), true);
  await link.close();
});

/* ------------------------------------------------------------ Linux: BlueZ */

test('linux: the LE link already up - no Connect(), the room socket both ways, never Device1.Disconnect', async () => {
  const phone = socketPhone();
  const { tree, rpa } = piTree({ live: true });
  const dbus = fakeDbus({ tree, onMessage: phone.onMessage });
  dbus.addGatt(rpa);
  const link = linuxLink(dbus);
  const s = socketOver(link);
  const p = await link.open();
  assert.equal(p.address, '24:29:34:86:EA:AF');
  await s.send([sock.encodeOpen({ room: 'r1' })]);
  await s.send(sock.encodeText('{"t":"join"}'));
  await tick();
  assert.deepEqual(s.got.map((e) => e.kind), ['opened', 'text']);
  await link.close();
  assert.equal(dbus.calls.filter((c) => c[0] === 'Connect').length, 0);
  const writes = dbus.calls.filter((c) => c[0] === 'WriteValue');
  assert.ok(writes.every((c) => c[1] === `${rpa}/service00a7/char00a8` && c[3] === 'request'), 'write with response, to the request char');
  const order = dbus.calls.map((c) => c[0]);
  assert.ok(order.indexOf('StartNotify') < order.indexOf('WriteValue'), 'subscribed before the first write');
  assert.ok(order.includes('StopNotify') && order.includes('bus.disconnect'));
  assert.ok(!order.includes('Disconnect'), 'never Device1.Disconnect: that would drop the classic keyboard too');
});

test('linux: classic-only (the keyboard), cached GATT - PreferredBearer le, Connect(), then the table resolves', async () => {
  const { tree, rpa } = piTree({ preferredBearer: 'bredr' });
  const dbus = fakeDbus({ tree });
  dbus.addGatt(rpa);
  const link = linuxLink(dbus);
  await link.open();
  assert.deepEqual(dbus.calls.find((c) => c[0] === 'Set').slice(1), [rpa, 'org.bluez.Device1', 'PreferredBearer', 'le']);
  assert.deepEqual(dbus.calls.find((c) => c[0] === 'Connect').slice(1), [rpa, 'le'], 'Connect() after the bearer is set');
  const order = dbus.calls.map((c) => c[0]);
  assert.deepEqual(dbus.calls.find((c) => c[0] === 'SetDiscoveryFilter').slice(1), ['/org/bluez/hci0', 'le']);
  assert.ok(order.indexOf('StartDiscovery') < order.indexOf('Connect'));
  assert.ok(order.indexOf('StopDiscovery') > order.indexOf('Connect'));
  await link.send(CMD_SOCKET, sock.encodeOpen({ room: 'r1' }));
  await tick(10);
  assert.equal(dbus.phone.received.length, 1, 'the message reached the phone whole');
  await link.close();
});

test('linux: the RPA split - bonded identity object, GATT under a private-address object', async () => {
  const { tree, rpa, identity } = piTree({ rpaSplit: true });
  const dbus = fakeDbus({ tree, connect: 'already', gattUnder: rpa });
  const link = linuxLink(dbus);
  await link.open();
  assert.equal(dbus.calls.find((c) => c[0] === 'Connect')[1], identity, 'Connect() on the bonded one');
  await link.send(CMD_SOCKET, sock.encodeOpen({ room: 'r1' }));
  await tick(10);
  assert.equal(dbus.phone.received.length, 1);
  await link.close();
});

test('linux: named errors - no PreferredBearer, never resolves, classic socket, phone busy, off, not paired, no BlueZ', async () => {
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
    await assert.rejects(() => linuxLink(dbus).open(), (err) => {
      assert.equal(err.code, code, `${JSON.stringify(treeOpts)} ${JSON.stringify(dbusOpts)}: ${err.message}`);
      assert.match(err.message, message);
      return true;
    });
    assert.ok(dbus.calls.some((c) => c[0] === 'bus.disconnect'), `${code}: the bus is let go`);
  }
  const noBluez = fakeDbus({ tree: {} });
  const bus = noBluez.systemBus();
  bus.getProxyObject = async () => {
    const e = new Error('The name org.bluez was not provided by any .service files');
    e.type = 'org.freedesktop.DBus.Error.ServiceUnknown';
    throw e;
  };
  await assert.rejects(() => linuxLink({ ...noBluez, systemBus: () => bus }).open(),
    (err) => err.code === 'ENOBLUEZ' && /systemctl start bluetooth/.test(err.message));
});

test('linux: --address by address or name; two paired phones are refused, not guessed', async () => {
  for (const address of ['24:29:34:86:ea:af', 'pixel 6a']) {
    const { tree, rpa } = piTree({ live: true });
    const dbus = fakeDbus({ tree });
    dbus.addGatt(rpa);
    const link = linuxLink(dbus, { address });
    await link.open();
    await link.close();
  }
  const { tree } = piTree();
  tree['/org/bluez/hci0/dev_11_22_33_44_55_66'] = { 'org.bluez.Device1': {
    Address: '11:22:33:44:55:66', Name: 'Pixel 8', Paired: true, Connected: false,
    UUIDs: ['0c0ffab0-9f1e-4b1d-9c6a-0f0e1d2c3b4a'] } };
  await assert.rejects(() => linuxLink(fakeDbus({ tree })).open(),
    (err) => err.code === 'EMANYPHONE' && /--address/.test(err.message) && /Pixel 8/.test(err.message));
});

/*
 * A bonded phone whose cached UUIDs show neither the vendor nor the FIDO service is still found when the holder knows
 * its address (the server's --ble-address; the box, 2026-10-25).
 */
test('pickBluezDevice: a known phone is found by its address when BlueZ cached none of its services', () => {
  const objects = {
    '/org/bluez/hci0/dev_24_29_34_86_EA_AF': { 'org.bluez.Device1': { Address: '24:29:34:86:EA:AF', Name: 'Pixel 6a', Paired: true, UUIDs: ['00001124-0000-1000-8000-00805f9b34fb'] } },
    '/org/bluez/hci0/dev_11_22_33_44_55_66': { 'org.bluez.Device1': { Address: '11:22:33:44:55:66', Name: 'Headphones', Paired: true, UUIDs: [] } },
  };
  assert.throws(() => pickBluezDevice(objects, null), /No paired phone/);
  assert.equal(pickBluezDevice(objects, null, ['24:29:34:86:ea:af']).Name, 'Pixel 6a');
  /* an unpaired device at that address is not picked */
  objects['/org/bluez/hci0/dev_24_29_34_86_EA_AF']['org.bluez.Device1'].Paired = false;
  assert.throws(() => pickBluezDevice(objects, null, ['24:29:34:86:EA:AF']), /No paired phone/);
});
