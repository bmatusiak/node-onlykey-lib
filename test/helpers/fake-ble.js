/*
 * Fake Bluetooth stacks for cli/transport-ble.js: a fake @stoprocent/noble
 * MODULE (the Windows link) and a fake dbus-next MODULE over a fake BlueZ
 * object tree (the Linux link), each with a fake PHONE behind it.
 *
 * The phone is what ok-rn does: reassemble the host's CTAP-over-BLE fragments
 * into a 64-byte report, hand it to its key's vendor interface - here
 * test/helpers/fake-firmware.js, or any pipe - and notify each report the key
 * produces back as fragments. Its framing is written out again here rather
 * than borrowed from the code under test, so a bug the two shared would not
 * pass silently.
 *
 * Knobs model what the real stacks were seen to do on 2026-09-29:
 *   notifyBeforeWriteResolves  the reply lands before the write's own ack (WinRT)
 *   phoneFragment              67 = one notification per report at MTU 517;
 *                              20 = a phone limited to the minimum MTU
 */
'use strict';

const { EventEmitter } = require('events');
const { IFACE, DIR } = require('../../src/transport/contract');

const SVC = '0c0ffab09f1e4b1d9c6a0f0e1d2c3b4a';
const REQ = '0c0ffab19f1e4b1d9c6a0f0e1d2c3b4a';
const RSP = '0c0ffab29f1e4b1d9c6a0f0e1d2c3b4a';
const dashed = (u) => `${u.slice(0, 8)}-${u.slice(8, 12)}-${u.slice(12, 16)}-${u.slice(16, 20)}-${u.slice(20)}`;

/**
 * The phone: fragments in, reports to the key, reports out as fragments.
 *
 * @param {object} firmware  a pipe (fake-firmware) standing for the phone's key
 * @param {(frag: Buffer) => void} notify  deliver one notification to the host
 */
function fakePhone({ firmware, phoneFragment = 67, onMessage = null }) {
  let buf = null;
  let want = 0;
  let cmd = 0x83;
  const received = [];      // every whole report the host sent
  const fragments = [];     // every raw fragment written
  let notify = () => {};
  let off = null;

  function frame(report, command = 0x83) {
    const out = [Buffer.concat([Buffer.from([command, report.length >> 8, report.length & 0xff]),
      Buffer.from(report.subarray(0, phoneFragment - 3))])];
    for (let o = phoneFragment - 3, seq = 0; o < report.length; o += phoneFragment - 1, seq += 1) {
      out.push(Buffer.concat([Buffer.from([seq]), Buffer.from(report.subarray(o, o + phoneFragment - 1))]));
    }
    return out;
  }

  return {
    received,
    fragments,
    /** Start relaying the key's reports to `sink` (as the phone does once subscribed). */
    subscribe(sink) {
      notify = sink;
      if (firmware && !off) {
        off = firmware.on('stream', (event) => {
          if (event.dir !== DIR.OUT || event.iface !== IFACE.VENDOR) return;
          for (const f of frame(Uint8Array.from(event.bytes))) notify(f);
        });
      }
    },
    unsubscribe() {
      notify = () => {};
      if (off) { off(); off = null; }
    },
    /** One GATT write from the host. */
    write(frag) {
      const d = Buffer.from(frag);
      fragments.push(d);
      if (d[0] & 0x80) {
        cmd = d[0];
        want = (d[1] << 8) | d[2];
        buf = d.subarray(3);
      } else {
        buf = Buffer.concat([buf, d.subarray(1)]);
      }
      if (buf.length >= want) {
        const report = Uint8Array.from(buf.subarray(0, want));
        received.push(report);
        buf = null;
        /*
         * Part T: a test standing in for ok-rn's gate sees every whole message with its
         * command byte and answers with [{cmd, bytes}] (or nothing: silence).
         */
        if (onMessage) {
          const toKey = (bytes) => firmware && firmware.write(IFACE.VENDOR, bytes);
          const replies = onMessage(cmd, report, toKey) || [];
          for (const r of replies) for (const f of frame(Uint8Array.from(r.bytes), r.cmd)) notify(f);
          return;
        }
        if (firmware) firmware.write(IFACE.VENDOR, report);
      }
    },
    /** Part T: send one whole message to the host with this command byte (a test's gate answering). */
    send(command, bytes) { for (const f of frame(Uint8Array.from(bytes), command)) notify(f); },
    /** Notify raw bytes the host did not ask for (a test's own fragments). */
    raw(frag) { notify(Buffer.from(frag)); },
  };
}

/* ------------------------------------------------------------ noble */

/**
 * A fake @stoprocent/noble module.
 *
 * @param {object} [opts]
 * @param {object[]} [opts.adverts]  what the scan sees: {id, address, localName, serviceUuids}
 * @param {string}  [opts.phoneId]   which advert is the phone (default the first)
 * @param {boolean} [opts.vendor]    the phone has the vendor service (default true)
 * @param {string}  [opts.state]     adapter state (default poweredOn)
 * @param {number}  [opts.mtu]       negotiated MTU (default 517)
 */
function fakeNoble({
  firmware = null, adverts = null, phoneId = null, vendor = true, state = 'poweredOn', mtu = 517,
  phoneFragment = 67, notifyBeforeWriteResolves = false, connectHangs = false,
  /* WinRT right after another command's link: the first discovery fails, the next works */
  discoverFailsOnce = false,
  onMessage = null,
} = {}) {
  const noble = new EventEmitter();
  const phone = fakePhone({ firmware, phoneFragment, onMessage });
  const list = adverts || [{ id: '24293486eaaf', address: '24:29:34:86:ea:af', localName: 'Pixel 6a', serviceUuids: ['fffd'] }];
  const log = [];
  noble.state = state;
  noble.log = log;
  noble.phone = phone;
  let scanning = false;

  noble.waitForPoweredOnAsync = async () => {
    if (noble.state !== 'poweredOn') throw new Error('timeout waiting for poweredOn');
  };
  noble.startScanningAsync = async (uuids, dup) => {
    log.push(['scan', uuids, dup]);
    scanning = true;
    /* Adverts arrive on later turns, as the radio delivers them. */
    for (const a of list) {
      setImmediate(() => {
        if (!scanning) return;
        noble.emit('discover', peripheral(a));
      });
    }
  };
  noble.stopScanningAsync = async () => { scanning = false; log.push(['stopScan']); };
  /* The module's fresh-instance factory, and the teardown that lets the process exit. */
  noble.withBindings = (kind) => { log.push(['withBindings', kind]); return noble; };
  noble.stop = () => { log.push(['stop']); };

  const made = new Map();
  function peripheral(a) {
    if (made.has(a.id)) {
      const p = made.get(a.id);
      p.advertisement = { localName: a.localName, serviceUuids: a.serviceUuids };
      return p;
    }
    const p = new EventEmitter();
    Object.assign(p, {
      id: a.id, address: a.address, rssi: -50, mtu: null, state: 'disconnected',
      advertisement: { localName: a.localName, serviceUuids: a.serviceUuids },
    });
    const isPhone = a.id === (phoneId || list[0].id);
    const req = { uuid: REQ, properties: ['write'] };
    const rsp = Object.assign(new EventEmitter(), { uuid: RSP, properties: ['notify'] });
    req.writeAsync = async (data, withoutResponse) => {
      log.push(['write', Buffer.from(data).toString('hex'), withoutResponse]);
      if (p.state !== 'connected') throw new Error('not connected');
      /* the A13 on 2026-10-05: one write refused (WinRT "status: 3") in the middle of a session */
      if (noble.failNextWrite) {
        const why = noble.failNextWrite;
        noble.failNextWrite = null;
        throw new Error(why);
      }
      if (notifyBeforeWriteResolves) {
        phone.write(data);
        /* The reply has been notified; the ack comes a turn later. */
        await new Promise((r) => setImmediate(r));
        await new Promise((r) => setImmediate(r));
        return;
      }
      await new Promise((r) => setImmediate(r));
      /* The ack first, then the phone acts on it on a later turn. */
      setImmediate(() => phone.write(data));
    };
    rsp.subscribeAsync = async () => {
      log.push(['subscribe']);
      p.mtu = mtu;
      phone.subscribe((frag) => rsp.emit('data', frag, true));
    };
    rsp.unsubscribeAsync = async () => { log.push(['unsubscribe']); phone.unsubscribe(); };
    p.connectAsync = async () => {
      log.push(['connect', p.id]);
      if (connectHangs) return new Promise(() => {});
      p.state = 'connected';
      /* WinRT: no MTU yet at connect; it is known once the exchange after it is done. */
      p.mtu = null;
      return undefined;
    };
    p.cancelConnect = () => { log.push(['cancelConnect']); };
    p.disconnectAsync = async () => {
      log.push(['disconnect', p.id]);
      const was = p.state;
      p.state = 'disconnected';
      phone.unsubscribe();
      if (was === 'connected') setImmediate(() => p.emit('disconnect'));
    };
    p.discoverSomeServicesAndCharacteristicsAsync = async (svcs, chars) => {
      log.push(['discover', svcs, chars]);
      if (isPhone && discoverFailsOnce) {
        discoverFailsOnce = false;
        throw new Error('Device is unreachable while discovering services');
      }
      if (!isPhone || !vendor) return { services: [], characteristics: [] };
      return { services: [{ uuid: SVC }], characteristics: [req, rsp] };
    };
    made.set(a.id, p);
    return p;
  }
  noble.peripheral = (id) => made.get(id);
  return noble;
}

/* ------------------------------------------------------------ dbus-next + BlueZ */

class Variant {
  constructor(signature, value) { this.signature = signature; this.value = value; }
}

class DBusError extends Error {
  constructor(type, text) { super(text); this.type = type; this.text = text; }
}

const DEV = 'org.bluez.Device1';
const CHAR = 'org.bluez.GattCharacteristic1';

/**
 * A fake dbus-next module over a fake BlueZ.
 *
 * `tree` is {path: {iface: {prop: plainValue}}}; GetManagedObjects wraps the
 * values in Variants, as dbus-next does. `connect` decides what
 * Device1.Connect() does:
 *   'ok'         the LE link comes up: the device at `gattUnder` becomes
 *                Connected + ServicesResolved and its vendor GATT objects appear
 *   'already'    org.bluez.Error.AlreadyConnected, then as 'ok'
 *   'never'      returns, but ServicesResolved never goes true
 *   'br-socket'  org.bluez.Error.Failed br-connection-create-socket
 *   'abort'      org.bluez.Error.Failed le-connection-abort-by-local
 * With `needsDiscovery` (the default, as on the Pi) an 'ok' or 'already'
 * connect with no LE discovery session open never completes: the kernel's
 * accept-list scan never sees the phone's rotating address.
 */
function fakeDbus({ tree, firmware = null, connect = 'ok', gattUnder = null, phoneFragment = 67, mtu = 517, needsDiscovery = true }) {
  let discovering = false;
  const phone = fakePhone({ firmware, phoneFragment });
  const signals = new Map();     // path -> EventEmitter for PropertiesChanged
  const calls = [];
  const emitter = (path) => {
    if (!signals.has(path)) signals.set(path, new EventEmitter());
    return signals.get(path);
  };
  const setProps = (path, iface, changed) => {
    Object.assign(tree[path][iface], changed);
    const wrapped = {};
    for (const [k, v] of Object.entries(changed)) wrapped[k] = new Variant('?', v);
    emitter(path).emit('PropertiesChanged', iface, wrapped, []);
  };

  function addGatt(devPath) {
    const svc = `${devPath}/service00a7`;
    tree[svc] = { 'org.bluez.GattService1': { UUID: dashed(SVC), Device: devPath, Primary: true } };
    tree[`${svc}/char00a8`] = { [CHAR]: { UUID: dashed(REQ), Service: svc, Flags: ['write'], MTU: mtu } };
    tree[`${svc}/char00aa`] = { [CHAR]: { UUID: dashed(RSP), Service: svc, Flags: ['notify'], MTU: mtu, Notifying: false } };
  }

  function linkUp(devPath) {
    const at = gattUnder || devPath;
    if (!tree[`${at}/service00a7`]) addGatt(at);
    setProps(at, DEV, { Connected: true, ServicesResolved: true });
  }

  function iface(path, name) {
    const node = tree[path];
    if (name === 'org.freedesktop.DBus.ObjectManager') {
      return {
        async GetManagedObjects() {
          calls.push(['GetManagedObjects']);
          const out = {};
          for (const [p, ifs] of Object.entries(tree)) {
            out[p] = {};
            for (const [i, props] of Object.entries(ifs)) {
              out[p][i] = {};
              for (const [k, v] of Object.entries(props)) out[p][i][k] = new Variant('?', v);
            }
          }
          return out;
        },
      };
    }
    if (name === 'org.freedesktop.DBus.Properties') {
      const e = emitter(path);
      return {
        async Set(i, prop, variant) {
          calls.push(['Set', path, i, prop, variant.value]);
          setProps(path, i, { [prop]: variant.value });
        },
        on: (ev, fn) => e.on(ev, fn),
        removeListener: (ev, fn) => e.removeListener(ev, fn),
      };
    }
    if (!node || !node[name]) throw new DBusError('org.freedesktop.DBus.Error.UnknownObject', `no ${name} at ${path}`);
    if (name === DEV) {
      return {
        async Connect() {
          calls.push(['Connect', path, tree[path][DEV].PreferredBearer]);
          if (connect === 'br-socket') throw new DBusError('org.bluez.Error.Failed', 'br-connection-create-socket');
          if (connect === 'abort') throw new DBusError('org.bluez.Error.Failed', 'le-connection-abort-by-local');
          if (connect === 'never') return;
          if (needsDiscovery && !discovering) return new Promise(() => {});
          setTimeout(() => linkUp(path), 5);
          if (connect === 'already') throw new DBusError('org.bluez.Error.AlreadyConnected', 'Already Connected');
        },
        async Disconnect() { calls.push(['Disconnect', path]); },
      };
    }
    if (name === 'org.bluez.Adapter1') {
      return {
        async SetDiscoveryFilter(filter) { calls.push(['SetDiscoveryFilter', path, filter.Transport && filter.Transport.value]); },
        async StartDiscovery() { calls.push(['StartDiscovery', path]); discovering = true; },
        async StopDiscovery() { calls.push(['StopDiscovery', path]); discovering = false; },
      };
    }
    if (name === CHAR) {
      return {
        async StartNotify() {
          calls.push(['StartNotify', path]);
          phone.subscribe((frag) => emitter(path).emit('PropertiesChanged', CHAR, { Value: new Variant('ay', frag) }, []));
        },
        async StopNotify() { calls.push(['StopNotify', path]); phone.unsubscribe(); },
        async WriteValue(buf, opts) {
          calls.push(['WriteValue', path, Buffer.from(buf).toString('hex'), opts.type && opts.type.value]);
          const dev = tree[tree[tree[path][CHAR].Service]['org.bluez.GattService1'].Device][DEV];
          if (!(dev.Connected && dev.ServicesResolved)) throw new DBusError('org.bluez.Error.Failed', 'Not connected');
          await new Promise((r) => setImmediate(r));
          setImmediate(() => phone.write(buf));
        },
      };
    }
    return {};
  }

  const bus = new EventEmitter();
  bus.getProxyObject = async (service, path) => {
    if (service !== 'org.bluez') throw new DBusError('org.freedesktop.DBus.Error.ServiceUnknown', 'The name org.bluez was not provided');
    return { getInterface: (name) => iface(path, name) };
  };
  bus.disconnect = () => { calls.push(['bus.disconnect']); };

  return { systemBus: () => bus, Variant, calls, phone, tree, addGatt, linkUp };
}

/** The Pi as it was found on 2026-09-29, before any LE connect. */
function piTree({ preferredBearer = 'le', rpaSplit = false, powered = true, paired = true, live = false } = {}) {
  const tree = {
    '/org/bluez/hci0': { 'org.bluez.Adapter1': { Address: 'DC:A6:32:00:00:01', Powered: powered } },
  };
  const phone = {
    Address: '24:29:34:86:EA:AF', AddressType: 'public', Name: 'Pixel 6a', Alias: 'Pixel 6a', Adapter: '/org/bluez/hci0',
    Paired: paired, Bonded: paired, Trusted: true,
    /* The classic keyboard link: Connected with no LE, so nothing resolved. */
    Connected: true, ServicesResolved: live,
    UUIDs: ['0000fffd-0000-1000-8000-00805f9b34fb', '0c0ffab0-9f1e-4b1d-9c6a-0f0e1d2c3b4a'],
  };
  if (preferredBearer !== null) phone.PreferredBearer = preferredBearer;
  /*
   * The phone lived at the path of the private address BlueZ first met it
   * on, not at dev_24_29_34_86_EA_AF. With rpaSplit, an identity-path object
   * exists too, and the GATT objects are under the RPA one.
   */
  const rpa = '/org/bluez/hci0/dev_78_8B_B8_DC_65_05';
  if (rpaSplit) {
    tree['/org/bluez/hci0/dev_24_29_34_86_EA_AF'] = { [DEV]: { ...phone, ServicesResolved: false } };
    tree[rpa] = { [DEV]: { ...phone, Address: '78:8B:B8:DC:65:05', AddressType: 'random', Paired: false, Bonded: false, Connected: live, ServicesResolved: live } };
  } else {
    tree[rpa] = { [DEV]: phone };
  }
  return { tree, rpa, identity: '/org/bluez/hci0/dev_24_29_34_86_EA_AF' };
}

module.exports = { fakeNoble, fakeDbus, fakePhone, piTree, Variant, DBusError };
