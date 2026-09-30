/*
 * cli/transport-ble.js - an OnlyKey reached over Bluetooth LE, as the byte pipe
 * transport/ble eats.
 *
 * The sibling of ./transport-hid.js. Same pipe contract
 * (src/transport/pipeTransport.js), same direction and echo conventions, same
 * "vendor interface only" rule; what differs is everything below the pipe. On
 * the other end is a phone running ok-rn - a soft key - that publishes the
 * OnlyKey VENDOR interface as a GATT service: the host writes reports to one
 * characteristic, the phone notifies reports on another, and relays both to and
 * from its key unchanged. So what crosses the radio is what would cross a
 * cable, and everything above this file - session, device plugin, okcrypto,
 * the ssh and gpg agents - is the code a USB key runs.
 *
 *   onlykey-js --ble status
 *   onlykey-js --ble --address "Pixel 6a" agent me@example.com
 *
 * WHY IT LIVES UNDER cli/ (see transport-hid.js): both Bluetooth stacks it
 * drives are Node-only - a native WinRT addon on Windows, the D-Bus system
 * socket on Linux - and src/ must stay browser- and Hermes-clean.
 *
 * ## One pipe, two platform links
 *
 * The part that is the same everywhere lives here once: the CTAP-over-BLE
 * framing, reassembly, the echo, holding replies that beat their own write
 * (below), the refusals. Beneath it is a LINK - "connect me to the vendor
 * characteristics, give me write(fragment) and a stream of notifications" -
 * and the link is chosen by process.platform:
 *
 *   win32  @stoprocent/noble over WinRT. Exactly the path the spike proved on
 *          2026-09-29 (NITRO16, no dongle): scan, connect, vendor-only
 *          discovery, subscribe, write with response.
 *   linux  BlueZ's own GATT API over D-Bus (dbus-next). NOT noble: noble's
 *          default Linux backend is raw HCI, which needs root and ignores the
 *          bond BlueZ holds; its dbus backend waits on a Connected change that
 *          never comes when the phone is already connected (its classic
 *          keyboard always is). See openBluezLink for what BlueZ needs instead.
 *
 * A Linux lesson must never change the Windows path, and the reverse: each link
 * is its own function, and the only shared code is the framing, which both
 * proved identically.
 *
 * ## The wire (python-onlykey dc67301 onlykey/transports/ble.py, ok-rn)
 *
 * One 64-byte vendor report per message, framed as CTAP-over-BLE fragments:
 * the first is [0x83][len hi][len lo] + data, each continuation [seq] + data.
 * 0x83 is fixed - the "command" is always "a report". The phone notifies ONE
 * 67-byte fragment per report (83 00 40 + 64 bytes) at the MTU it negotiates;
 * reassembly still accepts continuations, because a host with a small MTU gets
 * them.
 *
 * ## What python needs and this does not: the 400 ms read floor
 *
 * python-onlykey's client polls (read, 100 ms, "empty means the answer is
 * over"), so its BLE transport stretches every empty read to 400 ms - over BLE
 * a reply waits for a connection event, 120-240 ms, and a multi-report answer
 * (OKGETLABELS: 12 reports) comes in bursts 50-120 ms apart. This library does
 * not poll: every report is an event, and the readers wait on their own
 * timeouts (readLabels: 15 s) or quiet windows (250 ms and up, above the
 * burst gap). There is no read here to put a floor under.
 *
 * ## Firmware update is REFUSED
 *
 * An OKFWUPDATE report is refused by this pipe, whatever sent it. The phone
 * relays the vendor interface; it is not a bootloader, and a firmware image
 * half-delivered over a radio link that drops is the one failure a key cannot
 * recover from by itself. The CLI has no firmware command today; this is what
 * keeps one added later from reaching a key through the air.
 */
'use strict';

const { IFACE, DIR } = require('../src/transport/contract');
const { MSG } = require('../src/protocol/msg');

/* ok-rn's vendor service (NativeFidoGattModule.kt). Not advertised - found by discovery. */
const SERVICE_UUID = '0c0ffab0-9f1e-4b1d-9c6a-0f0e1d2c3b4a';
/* host -> phone: write, ENCRYPTED - a bond is required, which is why pairing comes first. */
const REQUEST_UUID = '0c0ffab1-9f1e-4b1d-9c6a-0f0e1d2c3b4a';
/* phone -> host: notify. */
const RESPONSE_UUID = '0c0ffab2-9f1e-4b1d-9c6a-0f0e1d2c3b4a';
/*
 * The FIDO service, which the phone DOES advertise (with its name). A soft key
 * is a FIDO authenticator first; the vendor service rides beside it.
 */
const FIDO_UUID = '0000fffd-0000-1000-8000-00805f9b34fb';

const CMD_REPORT = 0x83;
/* The smallest ATT MTU is 23: 20 bytes of payload per write, no negotiation needed. */
const SMALL_FRAGMENT = 20;
/* 64 bytes and the 3-byte header: the whole report in one write when the MTU allows. */
const WHOLE_REPORT = 64 + 3;

/*
 * How long each stage may take before it is reported as what it is. Scan and
 * connect are the radio; "resolve" is BlueZ discovering (or re-reading) the
 * phone's GATT table after an LE connect.
 */
const TIMEOUTS = { powerMs: 10000, scanMs: 12000, connectMs: 20000, resolveMs: 15000 };

/** An error the CLI prints as a sentence; `code` for callers and tests (see transport-hid.js). */
function bleError(code, message, cause) {
  const err = new Error(message);
  err.code = code;
  if (cause) err.cause = cause;
  return err;
}

/* 128-bit UUID in the two spellings the stacks use: WinRT/noble drop the dashes. */
const bare = (uuid) => uuid.replace(/-/g, '').toLowerCase();
/* An address compared the way a person types it: case and colons do not matter. */
const addrKey = (s) => String(s || '').replace(/[:-]/g, '').toLowerCase();
const looksLikeAddress = (s) => /^[0-9a-f]{12}$/i.test(addrKey(s));

/* ------------------------------------------------------------ framing */

/**
 * Split one report into CTAP-over-BLE fragments of at most `size` bytes.
 * python's _fragment(), byte for byte.
 */
function fragment(payload, size = SMALL_FRAGMENT) {
  const p = Uint8Array.from(payload);
  const first = new Uint8Array(Math.min(size, p.length + 3));
  first.set([CMD_REPORT, (p.length >> 8) & 0xff, p.length & 0xff]);
  first.set(p.subarray(0, size - 3), 3);
  const out = [first];
  for (let off = size - 3, seq = 0; off < p.length; off += size - 1, seq += 1) {
    const chunk = p.subarray(off, off + size - 1);
    const frag = new Uint8Array(chunk.length + 1);
    frag[0] = seq & 0x7f;
    frag.set(chunk, 1);
    out.push(frag);
  }
  return out;
}

/**
 * Reassemble notified fragments into whole reports.
 *
 * A first fragment (high bit set) starts a new message and discards any
 * unfinished one: a notification lost on the air must cost one message, not
 * shift every message after it.
 */
function createAssembler() {
  let buf = null;
  let want = 0;
  return {
    /** @returns {Uint8Array|null} a whole message, or null while one is incomplete */
    push(data) {
      const d = Uint8Array.from(data || []);
      if (!d.length) return null;
      if (d[0] & 0x80) {
        if (d.length < 3) return null;
        want = (d[1] << 8) | d[2];
        buf = d.slice(3);
      } else {
        /* A continuation with no start is noise from before we subscribed. */
        if (!buf) return null;
        const next = new Uint8Array(buf.length + d.length - 1);
        next.set(buf);
        next.set(d.subarray(1), buf.length);
        buf = next;
      }
      if (buf.length < want) return null;
      const message = buf.slice(0, want);
      buf = null;
      return message;
    },
  };
}

/* ------------------------------------------------------------ optional deps */

/**
 * Load an optional peer by name, telling "not installed" from "will not load"
 * the way loadNodeHid does (the fix differs, and a package whose OWN
 * dependency is missing throws the same code).
 */
function loadOptional(name, loader, why) {
  try {
    return loader();
  } catch (err) {
    const escaped = name.replace(/[/@.]/g, (c) => `\\${c}`);
    const missing = err && err.code === 'MODULE_NOT_FOUND'
      && new RegExp(`['"]${escaped}['"]`).test(String(err.message));
    if (missing) {
      throw bleError('ENOBLE',
        `--ble needs "${name}" ${why}, and it is not installed. `
        + 'It is an OPTIONAL PEER of node-onlykey-lib - not installed with it, so the '
        + 'web app and ok-rn never download it - install it next to the library: '
        + `npm install ${name === '@stoprocent/noble' ? '@stoprocent/noble@2.8.0' : name}`,
        err);
    }
    throw bleError('EBLELOAD',
      `"${name}" is installed but failed to load (${err && err.message}). `
      + `Reinstall it for this Node version and platform: npm rebuild ${name}`,
      err);
  }
}

/** @param {() => object} [loader] injectable, so a test can be a machine without it */
function loadNoble(loader = () => require('@stoprocent/noble')) {
  return loadOptional('@stoprocent/noble', loader, 'to reach a phone over Bluetooth on Windows');
}

/** @param {() => object} [loader] injectable */
function loadDbus(loader = () => require('dbus-next')) {
  return loadOptional('dbus-next', loader, 'to reach a phone through BlueZ on Linux');
}

/* ------------------------------------------------------------ helpers */

/** Race `promise` against `ms`; on timeout throw what `onTimeout()` returns. */
function within(promise, ms, onTimeout) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(onTimeout()), ms); }),
  ]).finally(() => clearTimeout(timer));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ------------------------------------------------------------ Windows: noble over WinRT */

/**
 * Find the phone, connect, find the vendor characteristics, subscribe.
 *
 * Every step is the spike's (ble-spike/vendor.js, 2026-09-29), which reached
 * the phone and read OKCONNECT and OKGETLABELS; the notes are what it learned.
 *
 * @returns {Promise<object>} the link: {mtu, write(frag), close(), describe}
 */
async function openNobleLink({ noble, target, onData, onDisconnect, timeouts, log }) {
  const t0 = Date.now();
  try {
    await noble.waitForPoweredOnAsync(timeouts.powerMs);
  } catch (err) {
    throw bleError('EBLEOFF',
      `Bluetooth on this computer is not on (state: ${noble.state}). `
      + 'Turn it on in Settings > Bluetooth & devices.', err);
  }

  /*
   * THE SCAN. The phone advertises its name and the FIDO service from
   * rotating private addresses; WinRT resolves a BONDED phone to its identity
   * address, which is what `--address` may name. `connectable` is NOT
   * checked: WinRT reports false for this phone's connectable advertising.
   * Name and service can come in different packets (advertisement, scan
   * response), so each is remembered per peripheral across events.
   */
  const seen = new Map();
  const wanted = (p) => {
    const a = p.advertisement || {};
    const prev = seen.get(p.id) || { name: '', uuids: new Set() };
    if (a.localName) prev.name = a.localName;
    for (const u of a.serviceUuids || []) prev.uuids.add(String(u).toLowerCase());
    prev.address = p.address;
    seen.set(p.id, prev);
    if (target) {
      if (looksLikeAddress(target)) {
        return addrKey(p.id) === addrKey(target) || addrKey(p.address) === addrKey(target);
      }
      return prev.name.toLowerCase() === target.toLowerCase();
    }
    return prev.uuids.has('fffd') || prev.uuids.has(bare(FIDO_UUID))
      || prev.uuids.has(bare(SERVICE_UUID));
  };
  const peripheral = await new Promise((resolve, reject) => {
    const done = (err, p) => {
      clearTimeout(timer);
      noble.removeListener('discover', onDiscover);
      Promise.resolve(noble.stopScanningAsync()).catch(() => {}).then(() => (err ? reject(err) : resolve(p)));
    };
    const onDiscover = (p) => { if (wanted(p)) done(null, p); };
    const timer = setTimeout(() => {
      const fido = [...seen.entries()].filter(([, v]) => v.uuids.has('fffd') || v.uuids.has(bare(FIDO_UUID)));
      const named = [...seen.values()].filter((v) => v.name).map((v) => `"${v.name}"`);
      done(bleError('ENOPHONE',
        `No phone ${target ? `matching "${target}" ` : 'advertising the FIDO service (0xFFFD) '}`
        + `was seen in ${timeouts.scanMs / 1000} s. Saw ${seen.size} Bluetooth devices`
        + (fido.length ? `; FIDO: ${fido.map(([id, v]) => `${v.name || '(no name)'} ${id}`).join(', ')}` : '; none advertising FIDO')
        + (named.length ? `; names: ${[...new Set(named)].slice(0, 8).join(', ')}` : '')
        + '. Is ok-rn open with its soft key on and Bluetooth on in the phone, and is the phone '
        + 'paired with this computer (Settings > Bluetooth & devices)?'));
    }, timeouts.scanMs);
    noble.on('discover', onDiscover);
    Promise.resolve(noble.startScanningAsync([], true)).catch((err) => done(bleError('ESCAN',
      `Bluetooth scan failed to start: ${err && err.message}`, err)));
  });
  const name = (seen.get(peripheral.id) || {}).name || peripheral.id;
  log(`found ${name} (${peripheral.id}) in ${Date.now() - t0} ms, rssi ${peripheral.rssi}`);

  const onDrop = (reason) => onDisconnect(reason);
  peripheral.once('disconnect', onDrop);
  const giveUp = async () => {
    peripheral.removeListener('disconnect', onDrop);
    try { await peripheral.disconnectAsync(); } catch { /* never connected */ }
  };

  const tc = Date.now();
  try {
    await within(peripheral.connectAsync(), timeouts.connectMs, () => {
      try { peripheral.cancelConnect(); } catch { /* nothing pending */ }
      return bleError('ECONNECT',
        `${name} was seen but did not accept a connection in ${timeouts.connectMs / 1000} s. `
        + 'The phone serves one computer at a time over LE - is another one connected to it?');
    });
  } catch (err) {
    await giveUp();
    throw err.code ? err : bleError('ECONNECT', `could not connect to ${name}: ${err && err.message}`, err);
  }
  log(`connected in ${Date.now() - tc} ms, mtu ${peripheral.mtu}`);

  /*
   * VENDOR-ONLY DISCOVERY. Asking for just the one service and its two
   * characteristics is what the spike did; a full discovery also works but
   * reads the whole table, FIDO and all, on every command.
   */
  let req;
  let rsp;
  try {
    const found = await within(
      peripheral.discoverSomeServicesAndCharacteristicsAsync([bare(SERVICE_UUID)], [bare(REQUEST_UUID), bare(RESPONSE_UUID)]),
      timeouts.resolveMs,
      () => bleError('EDISCOVER', `${name} connected but did not list its services in ${timeouts.resolveMs / 1000} s.`));
    const chars = found.characteristics || [];
    req = chars.find((c) => c.uuid === bare(REQUEST_UUID));
    rsp = chars.find((c) => c.uuid === bare(RESPONSE_UUID));
  } catch (err) {
    await giveUp();
    throw err;
  }
  if (!req || !rsp) {
    await giveUp();
    throw bleError('ENOVENDOR',
      `${name} has no OnlyKey vendor service (${SERVICE_UUID}). Is it the phone running ok-rn, `
      + 'with the soft key on? Another FIDO device nearby can match; choose the phone with --address.');
  }

  /*
   * SUBSCRIBE BEFORE THE FIRST WRITE. The reply to a write can arrive before
   * the write's own acknowledgement does; a subscription made after it would
   * miss it.
   */
  const onNotify = (data) => onData(data);
  rsp.on('data', onNotify);
  try {
    await rsp.subscribeAsync();
  } catch (err) {
    rsp.removeListener('data', onNotify);
    await giveUp();
    throw bleError('ESUBSCRIBE', `could not subscribe to ${name}'s replies: ${err && err.message}`, err);
  }
  log(`subscribed, ${Date.now() - t0} ms from start`);

  return {
    mtu: peripheral.mtu || 23,
    describe: `${name} (${peripheral.id})`,
    /* WITH response: the phone acknowledges each fragment, so a lost one is an error, not silence. */
    write: (frag) => req.writeAsync(Buffer.from(frag), false),
    async close() {
      rsp.removeListener('data', onNotify);
      peripheral.removeListener('disconnect', onDrop);
      try { await rsp.unsubscribeAsync(); } catch { /* link already gone */ }
      try { await peripheral.disconnectAsync(); } catch { /* link already gone */ }
    },
  };
}

/* ------------------------------------------------------------ Linux: BlueZ over D-Bus */

const BLUEZ = 'org.bluez';
const I_OM = 'org.freedesktop.DBus.ObjectManager';
const I_PROPS = 'org.freedesktop.DBus.Properties';
const I_ADAPTER = 'org.bluez.Adapter1';
const I_DEVICE = 'org.bluez.Device1';
const I_SERVICE = 'org.bluez.GattService1';
const I_CHAR = 'org.bluez.GattCharacteristic1';
const FIX = 'scripts/ble-linux-connect.sh "<phone name>"';

/* GetManagedObjects' {path: {iface: {prop: Variant}}}, with the Variants unwrapped. */
function unwrap(managed) {
  const out = {};
  for (const [path, ifaces] of Object.entries(managed || {})) {
    out[path] = {};
    for (const [iface, props] of Object.entries(ifaces || {})) {
      out[path][iface] = {};
      for (const [k, v] of Object.entries(props || {})) {
        out[path][iface][k] = v && typeof v === 'object' && 'value' in v && 'signature' in v ? v.value : v;
      }
    }
  }
  return out;
}

/**
 * Pick the bonded phone among BlueZ's devices.
 *
 * Only PAIRED devices: the request characteristic is encrypted, so an
 * unbonded device could be found and connected and then refuse every write.
 */
function pickBluezDevice(objects, target) {
  const devices = Object.entries(objects)
    .filter(([, i]) => i[I_DEVICE])
    .map(([path, i]) => ({ path, ...i[I_DEVICE] }));
  const paired = devices.filter((d) => d.Paired);
  let matches;
  if (target) {
    matches = paired.filter((d) => (looksLikeAddress(target)
      ? addrKey(d.Address) === addrKey(target)
      : [d.Name, d.Alias].some((n) => n && n.toLowerCase() === target.toLowerCase())));
  } else {
    /*
     * The phone lists the vendor service among its UUIDs once BlueZ has read
     * its GATT table; before that, the FIDO service it advertises.
     */
    const uuids = (d) => (d.UUIDs || []).map((u) => String(u).toLowerCase());
    matches = paired.filter((d) => uuids(d).includes(SERVICE_UUID));
    if (!matches.length) matches = paired.filter((d) => uuids(d).includes(FIDO_UUID));
  }
  /*
   * One phone, one entry: BlueZ can hold the same bonded phone under two
   * paths (an identity-address object and one named after a private address
   * it resolved later). Same Address after resolution = same phone.
   */
  const byAddress = new Map();
  for (const d of matches) {
    const prev = byAddress.get(addrKey(d.Address));
    if (!prev || (d.Connected && !prev.Connected)) byAddress.set(addrKey(d.Address), d);
  }
  const unique = [...byAddress.values()];
  if (unique.length === 1) return unique[0];
  if (unique.length > 1) {
    throw bleError('EMANYPHONE',
      `${unique.length} paired phones match; choose one with --address:\n`
      + unique.map((d) => `  ${d.Address}  "${d.Name || d.Alias || ''}"`).join('\n'));
  }
  const seen = devices.filter((d) => !target || (looksLikeAddress(target)
    ? addrKey(d.Address) === addrKey(target)
    : [d.Name, d.Alias].some((n) => n && n.toLowerCase() === String(target).toLowerCase())));
  throw bleError('ENOBOND',
    (target && seen.length
      ? `"${target}" is known to BlueZ but not paired with this computer. `
      : `No paired phone ${target ? `matching "${target}"` : 'with the OnlyKey vendor or FIDO service'} on this computer. `)
    + `Pair it first: ${FIX}`);
}

/**
 * The vendor characteristics that belong to `device`, wherever BlueZ put them.
 *
 * NEVER A PATH BUILT FROM THE ADDRESS. On the Pi (2026-09-29) the bonded phone
 * with identity 24:29:34:86:EA:AF lived at .../dev_78_8B_B8_DC_65_05 - the
 * path of the private address BlueZ first met it on - and at another time an
 * identity-path object and an RPA-path object existed side by side, the GATT
 * objects under the RPA one. So characteristics are found by UUID, and tied
 * to the phone through their service's `Device` property, accepting any
 * device object with the same resolved Address or Name.
 *
 * `live` is the proof they can be used: BlueZ EXPORTS A BONDED DEVICE'S
 * CACHED GATT TABLE WHILE LE IS DOWN, so a characteristic existing proves
 * nothing - a write to one then fails (org.bluez.Error.Failed) or vanishes.
 * Its device must be Connected AND ServicesResolved. Connected alone is not
 * enough either: the phone's classic keyboard keeps Device1.Connected true
 * with no LE link at all.
 */
function findVendor(objects, device) {
  const same = (path) => {
    const d = objects[path] && objects[path][I_DEVICE];
    if (!d) return false;
    return path === device.path
      || (d.Address && addrKey(d.Address) === addrKey(device.Address))
      /* An RPA-path object is not Paired itself and may still carry the private address. */
      || (d.Name && device.Name && d.Name === device.Name);
  };
  const found = [];
  for (const [path, i] of Object.entries(objects)) {
    const c = i[I_CHAR];
    if (!c || String(c.UUID).toLowerCase() !== REQUEST_UUID) continue;
    const service = objects[c.Service] && objects[c.Service][I_SERVICE];
    if (!service || !same(service.Device)) continue;
    const rspPath = Object.keys(objects).find((p) => objects[p][I_CHAR]
      && objects[p][I_CHAR].Service === c.Service
      && String(objects[p][I_CHAR].UUID).toLowerCase() === RESPONSE_UUID);
    if (!rspPath) continue;
    const dev = objects[service.Device][I_DEVICE];
    found.push({
      req: path, rsp: rspPath, device: service.Device, mtu: c.MTU || objects[rspPath][I_CHAR].MTU || 0,
      live: Boolean(dev.Connected && dev.ServicesResolved),
    });
  }
  return found.find((f) => f.live) || found[0] || null;
}

/** A BlueZ D-Bus error's name and text, whichever fields this dbus-next version fills. */
const dbusWhat = (err) => `${(err && err.type) || ''} ${(err && (err.text || err.message)) || ''}`.trim();

/**
 * Reach the phone's vendor characteristics through BlueZ.
 *
 * The order is the Linux lessons (scripts/ble-linux-connect.sh's header):
 * adapter powered; the phone PAIRED (both ends - the script); if its vendor
 * characteristics are not live, PreferredBearer "le" and Device1.Connect(),
 * because without it BlueZ connects a dual-mode phone over CLASSIC and the GATT
 * table never resolves; then wait for ServicesResolved; then StartNotify
 * BEFORE any write, as on Windows.
 */
async function openBluezLink({ dbus, target, onData, onDisconnect, timeouts, log }) {
  const t0 = Date.now();
  const bus = dbus.systemBus();
  /* A bus with no daemon behind it reports on 'error'; unheard, that would crash the process. */
  let busError = null;
  const onBusError = (err) => { busError = err; };
  if (bus.on) bus.on('error', onBusError);
  const closeBus = () => {
    if (bus.removeListener) bus.removeListener('error', onBusError);
    try { bus.disconnect(); } catch { /* already closed */ }
  };

  const managed = async () => {
    try {
      const root = await bus.getProxyObject(BLUEZ, '/');
      return unwrap(await root.getInterface(I_OM).GetManagedObjects());
    } catch (err) {
      const what = dbusWhat(err) || dbusWhat(busError);
      throw bleError('ENOBLUEZ',
        /ServiceUnknown|not provided|was not provided/i.test(what)
          ? 'BlueZ (bluetoothd) is not running: sudo systemctl start bluetooth'
          : `cannot reach BlueZ on the system D-Bus (${what})`, err);
    }
  };
  const iface = async (path, name) => (await bus.getProxyObject(BLUEZ, path)).getInterface(name);

  try {
    let objects = await managed();

    const adapters = Object.entries(objects).filter(([, i]) => i[I_ADAPTER]);
    if (!adapters.length) {
      throw bleError('ENOADAPTER', `This computer has no Bluetooth adapter BlueZ can use. ${FIX} --fix checks for an rfkill block.`);
    }
    if (!adapters.some(([, i]) => i[I_ADAPTER].Powered)) {
      throw bleError('EBLEOFF',
        'The Bluetooth adapter is off (rfkill-blocked or not powered). '
        + `Run: ${FIX} --fix`);
    }

    const device = pickBluezDevice(objects, target);
    const name = device.Name || device.Alias || device.Address;
    let vendor = findVendor(objects, device);

    if (vendor && vendor.live) {
      log(`${name}: LE link already up (${vendor.device})`);
    } else {
      /*
       * PreferredBearer exists only with bluetoothd's Experimental = true, and
       * only on a device BlueZ knows is dual-mode. Without it Connect() picks
       * classic, which the keyboard already holds, and GATT never comes.
       */
      if (!('PreferredBearer' in device)) {
        throw bleError('EBEARER',
          `BlueZ offers no PreferredBearer for ${name}, so it cannot be told to connect over LE `
          + '(bluetoothd needs Experimental = true, and the phone must have been paired while the '
          + `host was dual-mode). Run: ${FIX} --fix`);
      }
      if (device.PreferredBearer !== 'le') {
        await (await iface(device.path, I_PROPS)).Set(I_DEVICE, 'PreferredBearer', new dbus.Variant('s', 'le'));
      }
      const tc = Date.now();
      try {
        await within((await iface(device.path, I_DEVICE)).Connect(), timeouts.connectMs,
          () => bleError('EBUSY',
            `${name} did not accept an LE connection in ${timeouts.connectMs / 1000} s. `
            + 'The phone serves one computer at a time over LE - is another one (a Windows PC) '
            + 'connected to it? Is ok-rn open with Bluetooth on?'));
      } catch (err) {
        if (err.code) throw err;
        const what = dbusWhat(err);
        if (/AlreadyConnected|InProgress|Already Connected/i.test(what)) {
          /* Someone else's connect (or BlueZ's own reconnect) got there first: the wait below decides. */
        } else if (/br-connection/i.test(what)) {
          throw bleError('ECLASSIC',
            `BlueZ tried to reach ${name} over CLASSIC Bluetooth (${what}), not LE. `
            + `PreferredBearer did not take - run: ${FIX}`, err);
        } else if (/le-connection-abort-by-local|Page Timeout|Host is down|ConnectionAttemptFailed/i.test(what)) {
          throw bleError('EBUSY',
            `${name} did not accept an LE connection (${what}). The phone serves one computer at a `
            + 'time over LE - is another one connected to it? Is ok-rn open with Bluetooth on?', err);
        } else {
          throw bleError('ECONNECT', `could not connect to ${name}: ${what}`, err);
        }
      }
      log(`Connect() returned in ${Date.now() - tc} ms`);

      /*
       * Wait for the GATT table. Polled, not signalled: the object that
       * resolves may be a different device path from the one connected (the
       * RPA split above), and a poll of the whole tree cannot pick the wrong
       * one to listen to.
       */
      const deadline = Date.now() + timeouts.resolveMs;
      for (;;) {
        objects = await managed();
        vendor = findVendor(objects, device);
        if (vendor && vendor.live) break;
        if (Date.now() >= deadline) {
          const d = objects[device.path] && objects[device.path][I_DEVICE];
          throw bleError(d && d.Connected ? 'ECLASSIC' : 'EBUSY',
            d && d.Connected
              ? `${name} is connected but its services never resolved in ${timeouts.resolveMs / 1000} s `
                + `(ServicesResolved ${d.ServicesResolved ? 'true' : 'false'}, vendor service `
                + `${vendor ? 'cached only' : 'not found'}): the link came up CLASSIC, not LE. `
                + `Run: ${FIX}`
              : `${name} did not stay connected (no LE link after ${timeouts.resolveMs / 1000} s). `
                + 'Is another computer connected to the phone?');
        }
        await sleep(250);
      }
      log(`services resolved, ${Date.now() - tc} ms after Connect()`);
    }

    /* Subscribe before any write: replies can beat the write's acknowledgement. */
    const rspProps = await iface(vendor.rsp, I_PROPS);
    const onChanged = (ifaceName, changed) => {
      if (ifaceName !== I_CHAR || !changed || !changed.Value) return;
      const v = changed.Value;
      onData(v && typeof v === 'object' && 'value' in v && 'signature' in v ? v.value : v);
    };
    rspProps.on('PropertiesChanged', onChanged);
    /* LE dropping shows as the device's Connected/ServicesResolved going false. */
    const devProps = await iface(vendor.device, I_PROPS);
    const onDevChanged = (ifaceName, changed) => {
      if (ifaceName !== I_DEVICE || !changed) return;
      const off = (k) => changed[k] && (('value' in changed[k]) ? changed[k].value === false : changed[k] === false);
      if (off('ServicesResolved') || off('Connected')) onDisconnect('the LE link went down');
    };
    devProps.on('PropertiesChanged', onDevChanged);
    const rsp = await iface(vendor.rsp, I_CHAR);
    try {
      await rsp.StartNotify();
    } catch (err) {
      /* BlueZ answers a second StartNotify from the same client this way; still subscribed. */
      if (!/InProgress|Already notifying/i.test(dbusWhat(err))) {
        rspProps.removeListener('PropertiesChanged', onChanged);
        devProps.removeListener('PropertiesChanged', onDevChanged);
        throw bleError('ESUBSCRIBE', `could not subscribe to ${name}'s replies: ${dbusWhat(err)}`, err);
      }
    }
    const req = await iface(vendor.req, I_CHAR);
    log(`subscribed, ${Date.now() - t0} ms from start (mtu ${vendor.mtu || 'unknown'})`);

    return {
      mtu: vendor.mtu || 23,
      describe: `${name} (${vendor.device})`,
      /*
       * type 'request' = write WITH response, as on Windows: the phone
       * acknowledges each fragment. A failure here with LE down is BlueZ's
       * "Not connected"; it is reported by the pipe as the link going away.
       */
      write: (frag) => req.WriteValue(Buffer.from(frag), { type: new dbus.Variant('s', 'request') }),
      /*
       * StopNotify and let go of the bus - but NOT Device1.Disconnect(). That
       * drops every bearer, including the classic keyboard the phone keeps to
       * this computer; the LE link is left for BlueZ to idle out (and for the
       * next command to find already up).
       */
      async close() {
        rspProps.removeListener('PropertiesChanged', onChanged);
        devProps.removeListener('PropertiesChanged', onDevChanged);
        try { await rsp.StopNotify(); } catch { /* link already gone */ }
        closeBus();
      },
    };
  } catch (err) {
    closeBus();
    throw err;
  }
}

/* ------------------------------------------------------------ the pipe */

/**
 * Build the pipe.
 *
 * @param {object} [opts]
 * @param {string} [opts.address]   the phone: an address (any case, colons
 *   optional) or its Bluetooth name; default the one paired phone that
 *   advertises FIDO / lists the vendor service
 * @param {string} [opts.platform]  process.platform; injectable for tests
 * @param {() => object} [opts.loadNoble]  returns @stoprocent/noble (win32)
 * @param {() => object} [opts.loadDbus]   returns dbus-next (linux)
 * @param {object} [opts.timeouts]  overrides TIMEOUTS
 * @param {(line: string) => void} [opts.log]  timings; default stderr when
 *   ONLYKEY_JS_DEBUG is set
 * @returns the pipe contract (start/stop/isRunning/write/on) plus `link`
 */
function createBlePipe({ address, platform = process.platform, loadNoble: ln, loadDbus: ld, timeouts = {}, log } = {}) {
  const listeners = new Set();
  const limits = { ...TIMEOUTS, ...timeouts };
  const trace = log || (process.env.ONLYKEY_JS_DEBUG
    ? (line) => process.stderr.write(`onlykey-js ble: ${line}\n`) : () => {});
  let link = null;
  let lastError = null;
  let assembler = createAssembler();
  /*
   * Writes are serialised: two reports' fragments interleaved on the
   * characteristic would reassemble on the phone as neither.
   */
  let queue = Promise.resolve();
  /*
   * REPLIES THAT BEAT THEIR OWN WRITE. Over USB the echo of a write is always
   * emitted before the reply to it (transport-hid.js). Over BLE the phone's
   * notification can arrive BEFORE the write-with-response resolves - seen on
   * Windows. So while a write is in flight, reports are held, and released
   * after the echo, keeping the order every pipe promises.
   */
  let writing = false;
  let held = [];

  function emit(event) {
    for (const listener of [...listeners]) listener(event);
  }

  function onData(data) {
    const message = assembler.push(data);
    if (!message) return;
    const event = { iface: IFACE.VENDOR, dir: DIR.OUT, bytes: message };
    if (writing) held.push(event);
    else emit(event);
  }

  function onDisconnect(reason) {
    lastError = new Error(`the phone dropped the Bluetooth link${reason ? ` (${reason})` : ''}`);
    const was = link;
    link = null;
    if (was) Promise.resolve(was.close()).catch(() => {});
  }

  async function openLink() {
    const common = { target: address, onData, onDisconnect, timeouts: limits, log: trace };
    /*
     * One branch per platform, and nothing shared below this line: the
     * Windows path is the spike's and stays so whatever Linux needs.
     */
    if (platform === 'win32') return openNobleLink({ noble: loadNoble(ln), ...common });
    if (platform === 'linux') return openBluezLink({ dbus: loadDbus(ld), ...common });
    throw bleError('EBLEPLATFORM',
      `--ble is built and tested on Windows and Linux; this is ${platform}.`);
  }

  return {
    async start() {
      if (link) return { started: true, address: link.describe };
      assembler = createAssembler();
      held = [];
      writing = false;
      link = await openLink();
      lastError = null;
      return { started: true, address: link.describe };
    },

    async stop() {
      const was = link;
      link = null;
      if (was) await was.close();
    },

    isRunning() {
      return link !== null;
    },

    write(iface, bytes) {
      if (iface !== IFACE.VENDOR) {
        return Promise.reject(new Error(
          `the Bluetooth pipe carries only the vendor interface (${IFACE.VENDOR}); `
          + `interface ${iface} is not on this link`));
      }
      const frame = Uint8Array.from(bytes);
      if (frame.length > 4 && frame[0] === 0xff && frame[1] === 0xff && frame[2] === 0xff
        && frame[3] === 0xff && frame[4] === MSG.OKFWUPDATE) {
        return Promise.reject(bleError('EFIRMWARE',
          'Firmware update is refused over Bluetooth. Update a key over USB.'));
      }
      const run = async () => {
        if (!link) {
          throw bleError('ENOTOPEN',
            lastError ? lastError.message : 'the phone is not connected');
        }
        /* One write when the MTU carries the whole report (the phone's 517 does); else the 20-byte floor. */
        const size = link.mtu - 3 >= WHOLE_REPORT ? WHOLE_REPORT : SMALL_FRAGMENT;
        writing = true;
        try {
          for (const piece of fragment(frame, size)) {
            if (!link) throw bleError('ENOTOPEN', lastError ? lastError.message : 'the phone is not connected');
            await link.write(piece);
          }
        } catch (err) {
          writing = false;
          const replies = held;
          held = [];
          for (const e of replies) emit(e);
          throw err.code ? err : bleError('EWRITE', `the phone did not take the write: ${err && err.message}`, err);
        }
        writing = false;
        /* Echo first (dir IN, as every pipe does), then anything that beat it. */
        emit({ iface, dir: DIR.IN, bytes: frame });
        const replies = held;
        held = [];
        for (const e of replies) emit(e);
        return frame.length;
      };
      const result = queue.then(run, run);
      queue = result.catch(() => {});
      return result;
    },

    on(event, listener) {
      if (event !== 'stream') throw new Error(`the Bluetooth pipe has no "${event}" event`);
      listeners.add(listener);
      return () => listeners.delete(listener);
    },

    /** Which phone, once started. */
    get link() { return link ? link.describe : null; },
  };
}

module.exports = {
  createBlePipe, fragment, createAssembler, loadNoble, loadDbus, pickBluezDevice, findVendor,
  SERVICE_UUID, REQUEST_UUID, RESPONSE_UUID, FIDO_UUID, TIMEOUTS,
};
