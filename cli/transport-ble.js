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
/*
 * PART T (onlykey-edge features/BLUETOOTH-PAIRING-SPEC.md): once this computer USER
 * is paired with the phone, every report travels sealed (0x84) after a handshake
 * (0x85, also used to pair). Bluetooth's own encryption is per DEVICE - any user or
 * app on a bonded computer can use it - so the phone answers only a paired user.
 * Each sealed message starts with a kind byte: a key report, or a control message
 * (the weekly renewal) that never reaches the key.
 */
const CMD_SEALED = 0x84;
const CMD_PAIR = 0x85;
const KIND_REPORT = 0x01;
const KIND_CONTROL = 0x02;
const SILENT_MESSAGE = 'no answer from ok-rn - is this computer user paired, and switched on, in ok-rn\'s Bluetooth tab? '
  + '(pair with: onlykey-js --ble pair)';

/**
 * The PHONE's refusal, never a key's reply.
 *
 * ok-rn gates the vendor channel: a write from a computer that is not its
 * Bluetooth target, or while its "API" switch is off, never reaches the key -
 * the phone diverts it and answers with the framing's own ERROR command
 * (CTAP BLE CMD_ERROR, 0xbf; payload one byte, ERR_OTHER 0x7f). No key sends
 * that command, so it cannot be mistaken for firmware. Before it existed the
 * refused write was dropped and this pipe waited out its timeout with no
 * reason to give (ok-rn NativeFidoGattModule.kt refuseVendor).
 */
const CMD_ERROR = 0xbf;

/** What a refusal says: the fix is on the phone, and it names both gates. */
const REFUSED_MESSAGE =
  'the phone refused this request - in ok-rn > Bluetooth, make this computer the Target and switch API on';

/**
 * The last refusal any pipe in this process saw. The CLI reads it to explain a
 * transport timeout: the pipe contract has no error event, so a refusal that
 * arrives while a read is waiting can only be named after the fact.
 */
let lastRefusal = null;
function refusal() { return lastRefusal; }
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
function fragment(payload, size = SMALL_FRAGMENT, cmd = CMD_REPORT) {
  const p = Uint8Array.from(payload);
  const first = new Uint8Array(Math.min(size, p.length + 3));
  first.set([cmd, (p.length >> 8) & 0xff, p.length & 0xff]);
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
  let command = 0;
  return {
    /**
     * @returns {Uint8Array|null} a whole message, or null while one is
     *   incomplete. The message carries the frame's command byte as
     *   `.command` - CMD_REPORT for a key's reply, CMD_ERROR for the phone's
     *   own refusal (see CMD_ERROR).
     */
    push(data) {
      const d = Uint8Array.from(data || []);
      if (!d.length) return null;
      if (d[0] & 0x80) {
        if (d.length < 3) return null;
        command = d[0];
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
      message.command = command;
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
async function openNobleLink({ nobleModule, ...rest }) {
  /*
   * A NOBLE OF OUR OWN, STOPPED ON CLOSE. The module's default export is a
   * process-wide instance whose WinRT manager, once started, keeps Node's
   * event loop alive for good: the first live run printed its answer and then
   * never exited. withBindings('win') makes a fresh instance on the same
   * bindings the default picks on Windows, and stop() deletes its manager,
   * so the process can end - and an agent that reopens the phone after an
   * idle release gets a working instance instead of a stopped one.
   */
  const noble = typeof nobleModule.withBindings === 'function' ? nobleModule.withBindings('win') : nobleModule;
  const stopNoble = () => { try { if (noble.stop) noble.stop(); } catch { /* already stopped */ } };
  let link;
  try {
    link = await nobleSession({ noble, ...rest });
  } catch (err) {
    stopNoble();
    throw err;
  }
  const close = link.close;
  link.close = async () => {
    try { await close(); } finally { stopNoble(); }
  };
  return link;
}

async function nobleSession({ noble, target, onData, onDisconnect, timeouts, log }) {
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
  const discover = async () => {
    const found = await within(
      peripheral.discoverSomeServicesAndCharacteristicsAsync([bare(SERVICE_UUID)], [bare(REQUEST_UUID), bare(RESPONSE_UUID)]),
      timeouts.resolveMs,
      () => bleError('EDISCOVER', `${name} connected but did not list its services in ${timeouts.resolveMs / 1000} s.`));
    const chars = found.characteristics || [];
    req = chars.find((c) => c.uuid === bare(REQUEST_UUID));
    rsp = chars.find((c) => c.uuid === bare(RESPONSE_UUID));
  };
  try {
    await discover();
  } catch (first) {
    /*
     * ONE RETRY (owner, 2026-10-03: pushes now go through the phone, and the
     * third push in a row failed "Device is unreachable while discovering
     * services" - WinRT, while the previous command's link was still being
     * torn down; run again, it worked). Disconnect, let the link settle,
     * connect and discover once more. Once only: a phone that is really
     * gone still fails fast, with the first attempt's words.
     */
    log(`discovery failed (${first && first.message}); reconnecting once`);
    try {
      /* our own disconnect is not the phone dropping the link: unhook that handler around it */
      peripheral.removeListener('disconnect', onDrop);
      try { await peripheral.disconnectAsync(); } catch { /* already down */ }
      await new Promise((r) => setTimeout(r, 1500));
      await within(peripheral.connectAsync(), timeouts.connectMs, () => bleError('ECONNECT', `${name} did not accept the reconnect`));
      peripheral.once('disconnect', onDrop);
      await discover();
    } catch {
      await giveUp();
      throw first;
    }
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
    /*
     * Read at each write, not now: WinRT reports the MTU only after the
     * exchange that follows the connect (null at connect, 517 once
     * subscribed), and a value frozen here fell back to 20-byte fragments.
     */
    get mtu() { return peripheral.mtu || 23; },
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
 * table never resolves - inside an LE discovery session, or the phone's
 * rotating address is never seen; then wait for ServicesResolved; then
 * StartNotify BEFORE any write, as on Windows.
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
      /*
       * AN LE DISCOVERY SESSION AROUND THE CONNECT. Without one, the kernel
       * connects by a PASSIVE scan filtered on the accept list, which holds
       * the phone's IDENTITY address - and the phone advertises only from
       * rotating private addresses, which this controller did not resolve:
       * the Pi's btmon showed the filtered scan and not one advertising report,
       * and Connect() ran into le-connection-abort-by-local after 20 s, phone
       * advertising the whole time (2026-09-29). With a discovery session
       * open, the scan is unfiltered, the host resolves the private address
       * with the bond's IRK, and the same Connect() came up in 0.8 s with the
       * GATT table resolved 1 s later. The session is this D-Bus client's own:
       * stopped here, and BlueZ drops it anyway when the client goes.
       */
      const adapterPath = device.Adapter || adapters.find(([, i]) => i[I_ADAPTER].Powered)[0];
      const adapter = await iface(adapterPath, I_ADAPTER);
      let discovering = false;
      try {
        await adapter.SetDiscoveryFilter({ Transport: new dbus.Variant('s', 'le') });
      } catch (err) {
        log(`SetDiscoveryFilter: ${dbusWhat(err)} (continuing)`);
      }
      try {
        await adapter.StartDiscovery();
        discovering = true;
      } catch (err) {
        /* InProgress: another client is already scanning, which serves as well. */
        log(`StartDiscovery: ${dbusWhat(err)} (continuing)`);
      }
      const tc = Date.now();
      try {
        try {
          await within((await iface(device.path, I_DEVICE)).Connect(), timeouts.connectMs,
            () => bleError('EBUSY',
              `${name} did not accept an LE connection in ${timeouts.connectMs / 1000} s. `
              + 'The phone serves one computer at a time over LE - is another one (a Windows PC) '
              + 'connected to it? Is ok-rn open, with its soft key on?'));
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
              + 'time over LE - is another one connected to it? Is ok-rn open, with its soft key on?', err);
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
            /*
             * Connected but never resolved is one of two things D-Bus cannot
             * tell apart in BlueZ 5.82: the link is classic only (the
             * keyboard's), or an LE link from an earlier connection is up but
             * stale - the Pi was found with exactly that, and its GATT never
             * resolved until the LE link was dropped and made again.
             */
            throw bleError(d && d.Connected ? 'ECLASSIC' : 'EBUSY',
              d && d.Connected
                ? `${name} is connected but its services never resolved in ${timeouts.resolveMs / 1000} s `
                  + `(ServicesResolved ${d.ServicesResolved ? 'true' : 'false'}, vendor service `
                  + `${vendor ? 'cached only' : 'not found'}): the link is classic only, or an LE link left `
                  + 'from an earlier connection is stale. Check PreferredBearer with '
                  + `${FIX}; a stale LE link goes with: sudo hcitool ledc <LE handle from hcitool con> `
                  + '(the classic keyboard link stays up).'
                : `${name} did not stay connected (no LE link after ${timeouts.resolveMs / 1000} s). `
                  + 'Is another computer connected to the phone?');
          }
          await sleep(250);
        }
      } finally {
        if (discovering) {
          try { await adapter.StopDiscovery(); } catch { /* already stopped */ }
        }
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
function createBlePipe({ address, platform = process.platform, loadNoble: ln, loadDbus: ld, timeouts = {}, log, pairing = null, computerName = null, onPairingRenewed = null, now = () => Date.now(), reconnect = true, onLink = null } = {}) {
  const btpair = require('../src/btpair');
  /* Part T: the session (null = plaintext, until this user is paired with this phone) and waiters for 0x85 answers */
  let session = null;
  let pairWaiters = [];
  let renewing = null;
  const listeners = new Set();
  const limits = { ...TIMEOUTS, ...timeouts };
  const trace = log || (process.env.ONLYKEY_JS_DEBUG
    ? (line) => process.stderr.write(`onlykey-js ble: ${line}\n`) : () => {});
  /* the link's own news (down, reconnecting, back): always to onLink - a long-running service shows it - and to the trace */
  const say = (line) => {
    trace(line);
    if (onLink) {
      try { onLink(line); } catch { /* a reporter never breaks the link */ }
    }
  };
  let link = null;
  let lastError = null;
  /* A refusal from the phone; the next write fails with it. See CMD_ERROR. */
  let refused = null;
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
  let wrote = false;

  function emit(event) {
    for (const listener of [...listeners]) listener(event);
  }

  function onData(data) {
    const message = assembler.push(data);
    if (!message) return;
    if (message.command === CMD_PAIR) {
      const w = pairWaiters.shift();
      if (w) w(Uint8Array.from(message));
      return;
    }
    if (message.command === CMD_SEALED) {
      if (!session) return; /* nothing sealed is expected before a handshake */
      let plain;
      try { plain = btpair.open(session, Uint8Array.from(message)); } catch (e) {
        trace(`dropped a sealed frame: ${e.code || e.message}`);
        return;
      }
      if (plain[0] === KIND_CONTROL) { onControl(plain.slice(1)); return; }
      if (plain[0] !== KIND_REPORT) return;
      const sealedEvent = { iface: IFACE.VENDOR, dir: DIR.OUT, bytes: plain.slice(1) };
      if (writing) held.push(sealedEvent);
      else emit(sealedEvent);
      return;
    }
    /* once sealed, a plaintext report from "the phone" is not the phone's: dropped */
    if (session && message.command === CMD_REPORT) { trace('dropped a plaintext report inside a sealed session'); return; }
    if (message.command === CMD_ERROR) {
      /*
       * Not a report: nothing is emitted, so no caller mistakes it for the
       * key's answer. It is remembered instead - the next write fails with it
       * at once, and refusal() lets the CLI replace the transport's bare "no
       * reply within N ms" with the reason.
       */
      refused = bleError('EREFUSED', REFUSED_MESSAGE);
      trace(`the phone refused the request (error frame 0x${(message[0] || 0).toString(16)})`);
      lastRefusal = refused;
      return;
    }
    const event = { iface: IFACE.VENDOR, dir: DIR.OUT, bytes: message };
    if (writing) held.push(event);
    else emit(event);
  }

  /* the phone's renewal offer (day 6 of 7), inside the session: accept, save the new secret, answer sealed */
  function onControl(payload) {
    if (payload[0] !== btpair.T.RENEW_OFFER || !pairing || renewing) return;
    renewing = (async () => {
      const acc = btpair.cliRenewAccept(pairing, payload, now());
      /*
       * Saved BEFORE answering, and TWO-PHASE: the record keeps the current
       * secret with the renewed one beside it (`next`). Whether the answer
       * reaches the phone or the link ends first, the next connection tries
       * `next`, falls back to the current one, and settles it (see start()).
       */
      if (onPairingRenewed) await onPairingRenewed(acc.record);
      pairing = acc.record;
      await sendRaw(CMD_SEALED, btpair.seal(session, concat2(Uint8Array.of(KIND_CONTROL), acc.payload)));
      trace(`pairing renewal sent (epoch ${acc.record.next.epoch} takes over on the next connection)`);
    })().catch((e) => trace(`renewal failed: ${e.message}`)).finally(() => { renewing = null; });
  }

  function concat2(a, b) { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; }

  /* one message on the link (any command), fragmented to the MTU; serialised with every other write */
  function sendRaw(cmd, payload) {
    const run = async () => {
      if (!link) throw bleError('ENOTOPEN', lastError ? lastError.message : 'the phone is not connected');
      const size = link.mtu - 3 >= WHOLE_REPORT ? Math.min(link.mtu - 3, 512) : SMALL_FRAGMENT;
      for (const piece of fragment(payload, size, cmd)) {
        if (!link) throw bleError('ENOTOPEN', lastError ? lastError.message : 'the phone is not connected');
        await link.write(piece);
      }
    };
    const result = queue.then(run, run);
    queue = result.catch(() => {});
    return result;
  }

  /* a 0x85 request and its answer; null after timeoutMs - the phone's silence */
  function pairExchange(bytes, timeoutMs) {
    return new Promise((resolve, reject) => {
      let done = false;
      const waiter = (m) => { if (!done) { done = true; clearTimeout(t); resolve(m); } };
      const t = setTimeout(() => { if (!done) { done = true; pairWaiters = pairWaiters.filter((w) => w !== waiter); resolve(null); } }, timeoutMs);
      pairWaiters.push(waiter);
      sendRaw(CMD_PAIR, bytes).catch((e) => { if (!done) { done = true; clearTimeout(t); reject(e); } });
    });
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
    if (platform === 'win32') return openNobleLink({ nobleModule: loadNoble(ln), ...common });
    if (platform === 'linux') return openBluezLink({ dbus: loadDbus(ld), ...common });
    throw bleError('EBLEPLATFORM',
      `--ble is built and tested on Windows and Linux; this is ${platform}.`);
  }

  /*
   * ONE connect, shared by start() and by a write that finds the link gone
   * (bug 1, 2026-10-05: one refused write ended the edge-agent, and every
   * request after it went nowhere). `started` says the caller wants the link
   * up - set by start(), cleared by stop() - so a deliberate stop is never
   * undone by a reconnect.
   */
  let starting = null;
  let started = false;
  function startLink() {
    if (link) return Promise.resolve({ started: true, address: link.describe, encrypted: !!session });
    if (!starting) starting = connect().finally(() => { starting = null; });
    return starting;
  }

  async function connect() {
    {
      if (link) return { started: true, address: link.describe };
      assembler = createAssembler();
      held = [];
      writing = false;
      wrote = false;
      link = await openLink();
      lastError = null;
      session = null;
      /* Part T: a paired user opens an encrypted session first - fresh keys every connection */
      try {
      if (pairing) {
        /*
         * The computer's CURRENT name, not the one stored at pairing time: the
         * phone binds the pairing to name + Bluetooth address and revokes it when
         * either changes (Brad, 2026-10-04). Sending the stored name would let a
         * renamed computer keep connecting.
         */
        const name = computerName || pairing.name;
        const hello = async (rec) => {
          const h = btpair.cliHello(rec, { name });
          const answer = await pairExchange(h.msg, limits.helloMs || 8000);
          return answer ? btpair.cliOnHelloOk(h.state, answer) : null;
        };
        /* a renewal still settling: the renewed secret first, then the current one (two-phase, btpair phoneOnHello) */
        if (pairing.next) {
          session = await hello(btpair.cliUseNext(pairing));
          const settled = session ? btpair.cliUseNext(pairing) : btpair.cliDropNext(pairing);
          if (!session) session = await hello(settled);
          if (session) {
            pairing = settled;
            if (onPairingRenewed) await onPairingRenewed(pairing);
            trace(`pairing at epoch ${pairing.epoch}`);
          }
        } else {
          session = await hello(pairing);
        }
        if (!session) throw bleError('ESILENT', SILENT_MESSAGE);
        trace('encrypted session open (Part T)');
      }
      } catch (e) {
        /*
         * No session: CLOSE the link we just opened. Found on the A13 (2026-10-05):
         * a reconnect whose hello met silence (the key was still locked) left the
         * link open - Windows kept the connection, the phone showed "connected" and
         * stopped advertising, and the next write went out unencrypted, dropped.
         * A short command never saw it (its process ended); a service did.
         */
        const was = link;
        link = null;
        session = null;
        if (was) await Promise.resolve(was.close()).catch(() => {});
        throw e;
      }
      return { started: true, address: link.describe, encrypted: !!session };
    }
  }

  return {
    async start() {
      const r = await startLink();
      started = true;
      return r;
    },

    /** Part T pairing: one 0x85 message out, its answer back (null = silence). */
    pairExchange,

    /** Whether reports travel sealed on this link. */
    get encrypted() { return !!session; },

    async stop() {
      /*
       * A renewal the phone offered during this connection is answered before
       * the link closes (up to 5 s). Found on the Pixel (2026-10-04): a short
       * command (status) closed the link first, every time, so a pairing used
       * only for short commands could never renew and would expire on day 7.
       */
      if (renewing) await Promise.race([renewing, new Promise((r) => setTimeout(r, 5000))]);
      started = false; /* a deliberate stop: no write reconnects after it */
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
        if (refused) {
          const err = refused;
          refused = null;
          throw err;
        }
        if (!link && started && reconnect) {
          /*
           * The link went down after start() (the phone dropped it, or a write
           * failed below): connect again - Part T's hello included - and say so.
           * Only THIS write waits for it; the one that failed was not retried.
           */
          say(`the Bluetooth link is down (${lastError ? lastError.message : 'closed'}) - reconnecting`);
          try {
            await startLink();
          } catch (e) {
            say(`reconnect failed: ${e && e.message}`);
            throw bleError('ENOTOPEN', `the phone is not connected, and reconnecting failed: ${e && e.message}`, e);
          }
          say(`reconnected${session ? ' (encrypted)' : ''}`);
        }
        if (!link) {
          throw bleError('ENOTOPEN',
            lastError ? lastError.message : 'the phone is not connected');
        }
        /* One write when the MTU carries the whole report (the phone's 517 does); else the 20-byte floor. */
        const size = link.mtu - 3 >= WHOLE_REPORT ? Math.min(link.mtu - 3, 512) : SMALL_FRAGMENT;
        /* Part T: sealed when paired - the echo below stays the plaintext report, as every pipe promises */
        const pieces = session
          ? fragment(btpair.seal(session, concat2(Uint8Array.of(KIND_REPORT), frame)), size, CMD_SEALED)
          : fragment(frame, size);
        if (!wrote) trace(`first write: ${pieces.length} fragment(s) of <= ${size} bytes at mtu ${link.mtu}`);
        wrote = true;
        writing = true;
        try {
          for (const piece of pieces) {
            if (!link) throw bleError('ENOTOPEN', lastError ? lastError.message : 'the phone is not connected');
            await link.write(piece);
          }
        } catch (err) {
          writing = false;
          const replies = held;
          held = [];
          for (const e of replies) emit(e);
          const failed = err.code ? err : bleError('EWRITE', `the phone did not take the write: ${err && err.message}`, err);
          /*
           * A link that refused a write is not trusted with the next one (on
           * 2026-10-05 the A13 refused with status 3, then nothing more got
           * through): drop it, so the next request reconnects. This request
           * fails - a half-sent request is never sent again on its own.
           */
          if (link) {
            const was = link;
            link = null;
            lastError = failed;
            Promise.resolve(was.close()).catch(() => {});
            say(`a write failed (${failed.message}) - link dropped; the next request reconnects`);
          }
          throw failed;
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
  createBlePipe, fragment, createAssembler, loadNoble, loadDbus, pickBluezDevice, findVendor, refusal,
  CMD_ERROR, CMD_REPORT, CMD_SEALED, CMD_PAIR, KIND_REPORT, KIND_CONTROL,
  SERVICE_UUID, REQUEST_UUID, RESPONSE_UUID, FIDO_UUID, TIMEOUTS,
};
