/*
 * cli/ble-link.js - a Bluetooth LE link to a phone running the OnlyKey app: whole framed MESSAGES both ways.
 *
 * THE LINK CAME BACK WITHOUT ITS GATE (Brad, 2026-11-01: "the ble work comes back, the cli pair code stuff that gates
 * communication is replaced"; "the mcp server should make communication with ble transparent - the phone asks over ble
 * to talk to the mcp-server like it was connected to it over websockets"). Until 2026-10-30 this was
 * cli/transport-ble.js, the vendor-report pipe of `onlykey-js --ble`, sealed by the cli pair (tag
 * ble-cli-pair-removal). Now it is the radio only: the mcp-server holds the link (ok-edge mcp-server/src/localhost)
 * and the room's messages ride it as 0x86 socket messages (../src/transport/ble-socket.js) - the room's join is the
 * gate, as over a websocket. Nothing here knows what a message means.
 *
 * The phone publishes the OnlyKey VENDOR service as a GATT service (ok-edge VendorGattService.kt): the host writes
 * fragments to one characteristic, the phone notifies on another, and its native layer passes each whole message, with
 * its command byte, to the app unread.
 *
 * WHY IT LIVES UNDER cli/: both Bluetooth stacks it drives are Node-only - a native WinRT addon on Windows, the D-Bus
 * system socket on Linux - and src/ must stay browser- and Hermes-clean.
 *
 * ## One framing, two platform links
 *
 * The part that is the same everywhere lives here once: the CTAP-over-BLE framing and reassembly. Beneath it is a
 * LINK - "connect me to the vendor characteristics, give me write(fragment) and a stream of notifications" - chosen
 * by process.platform:
 *
 *   win32  @stoprocent/noble over WinRT (the fork - see NOBLE_FORK). Exactly the path the spike proved on 2026-09-29
 *          (NITRO16, no dongle): scan, connect, vendor-only discovery, subscribe, write with response.
 *   linux  BlueZ's own GATT API over D-Bus (dbus-next). NOT noble: noble's default Linux backend is raw HCI, which
 *          needs root and ignores the bond BlueZ holds; its dbus backend waits on a Connected change that never comes
 *          when the phone is already connected (its classic keyboard always is). See openBluezLink.
 *
 * A Linux lesson must never change the Windows path, and the reverse: each link is its own function, and the only
 * shared code is the framing, which both proved identically.
 *
 * ## The wire (python-onlykey dc67301 onlykey/transports/ble.py)
 *
 * A message is framed as CTAP-over-BLE fragments: the first is [cmd][len hi][len lo] + data, each continuation
 * [seq] + data. The command byte says what the message is (0x86: a room socket message); the length is 16 bits, so a
 * message is at most 65535 bytes (ble-socket.js sends longer room messages in pieces).
 */
'use strict';

/* the phone's vendor service (ok-edge VendorGattService.kt). Not advertised - found by discovery. */
const SERVICE_UUID = '0c0ffab0-9f1e-4b1d-9c6a-0f0e1d2c3b4a';
/* host -> phone: write, ENCRYPTED - a Bluetooth bond is required (scripts/ble-linux-connect.sh, or Windows Settings). */
const REQUEST_UUID = '0c0ffab1-9f1e-4b1d-9c6a-0f0e1d2c3b4a';
/* phone -> host: notify. */
const RESPONSE_UUID = '0c0ffab2-9f1e-4b1d-9c6a-0f0e1d2c3b4a';
/*
 * The FIDO service, which the phone DOES advertise (with its name). A soft key
 * is a FIDO authenticator first; the vendor service rides beside it.
 */
const FIDO_UUID = '0000fffd-0000-1000-8000-00805f9b34fb';

/*
 * THE FRAME COMMANDS this link is used with. 0x86: the room's socket messages (../src/transport/ble-socket.js). 0xbf
 * is the framing's own ERROR command, which no app message uses. The cli pair's 0x83 report / 0x84 sealed / 0x85
 * handshake went with it (2026-10-30); the phone answers none of them now.
 */
const { CMD_SOCKET } = require('../src/transport/ble-socket');
const CMD_ERROR = 0xbf;
/* the frame's length field is 16 bits */
const MAX_MESSAGE = 0xffff;

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
/* connecting straight to --address, and its first service list: a phone that is not there falls back to the scan after this */
const DIRECT_MS = 4000;
/* an advertising phone is seen in 50-300 ms once the scan runs, but Windows starts its scan slowly: 0.5 s missed it (A13); not seen by then, a link is probably still held */
const QUICK_SCAN_MS = 1200;
const looksLikeAddress = (s) => /^[0-9a-f]{12}$/i.test(addrKey(s));

/* ------------------------------------------------------------ framing */

/**
 * Split one message into CTAP-over-BLE fragments of at most `size` bytes.
 * python's _fragment(), byte for byte.
 */
function fragment(payload, size = SMALL_FRAGMENT, cmd = CMD_SOCKET) {
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
 * Reassemble notified fragments into whole messages.
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
     *   `.command`.
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
/*
 * THE NOBLE FORK (2026-10-07). stoprocent/noble 2.8.0 hangs on Windows against an
 * Android 17 phone: it asks for the WHOLE service table uncached, Windows fails that
 * with E_UNEXPECTED once Google Play services have moved the phone's GATT handles,
 * and the failure is lost inside its native handler - "did not list its services".
 * bmatusiak/noble-ble fix/win-discovery asks for our one service by UUID and reports
 * failures (2.8.0-bm.1). Proven on the Pixel 6a: 0 of 2 before, 6 of 6 after.
 *
 * 2.8.0-bm.2 (2026-10-28) installs without compiling: its Windows prebuilds are rebuilt from that fix,
 * and it has no install step - npm 11 broke a GLOBAL install of a git dependency with one (the
 * dependency's preparation inherits -g and its node-gyp-build is not there), so `npm install -g
 * bmatusiak/onlykey-js` - the CLI in one install - lost Bluetooth on Windows.
 */
const NOBLE_FORK = 'github:bmatusiak/noble-ble#d16fc663a0169d69c7f6a467974ce8d2c799d006';
const NOBLE_FORK_VERSION = '2.8.0-bm.2';

function loadOptional(name, loader, why) {
  try {
    return loader();
  } catch (err) {
    const escaped = name.replace(/[/@.]/g, (c) => `\\${c}`);
    const missing = err && err.code === 'MODULE_NOT_FOUND'
      && new RegExp(`['"]${escaped}['"]`).test(String(err.message));
    if (missing) {
      throw bleError('ENOBLE',
        `Bluetooth needs "${name}" ${why}, and it is not installed. `
        + 'It is an OPTIONAL PEER of node-onlykey-lib - not installed with it, so the '
        + 'web app and the phone app never download it - install it next to the library: '
        + `npm install ${name === '@stoprocent/noble' ? NOBLE_FORK : name}`,
        err);
    }
    throw bleError('EBLELOAD',
      `"${name}" is installed but failed to load (${err && err.message}). `
      + `Reinstall it for this Node version and platform: npm rebuild ${name}`,
      err);
  }
}

/** @param {() => object} [loader] injectable, so a test can be a machine without it */
let nobleChecked = false;
function loadNoble(loader) {
  const injected = Boolean(loader);
  const noble = loadOptional('@stoprocent/noble', loader || (() => require('@stoprocent/noble')), 'to reach a phone over Bluetooth on Windows');
  /* the real install only (tests inject their own), once: say so if it is not the fork */
  if (!injected && !nobleChecked) {
    nobleChecked = true;
    let version = null;
    try { version = require('@stoprocent/noble/package.json').version; } catch { /* no package.json export: say nothing */ }
    if (version && version !== NOBLE_FORK_VERSION) {
      process.stderr.write(`onlykey-js ble: @stoprocent/noble ${version} is not the patched fork (${NOBLE_FORK_VERSION}) - `
        + `against an Android 17 phone its service discovery can hang ("did not list its services"). Install: npm install ${NOBLE_FORK}\n`);
    }
  }
  return noble;
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
  const scan = (quickMs = 0) => new Promise((resolve, reject) => {
    const done = (err, p) => {
      clearTimeout(timer);
      noble.removeListener('discover', onDiscover);
      Promise.resolve(noble.stopScanningAsync()).catch(() => {}).then(() => (err ? reject(err) : resolve(p)));
    };
    const onDiscover = (p) => { if (wanted(p)) done(null, p); };
    const timer = setTimeout(() => {
      if (quickMs) { done(null, null); return; }
      const fido = [...seen.entries()].filter(([, v]) => v.uuids.has('fffd') || v.uuids.has(bare(FIDO_UUID)));
      const named = [...seen.values()].filter((v) => v.name).map((v) => `"${v.name}"`);
      done(bleError('ENOPHONE',
        `No phone ${target ? `matching "${target}" ` : 'advertising the FIDO service (0xFFFD) '}`
        + `was seen in ${timeouts.scanMs / 1000} s. Saw ${seen.size} Bluetooth devices`
        + (fido.length ? `; FIDO: ${fido.map(([id, v]) => `${v.name || '(no name)'} ${id}`).join(', ')}` : '; none advertising FIDO')
        + (named.length ? `; names: ${[...new Set(named)].slice(0, 8).join(', ')}` : '')
        /* the OnlyKey app starts Bluetooth only after its login (App.tsx RadioStatus): logged out = not advertising */
        + '. Is the OnlyKey app open and logged in (it is not on Bluetooth while logged out), with Bluetooth on in the phone, '
        + 'and is the phone paired with this computer (Settings > Bluetooth & devices)?'));
    }, quickMs || timeouts.scanMs);
    noble.on('discover', onDiscover);
    Promise.resolve(noble.startScanningAsync([], true)).catch((err) => done(bleError('ESCAN',
      `Bluetooth scan failed to start: ${err && err.message}`, err)));
  });

  /*
   * STRAIGHT TO A KNOWN ADDRESS (A13, 2026-10-07). Windows keeps the LE link ~3 s
   * after a command closes it - neither side's hang-up ends it sooner - and while it
   * is up the phone does not advertise, so the next command's scan waited for the
   * drop (up to 4.8 s). Connecting by address takes the link Windows still holds
   * (~0.6 s to a link up in 1.9-2.2 s, measured). But with no link held, Windows
   * finding the phone by address took over 4 s, where a scan sees it in 50-300 ms.
   * So with --address: a short look first (an advertising phone is seen at once),
   * then straight to the address (a link is still held), then the full scan, which
   * says what it saw. The straight path gets a short time and no slow retry.
   */
  const quick = target && looksLikeAddress(target) && typeof noble.connectAsync === 'function'
    ? await scan(QUICK_SCAN_MS) : null;
  if (quick) {
    log(`found ${(seen.get(quick.id) || {}).name || quick.id} (${quick.id}) in ${Date.now() - t0} ms, rssi ${quick.rssi}`);
    return linkUp(quick, { connected: false, resolveMs: timeouts.resolveMs, retry: true });
  }
  if (target && looksLikeAddress(target) && typeof noble.connectAsync === 'function') {
    const td = Date.now();
    let direct = null;
    try {
      direct = await within(noble.connectAsync(addrKey(target)), DIRECT_MS,
        () => bleError('ECONNECT', `no answer in ${DIRECT_MS / 1000} s`));
      log(`connected straight to ${direct.id} in ${Date.now() - td} ms - no scan`);
      return await linkUp(direct, { connected: true, resolveMs: DIRECT_MS, retry: false });
    } catch (e) {
      log(`straight to ${addrKey(target)}: ${e.message} - scanning`);
      try { noble.cancelConnect(addrKey(target)); } catch { /* nothing pending */ }
      if (direct) { try { await direct.disconnectAsync(); } catch { /* not connected */ } }
    }
  }
  const scanned = await scan();
  log(`found ${(seen.get(scanned.id) || {}).name || scanned.id} (${scanned.id}) in ${Date.now() - t0} ms, rssi ${scanned.rssi}`);
  return linkUp(scanned, { connected: false, resolveMs: timeouts.resolveMs, retry: true });

  async function linkUp(peripheral, { connected, resolveMs, retry }) {
    const name = (seen.get(peripheral.id) || {}).name || peripheral.id;
    const onDrop = (reason) => onDisconnect(reason);
    peripheral.once('disconnect', onDrop);
    const giveUp = async () => {
      peripheral.removeListener('disconnect', onDrop);
      try { await peripheral.disconnectAsync(); } catch { /* never connected */ }
    };

    const tc = Date.now();
    if (!connected) try {
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
    if (!connected) log(`connected in ${Date.now() - tc} ms, mtu ${peripheral.mtu}`);

    /*
     * VENDOR-ONLY DISCOVERY. Asking for just the one service and its two
     * characteristics is what the spike did; a full discovery also works but
     * reads the whole table, FIDO and all, on every command.
     */
    let req;
    let rsp;
    /*
     * fresh: the WHOLE table, asked of the phone itself. The quick vendor-only
     * discovery is served from Windows' cache, and after the phone app was
     * reinstalled its services sat at other handles - Windows connected every
     * 35 s and never listed them (the Pixel, 2026-10-05: FIDO moved to handle
     * 200). The full discovery is uncached in noble's WinRT code, so the retry
     * uses it: the cache is refreshed from the phone instead of trusted again.
     */
    const discover = async (fresh = false) => {
      const found = await within(
        fresh
          ? peripheral.discoverAllServicesAndCharacteristicsAsync()
          : peripheral.discoverSomeServicesAndCharacteristicsAsync([bare(SERVICE_UUID)], [bare(REQUEST_UUID), bare(RESPONSE_UUID)]),
        resolveMs,
        () => bleError('EDISCOVER', `${name} connected but did not list its services in ${resolveMs / 1000} s.`));
      const chars = found.characteristics || [];
      req = chars.find((c) => c.uuid === bare(REQUEST_UUID));
      rsp = chars.find((c) => c.uuid === bare(RESPONSE_UUID));
    };
    let first = null;
    try {
      await discover();
    } catch (e) {
      first = e;
    }
    /*
     * A table WITHOUT our service gets the same retry (Brad, 2026-10-06: an agent
     * restarted right after the old one was killed listed no vendor service, twice
     * 5 s apart, while the phone saw no new connection at all - Windows answered
     * from its cache over the dead process's link). The fresh discovery asks the
     * phone itself; a FIDO device that really has no vendor service still ends in
     * ENOVENDOR below.
     */
    if (!retry && (first || !req || !rsp)) {
      await giveUp();
      throw first || bleError('ENOVENDOR', `${name} listed no OnlyKey vendor service`);
    }
    if (first || !req || !rsp) {
      /*
       * ONE RETRY (owner, 2026-10-03: pushes now go through the phone, and the
       * third push in a row failed "Device is unreachable while discovering
       * services" - WinRT, while the previous command's link was still being
       * torn down; run again, it worked). Disconnect, let the link settle,
       * connect and discover once more. Once only: a phone that is really
       * gone still fails fast, with the first attempt's words.
       */
      log(`discovery ${first ? `failed (${first.message})` : 'listed no vendor service'}; reconnecting once, asking the phone for its whole table`);
      try {
        /* our own disconnect is not the phone dropping the link: unhook that handler around it */
        peripheral.removeListener('disconnect', onDrop);
        try { await peripheral.disconnectAsync(); } catch { /* already down */ }
        await new Promise((r) => setTimeout(r, 1500));
        await within(peripheral.connectAsync(), timeouts.connectMs, () => bleError('ECONNECT', `${name} did not accept the reconnect`));
        peripheral.once('disconnect', onDrop);
        await discover(true);
      } catch {
        /* a failed discovery keeps the first attempt's words; a table without our service ends in ENOVENDOR below */
        if (first) { await giveUp(); throw first; }
      }
    }
    if (!req || !rsp) {
      await giveUp();
      throw bleError('ENOVENDOR',
        `${name} has no OnlyKey vendor service (${SERVICE_UUID}). Is it the phone running the OnlyKey app, `
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
      /* the phone this link reached, whatever --address said (a name, a MAC, nothing) */
      address: peripheral.address || peripheral.id,
      name,
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
}

/* ------------------------------------------------------------ Linux: BlueZ over D-Bus */

const BLUEZ = 'org.bluez';
const I_OM = 'org.freedesktop.DBus.ObjectManager';
const I_PROPS = 'org.freedesktop.DBus.Properties';
const I_ADAPTER = 'org.bluez.Adapter1';
const I_DEVICE = 'org.bluez.Device1';
const I_BEARER_LE = 'org.bluez.Bearer.LE1';
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
function pickBluezDevice(objects, target, known = []) {
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
    /*
     * And the phones this computer was told of (`known`: the server's --ble-address list). BlueZ lists a phone's
     * services only from what it last cached, and a phone it has not read since (the box, 2026-10-25: the Pixel
     * bonded, its UUIDs without either service) was not found, though its address reached it at once. (Until
     * 2026-10-30 the cli pair's own list did this.)
     */
    if (!matches.length && known.length) {
      const wanted = new Set(known.map(addrKey));
      matches = paired.filter((d) => wanted.has(addrKey(d.Address)));
    }
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
async function openBluezLink({ dbus, target, known = [], onData, onDisconnect, timeouts, log }) {
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

    const device = pickBluezDevice(objects, target, known);
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
      const devIface = await iface(device.path, I_DEVICE);
      /* the link was already up when Connect() was called (it returned at once, or said so) */
      let foundUp = false;
      try {
        try {
          await within(devIface.Connect(), timeouts.connectMs,
            () => bleError('EBUSY',
              `${name} did not accept an LE connection in ${timeouts.connectMs / 1000} s. `
              + 'The phone serves one computer at a time over LE - is another one (a Windows PC) '
              + 'connected to it? Is the OnlyKey app open, with its soft key on?'));
        } catch (err) {
          if (err.code) throw err;
          const what = dbusWhat(err);
          if (/AlreadyConnected|InProgress|Already Connected/i.test(what)) {
            /* Someone else's connect (or BlueZ's own reconnect) got there first: the wait below decides. */
            foundUp = true;
          } else if (/br-connection/i.test(what)) {
            throw bleError('ECLASSIC',
              `BlueZ tried to reach ${name} over CLASSIC Bluetooth (${what}), not LE. `
              + `PreferredBearer did not take - run: ${FIX}`, err);
          } else if (/le-connection-abort-by-local|Page Timeout|Host is down|ConnectionAttemptFailed/i.test(what)) {
            throw bleError('EBUSY',
              `${name} did not accept an LE connection (${what}). The phone serves one computer at a `
              + 'time over LE - is another one connected to it? Is the OnlyKey app open, with its soft key on?', err);
          } else {
            throw bleError('ECONNECT', `could not connect to ${name}: ${what}`, err);
          }
        }
        log(`Connect() returned in ${Date.now() - tc} ms`);
        if (Date.now() - tc < 1000) foundUp = true;

        /*
         * Wait for the GATT table. Polled, not signalled: the object that
         * resolves may be a different device path from the one connected (the
         * RPA split above), and a poll of the whole tree cannot pick the wrong
         * one to listen to.
         *
         * A LINK FOUND UP MAY BE STALE, AND THE TOOL DROPS IT ITSELF (the box, 2026-10-23): right
         * after a bond, BlueZ keeps the LE link the pairing opened, and with `Cache = no` it never
         * discovers services on it - Connect() returned in 4 ms, then ServicesResolved stayed false
         * for the whole wait, every time, until a fresh connection was made. The message used to
         * hand the person `sudo hcitool ledc`. Now: a link found up that has not resolved within
         * STALE_MS is disconnected and connected again ONCE - a fresh link runs discovery (8.5 s on
         * the same phone) - and only then does the full wait decide. Disconnect() drops the classic
         * keyboard link too; the phone reconnects its target on its own.
         */
        const STALE_MS = 4000;
        let fresh = false;
        let deadline = Date.now() + timeouts.resolveMs;
        for (;;) {
          objects = await managed();
          vendor = findVendor(objects, device);
          if (vendor && vendor.live) break;
          if (foundUp && !fresh && Date.now() - tc >= STALE_MS) {
            fresh = true;
            log(`the link was already up but its services have not resolved in ${STALE_MS / 1000} s - a stale LE link: disconnecting and connecting fresh`);
            try { await devIface.Disconnect(); } catch (err) { log(`Disconnect: ${dbusWhat(err)} (continuing)`); }
            await sleep(1500);
            const tr = Date.now();
            try {
              await within(devIface.Connect(), timeouts.connectMs,
                () => bleError('EBUSY', `${name} did not accept a fresh LE connection in ${timeouts.connectMs / 1000} s`));
            } catch (err) {
              if (err.code) throw err;
              log(`Connect (fresh): ${dbusWhat(err)} (the wait below decides)`);
            }
            log(`fresh Connect() returned in ${Date.now() - tr} ms`);
            deadline = Date.now() + timeouts.resolveMs;
            continue;
          }
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
       * The phone this link reached: BlueZ's Address for the device it picked,
       * which is the phone's real (identity) address once it is bonded - even
       * when the link itself sits on a rotating private address's D-Bus path
       * (ZBOX + A13, 2026-10-20: dev_5B_03_59_D7_E3_02 reports 8C:6A:3B:71:C6:72).
       */
      address: device.Address,
      name,
      /*
       * type 'request' = write WITH response, as on Windows: the phone
       * acknowledges each fragment. A failure here with LE down is BlueZ's
       * "Not connected"; it is reported by the pipe as the link going away.
       */
      write: (frag) => req.WriteValue(Buffer.from(frag), { type: new dbus.Variant('s', 'request') }),
      /*
       * StopNotify, drop the LE link ALONE, and let go of the bus - never Device1.Disconnect(),
       * which drops every bearer, including the classic keyboard the phone keeps to this computer.
       *
       * The LE link used to be left "for BlueZ to idle out", and BlueZ does not: it stayed up
       * after the command was gone, and the phone's Authenticator said "connected" (not
       * "advertising") with nothing on this side using it (the box, BlueZ 5.87, 2026-10-23).
       * Windows drops the link when the program lets go; org.bluez.Bearer.LE1.Disconnect (BlueZ
       * 5.80+, Experimental) does the same for LE only. On a BlueZ without it the link stays, as
       * before.
       */
      async close() {
        rspProps.removeListener('PropertiesChanged', onChanged);
        devProps.removeListener('PropertiesChanged', onDevChanged);
        try { await rsp.StopNotify(); } catch { /* link already gone */ }
        try {
          await (await iface(vendor.device, I_BEARER_LE)).Disconnect();
        } catch (err) {
          log(`LE disconnect: ${dbusWhat(err)} (the link is left to BlueZ)`);
        }
        closeBus();
      },
    };
  } catch (err) {
    closeBus();
    throw err;
  }
}

/* ------------------------------------------------------------ the link */

/*
 * CTRL+C CLOSES THE LINKS FIRST (Brad, 2026-10-07, learned with the old pipe): a killed process never closes a Windows
 * Bluetooth link, so the phone stays "connected" and stops advertising. The open links close first (2 s at most), then
 * the process exits as Ctrl+C would - unless something else handles the signal (a server closing its links itself).
 */
const liveLinks = new Set();
let signalsArmed = false;
function onSignal(sig) {
  if (process.listenerCount(sig) > 1) return;
  const closes = [...liveLinks].map((l) => Promise.race([
    Promise.resolve(l.close()).catch(() => {}),
    new Promise((r) => setTimeout(r, 2000)),
  ]));
  Promise.all(closes).finally(() => process.exit(sig === 'SIGINT' ? 130 : 143));
}
function armSignals() {
  if (signalsArmed || typeof process === 'undefined' || typeof process.prependListener !== 'function') return;
  signalsArmed = true;
  process.prependListener('SIGINT', () => onSignal('SIGINT'));
  process.prependListener('SIGTERM', () => onSignal('SIGTERM'));
}

/**
 * One Bluetooth link to a phone.
 *
 * @param {object} [opts]
 * @param {string} [opts.address]  the phone: an address (any case, colons optional) or its Bluetooth name; default the
 *   one bonded phone that lists the vendor service or advertises FIDO
 * @param {string[]} [opts.known]  phone addresses to try when BlueZ has not cached their services (Linux)
 * @param {string} [opts.platform]  process.platform; injectable for tests
 * @param {() => object} [opts.loadNoble]  returns @stoprocent/noble (win32)
 * @param {() => object} [opts.loadDbus]   returns dbus-next (linux)
 * @param {object} [opts.timeouts]  overrides TIMEOUTS
 * @param {(line: string) => void} [opts.log]  the link's own steps (scan, connect, subscribe)
 * @returns {{open: () => Promise<{address: string, name: string, mtu: number}>, send: (command: number, bytes: Uint8Array) => Promise<void>,
 *   close: () => Promise<void>, on: (event: 'message'|'down', fn: Function) => () => void, isUp: () => boolean, phone: object|null}}
 *   'message' gives {command, bytes} for each whole message the phone sends; 'down' gives the reason the link went.
 *   A dropped link is not opened again here - the holder decides when (the server: on the phone's next advertisement).
 */
function createBleLink({ address, known = [], platform = process.platform, loadNoble: ln, loadDbus: ld, timeouts = {}, log } = {}) {
  const limits = { ...TIMEOUTS, ...timeouts };
  const trace = log || (() => {});
  const listeners = { message: new Set(), down: new Set() };
  const emit = (ev, v) => {
    for (const l of [...listeners[ev]]) {
      try { l(v); } catch { /* a listener's own trouble never breaks the link */ }
    }
  };
  let link = null;
  let closing = null;
  let assembler = createAssembler();
  /* writes are serialised: two messages' fragments interleaved on the characteristic would reassemble as neither */
  let queue = Promise.resolve();

  function onData(data) {
    const message = assembler.push(data);
    if (message) emit('message', { command: message.command, bytes: Uint8Array.from(message) });
  }
  function onDisconnect(reason) {
    const was = link;
    link = null;
    if (was) closing = Promise.resolve(was.close()).catch(() => {});
    emit('down', reason || 'the phone dropped the link');
  }

  const self = {
    async open() {
      if (link) return self.phone;
      /* the old link CLOSED first: a new Windows session opened while the dropped one shut down lost its writes (A13, 2026-10-05) */
      if (closing) { await closing; closing = null; }
      assembler = createAssembler();
      const common = { target: address, onData, onDisconnect, timeouts: limits, log: trace };
      if (platform === 'win32') link = await openNobleLink({ nobleModule: loadNoble(ln), ...common });
      else if (platform === 'linux') link = await openBluezLink({ dbus: loadDbus(ld), known, ...common });
      else throw bleError('EBLEPLATFORM', `Bluetooth is built and tested on Windows and Linux; this is ${platform}.`);
      liveLinks.add(self);
      armSignals();
      return self.phone;
    },

    /** One whole message with this frame command, fragmented to the link's MTU, after every earlier one. */
    send(command, bytes) {
      const payload = Uint8Array.from(bytes || []);
      if (payload.length > MAX_MESSAGE) return Promise.reject(bleError('ETOOLONG', `a Bluetooth message is at most ${MAX_MESSAGE} bytes; this one is ${payload.length}`));
      const run = async () => {
        if (!link) throw bleError('ENOTOPEN', 'the phone is not connected');
        /* one write when the MTU carries the whole fragment (the phone's 517 does); else the 20-byte floor */
        const size = link.mtu - 3 >= WHOLE_REPORT ? Math.min(link.mtu - 3, 512) : SMALL_FRAGMENT;
        const pieces = fragment(payload, size, command);
        /* 128 continuations at most (sequence 0x00-0x7f): the phone drops a message with more (CtapBleFramer.kt) */
        if (pieces.length > 129) throw bleError('ETOOLONG', `a ${payload.length}-byte message needs ${pieces.length - 1} continuations at mtu ${link.mtu}; CTAP-over-BLE allows 128 (ble-socket.js sends pieces)`);
        for (const piece of pieces) {
          if (!link) throw bleError('ENOTOPEN', 'the phone dropped the link in the middle of a message');
          await link.write(piece);
        }
      };
      const result = queue.then(run, run);
      queue = result.catch(() => {});
      return result;
    },

    async close() {
      liveLinks.delete(self);
      const was = link;
      link = null;
      if (was) await Promise.resolve(was.close()).catch(() => {});
    },

    on(event, fn) {
      if (!listeners[event]) throw new Error(`a Bluetooth link has no "${event}" event`);
      listeners[event].add(fn);
      return () => listeners[event].delete(fn);
    },

    isUp() { return link !== null; },

    /** The phone the open link reached - its address, Bluetooth name and MTU - or null. */
    get phone() { return link ? { address: String(link.address || ''), name: link.name || '', mtu: link.mtu } : null; },
  };
  return self;
}

/*
 * THE PHONES IN REACH (Brad, 2026-10-08, for `devices --ble`). Lists, never connects:
 * each phone advertising the FIDO or the OnlyKey vendor service. A logged-out phone
 * app does not advertise (its Bluetooth starts after the login), so it is not here.
 *   Windows / macOS: a noble scan for `seconds` (rotating private addresses are
 *   resolved to the identity address for a bonded phone, as for --address).
 *   Linux: BlueZ's devices with those services (the phones this computer is bonded
 *   with - the same set openBluezLink can open), RSSI when BlueZ saw it recently.
 * -> [{address, name, rssi}] (address as --address takes it)
 */
async function scanPhones({ seconds = 6, platform = process.platform, loadNoble: ln = loadNoble, loadDbus: ld = loadDbus } = {}) {
  const fidoish = (uuids) => uuids.some((u) => [bare(FIDO_UUID), bare(SERVICE_UUID), 'fffd', FIDO_UUID, SERVICE_UUID].includes(String(u).toLowerCase()));
  if (platform === 'linux') {
    const dbus = ld();
    const bus = dbus.systemBus();
    if (bus.on) bus.on('error', () => {});
    try {
      const root = await bus.getProxyObject(BLUEZ, '/');
      const objects = unwrap(await root.getInterface(I_OM).GetManagedObjects());
      const byAddress = new Map();
      for (const i of Object.values(objects)) {
        const d = i[I_DEVICE];
        if (!d || !fidoish(d.UUIDs || [])) continue;
        byAddress.set(addrKey(d.Address), { address: d.Address, name: d.Name || d.Alias || '', rssi: typeof d.RSSI === 'number' ? d.RSSI : null });
      }
      return [...byAddress.values()];
    } finally {
      try { bus.disconnect(); } catch { /* already closed */ }
    }
  }
  const noble = ln();
  await noble.waitForPoweredOnAsync(TIMEOUTS.powerMs);
  const seen = new Map();
  const onDiscover = (p) => {
    const a = p.advertisement || {};
    const prev = seen.get(p.id) || { name: '', uuids: new Set(), rssi: null, address: '' };
    if (a.localName) prev.name = a.localName;
    for (const u of a.serviceUuids || []) prev.uuids.add(String(u).toLowerCase());
    if (typeof p.rssi === 'number') prev.rssi = p.rssi;
    prev.address = p.address && p.address !== 'unknown' ? p.address : p.id;
    seen.set(p.id, prev);
  };
  noble.on('discover', onDiscover);
  try {
    await noble.startScanningAsync([], true);
    await new Promise((resolve) => setTimeout(resolve, seconds * 1000));
  } finally {
    noble.removeListener('discover', onDiscover);
    await Promise.resolve(noble.stopScanningAsync()).catch(() => {});
  }
  return [...seen.values()].filter((v) => fidoish([...v.uuids])).map((v) => ({ address: v.address, name: v.name, rssi: v.rssi }));
}

module.exports = {
  createBleLink, scanPhones, fragment, createAssembler, loadNoble, loadDbus, pickBluezDevice, findVendor,
  CMD_SOCKET, CMD_ERROR, MAX_MESSAGE, SERVICE_UUID, REQUEST_UUID, RESPONSE_UUID, FIDO_UUID, TIMEOUTS,
};
