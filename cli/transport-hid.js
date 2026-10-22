/*
 * cli/transport-hid.js - a desktop OnlyKey, as the byte pipe transport/usb eats.
 *
 * transport/usb does not reach for a bus. It takes a PIPE through Rectify
 * config and does all the demultiplexing and normalisation itself (see
 * src/transport/pipeTransport.js for the contract and why it is shaped that
 * way). On Android the pipe is ok-rn's USB module; in the emulator it is the
 * JNI bus. This is the third one: node-hid, i.e. hidapi, on Windows, Linux and
 * macOS. Everything above the pipe - the session, the device plugin, okcrypto -
 * is the same code the phone runs, which is the point of putting the CLI in
 * this library rather than writing a fourth protocol client.
 *
 * WHY IT LIVES UNDER cli/ AND NOT plugins/transport/. Everything under src/ and
 * plugins/ bundles for a browser and for React Native; test/package.test.js
 * fails the build if src/ ever requires a Node built-in. node-hid is a native
 * addon, so this file can only ever run in Node, and it sits beside the one
 * program that needs it.
 *
 * WHY node-hid IS LOADED HERE, LAZILY, AND NOWHERE ELSE. It is an
 * optionalDependency: a failed native build must not fail `npm install` for
 * the web app or ok-rn, which never touch it. The require() therefore happens
 * inside start(), so composing the stack, printing help, and every test that
 * injects a fake all work on a machine where node-hid is absent - and when it
 * IS absent, the one command that needed it says so by name instead of dying
 * with a MODULE_NOT_FOUND stack trace.
 *
 * WHAT THIS PIPE OPENS: the VENDOR interface, which carries the OnlyKey
 * protocol (PIN bracket, labels, slots, keys - see
 * src/transport/usbDescriptors.js), and - on first use only - the FIDO
 * interface, for what the firmware serves over CTAPHID alone: a label's
 * derived key (`keychain derive label`) is the one the CLI has. On a DEBUG
 * build it also opens SEREMU, the debug console (button presses, the
 * console's own lines). The keyboard is device-to-host only, so a write to it
 * is refused by name rather than sent somewhere it is ignored.
 *
 * WHY SEREMU OPENS AT START, AND IS NOT FATAL. The console talks without being
 * asked - "UNLOCKED", the prompts - and the device plugin's console buffer and
 * unlock() read those lines, so a console opened on the first write would
 * miss everything said before it. A production key does not enumerate SEREMU
 * at all (it is compiled out), and Windows can refuse to open it (a stale
 * per-device lock - DEVPKEY_Device_SecuritySDS - on one key's record, the one
 * Windows puts on FIDO interfaces). Either way every vendor command still
 * works, and only a console write says why it cannot be sent.
 *
 * WHICH INTERFACES BELONG TO THE OPENED KEY. hidapi lists interfaces, not
 * devices, and the emulator's Windows driver (okvhid) lists a full set of
 * OnlyKey interfaces - same ids, same usage pages, same serial - beside a real
 * key. So a FIDO or SEREMU interface is used only when it is certainly the
 * opened key's: among the interfaces of the same device as the chosen vendor
 * interface, exactly one vendor and one of the kind wanted. "Same device" is
 * the USB parent in sysfs on Linux (hidraw nodes of one key share it); without
 * that, the same KIND - interface-numbered USB interfaces, or the virtual
 * devices hidapi lists with interface -1. Anything less certain is refused.
 *
 * WHY FIDO OPENS LAZILY, AND ONLY WHEN THE MATCH IS CERTAIN (owner,
 * 2026-10-01: "add FIDO support to the pipe"). Every vendor-only command keeps
 * working where FIDO cannot be reached: Windows does not show a security key's
 * FIDO interface to a program that is not elevated (it keeps it for its own
 * WebAuthn service). And hidapi lists interfaces, not devices - nothing ties a
 * FIDO interface to the vendor interface of the same key except there being
 * one of each. With two OnlyKeys plugged in, a FIDO write could reach the
 * OTHER key; that is refused, not guessed.
 */
'use strict';

const { IFACE, DIR, REPORT_SIZE, withReportId } = require('../src/transport/contract');
const { VENDOR_ID, PRODUCT_ID, identify, describe } = require('../src/transport/usbDescriptors');

/* SEREMU's out-report: 32 bytes, not 64 (usbDescriptors.js). */
const SEREMU_OUT = describe(IFACE.SEREMU).endpointOut;

const hex4 = (n) => Number(n).toString(16).padStart(4, '0');
/*
 * The USB ids an OnlyKey enumerates with: 1d50:60fc, and 16c0:0486 - the
 * Teensy RawHID id early OnlyKeys shipped under, which python-onlykey still
 * accepts. Either way the vendor interface is then picked by usage page, so
 * accepting the older id cannot point this protocol at another interface.
 */
const USB_IDS = [[VENDOR_ID, PRODUCT_ID], [0x16c0, 0x0486]];
const USB_ID = USB_IDS.map(([v, p]) => `${hex4(v)}:${hex4(p)}`).join(' or ');

/**
 * An error the CLI prints as a sentence, not a stack trace.
 *
 * `code` lets a caller (and a test) branch without matching wording, which is
 * free to improve.
 */
function hidError(code, message, cause) {
  const err = new Error(message);
  err.code = code;
  if (cause) err.cause = cause;
  return err;
}

/**
 * Load node-hid, or explain why it cannot be.
 *
 * Two different failures, told apart because the fix differs:
 *
 *   NOT INSTALLED - npm skipped it (an optional dependency whose native build
 *   failed is skipped silently), or the library was installed with
 *   --omit=optional. The fix is to install it.
 *
 *   INSTALLED BUT WILL NOT LOAD - usually a prebuilt binary for another Node
 *   ABI or platform. The fix is to rebuild it, and the original message is the
 *   only thing that says which binary it looked for.
 *
 * The MODULE_NOT_FOUND test also checks the NAME: a node-hid that is present
 * but cannot find one of ITS dependencies throws the same code, and calling
 * that "not installed" would send someone to reinstall a package that is there.
 *
 * @param {() => object} [loader] injectable, so a test can be a machine without it
 */
function loadNodeHid(loader = () => require('node-hid')) {
  try {
    return loader();
  } catch (err) {
    const missing = err && err.code === 'MODULE_NOT_FOUND'
      && /['"]node-hid['"]/.test(String(err.message));
    if (missing) {
      throw hidError('ENOHID',
        'onlykey-js needs "node-hid" to reach a USB OnlyKey, and it is not installed. '
        + 'It is an OPTIONAL PEER of node-onlykey-lib - not installed with it, so the '
        + 'web app and ok-rn never download a native module - install it next to the '
        + 'library: npm install node-hid',
        err);
    }
    throw hidError('EHIDLOAD',
      `"node-hid" is installed but failed to load (${err && err.message}). `
      + 'Its native binary may not match this Node version or platform: npm rebuild node-hid',
      err);
  }
}

/**
 * Every OnlyKey vendor interface hidapi can see.
 *
 * Identified by HID USAGE PAGE, never by interface number or position.
 * Three of the key's interfaces are identical in every other respect, and a
 * guess sends the vendor protocol to the security-key interface, where every
 * request times out and the error blames the device (usbDescriptors.js's
 * header, and ok-rn's FINDING #40). python-onlykey falls back to "interface 2"
 * when the page is missing; this does not, and says so instead - see below.
 *
 * Enumerating does not OPEN anything: hidapi reads the list from the OS.
 *
 * @returns {{ vendor: object[], onlykeys: object[] }} the vendor interfaces,
 *   and every interface of every OnlyKey (to tell "none plugged in" from
 *   "plugged in but its interfaces could not be identified")
 */
function findOnlyKeys(HID) {
  const all = HID.devices() || [];
  const onlykeys = all.filter((d) => USB_IDS.some(([v, p]) => d.vendorId === v && d.productId === p));
  const vendor = onlykeys.filter(
    (d) => identify({ usagePage: d.usagePage, usage: d.usage }) === IFACE.VENDOR);
  const fido = onlykeys.filter(
    (d) => identify({ usagePage: d.usagePage, usage: d.usage }) === IFACE.FIDO);
  const seremu = onlykeys.filter(
    (d) => identify({ usagePage: d.usagePage, usage: d.usage }) === IFACE.SEREMU);
  return { vendor, fido, seremu, onlykeys };
}

/**
 * The USB device a Linux hidraw node belongs to, from sysfs, or null.
 *
 * /sys/class/hidraw/hidrawN/device resolves to
 * .../<usb device>/<usb device>:<config>.<interface>/<hid id>, so two levels
 * up is the USB device itself - the same directory for every interface of one
 * key, and a different one for the emulator's dummy_hcd gadget.
 */
function sysfsUsbParent(path) {
  const m = /^\/dev\/(hidraw\d+)$/.exec(String(path));
  if (!m || process.platform !== 'linux') return null;
  try {
    const fsys = require('fs');
    const nodePath = require('path');
    return nodePath.dirname(nodePath.dirname(fsys.realpathSync(`/sys/class/hidraw/${m[1]}/device`)));
  } catch (_) {
    return null;
  }
}

/**
 * The interface of `kind` that belongs to the opened key - only when that is
 * certain (see "WHICH INTERFACES BELONG TO THE OPENED KEY" above). Otherwise
 * null, and `why` says what to do.
 *
 * @param {object} found    findOnlyKeys()'s lists
 * @param {object} chosen   the vendor interface the pipe opened
 * @param {'fido'|'seremu'} kind
 * @param {(path: string) => string|null} usbParentOf
 */
function pairSibling(found, chosen, kind, usbParentOf) {
  const parent = usbParentOf(chosen.path);
  const sameDevice = parent
    ? (d) => usbParentOf(d.path) === parent
    : (d) => (d.interface >= 0) === (chosen.interface >= 0);
  const vendor = found.vendor.filter(sameDevice);
  const candidates = found[kind].filter(sameDevice);
  if (vendor.length === 1 && candidates.length === 1) return { device: candidates[0], why: null };

  const name = kind === 'fido' ? 'FIDO' : 'debug console (SEREMU)';
  if (vendor.length > 1) {
    return {
      device: null,
      why: `${vendor.length} OnlyKeys are plugged in, and a ${name} interface cannot be matched to the one `
        + 'chosen with --path (hidapi lists interfaces, not devices). Unplug the others for this command.',
    };
  }
  if (kind === 'fido' && !candidates.length && process.platform === 'win32') {
    return {
      device: null,
      why: 'Windows shows a security key\'s FIDO interface only to an elevated program (it keeps it for '
        + 'its WebAuthn service). Run onlykey-js from an elevated shell for this command - or, for a '
        + 'derived key, use the ssh or gpg scheme, which run over the vendor interface.',
    };
  }
  if (kind === 'seremu' && !candidates.length) {
    return {
      device: null,
      why: 'this OnlyKey lists no debug console (usage page 0xffc9) - a production build has none.',
    };
  }
  return { device: null, why: 'this OnlyKey\'s FIDO interface (usage page 0xf1d0) is not listed by hidapi.' };
}

/**
 * Pick the one device to open, or refuse with a sentence that says what to do.
 */
function selectDevice({ vendor, onlykeys }, path) {
  if (path) {
    /*
     * Only a path that IS an OnlyKey vendor interface. `--path` is for choosing
     * between keys, not for pointing this protocol at an arbitrary HID device,
     * which would receive OKCONNECT and whatever came after it.
     */
    const chosen = vendor.find((d) => d.path === path);
    if (!chosen) {
      throw hidError('ENOTONLYKEY',
        `${path} is not an OnlyKey vendor interface. `
        + (vendor.length
          ? `OnlyKeys on this machine: ${vendor.map((d) => d.path).join(', ')}`
          : 'No OnlyKey is plugged in.'));
    }
    return chosen;
  }

  if (vendor.length === 1) return vendor[0];

  if (vendor.length > 1) {
    /*
     * Refused, not "take the first". Enumeration order is the OS's and changes
     * with the port a key is in, so the first would be a different key on a
     * different day - and every command after this one acts on it.
     */
    throw hidError('EMANYONLYKEY',
      `${vendor.length} OnlyKeys are plugged in; choose one with --path:\n`
      + vendor.map((d) => `  ${d.path}${d.serialNumber ? `  (serial ${d.serialNumber})` : ''}`).join('\n'));
  }

  if (onlykeys.length) {
    /*
     * The key is on the bus but no interface carries the vendor usage page.
     * That is an hidapi too old to read report descriptors (a usage page of 0
     * on Linux's libusb backend), not a missing key - and guessing by interface
     * number is exactly what usbDescriptors.js refuses to do.
     */
    throw hidError('ENOVENDORIFACE',
      `An OnlyKey (${USB_ID}) is plugged in, but hidapi did not report its interfaces' `
      + 'usage pages, so the vendor interface (usage page 0xffab) cannot be identified. '
      + 'Update node-hid (hidapi 0.10 or newer reports them).');
  }

  throw hidError('ENOONLYKEY',
    `No OnlyKey found (USB ${USB_ID}). Plug one in and try again. `
    + 'On Linux, a key that is plugged in but not listed usually needs the OnlyKey udev rule '
    + '(49-onlykey.rules, https://docs.crp.to/linux.html).');
}

/**
 * Build the pipe.
 *
 * @param {object} [opts]
 * @param {() => object} [opts.loadHid] returns the node-hid module; injectable
 * @param {string} [opts.path] a specific key's hidapi path (see `--path`)
 * @param {(path: string) => string|null} [opts.usbParentOf] the USB device an
 *   interface path belongs to; injectable (default: sysfs on Linux, else null)
 * @returns the pipe contract (start/stop/isRunning/write/on) plus `device`,
 *   the enumeration entry of the key that was opened, once started
 */
function createHidPipe({ loadHid, path, usbParentOf = sysfsUsbParent } = {}) {
  const listeners = new Set();
  const closeListeners = new Set();
  let hid = null;
  let opened = null;
  let lastError = null;
  let HIDmodule = null;
  let fidoPair = null;     // {device, why} from the enumeration at start()
  let fidoHid = null;      // opened on the first FIDO write
  let seremuHid = null;    // opened at start(), when the key has a console
  let seremuWhy = null;    // why it is not open, for a console write
  let seremuDevice = null; // its enumeration entry

  function emit(event) {
    for (const listener of [...listeners]) listener(event);
  }

  const onData = (data) => deliver(IFACE.VENDOR, data);
  const onFidoData = (data) => deliver(IFACE.FIDO, data);
  const onSeremuData = (data) => deliver(IFACE.SEREMU, data);

  function openSeremu(found, chosen) {
    const pair = pairSibling(found, chosen, 'seremu', usbParentOf);
    if (!pair.device) { seremuWhy = pair.why; return; }
    try {
      seremuHid = new HIDmodule.HID(pair.device.path);
    } catch (err) {
      seremuWhy = `its debug console (${pair.device.path}) would not open (${err && err.message}). On Windows, `
        + 'an "Access is denied" here is a per-device lock (DEVPKEY_Device_SecuritySDS) on that interface.';
      return;
    }
    seremuDevice = pair.device;
    seremuHid.on('data', onSeremuData);
    seremuHid.on('error', onError);
  }

  function deliver(iface, data) {
    let bytes = Uint8Array.from(data);
    /*
     * hidapi strips a report ID of 0 on the way IN on every platform, so a
     * report arrives as its 64 bytes. python-onlykey reads 65 on Windows and
     * throws the zeros away with the padding; that is only safe because it
     * treats every report as text. A vendor report is not text - the transit
     * box and a public key are arbitrary bytes - so a stray leading ID is
     * removed here, by length, or every field would be read one byte late.
     */
    if (bytes.length === REPORT_SIZE + 1 && bytes[0] === 0x00) bytes = bytes.subarray(1);
    emit({ iface, dir: DIR.OUT, bytes });
  }

  function openFido() {
    if (fidoHid) return fidoHid;
    if (!fidoPair || !fidoPair.device) {
      throw hidError('ENOFIDO', `this command needs the OnlyKey's FIDO interface: ${fidoPair ? fidoPair.why : 'the pipe is not open.'}`);
    }
    try {
      fidoHid = new HIDmodule.HID(fidoPair.device.path);
    } catch (err) {
      throw hidError('EOPEN',
        `Could not open the OnlyKey's FIDO interface (${err && err.message}). A browser or another `
        + 'program may be holding it; on Linux, check the OnlyKey udev rule.', err);
    }
    fidoHid.on('data', onFidoData);
    fidoHid.on('error', onError);
    return fidoHid;
  }

  function onError(err) {
    /*
     * An unplugged key surfaces here, from hidapi's read thread. The pipe
     * stops being "running", so the next write fails with this cause instead
     * of hanging on a device that is gone.
     */
    const wasOpen = hid !== null;
    lastError = err;
    close();
    /* told once, to a host that shows it (a GUI's status line); the CLI learns on its next write */
    if (wasOpen) for (const listener of [...closeListeners]) listener(err);
  }

  function close() {
    for (const [device, listener] of [[hid, onData], [fidoHid, onFidoData], [seremuHid, onSeremuData]]) {
      if (!device) continue;
      device.removeListener('data', listener);
      device.removeListener('error', onError);
      try { device.close(); } catch (_) { /* already gone: nothing to release */ }
    }
    hid = null;
    fidoHid = null;
    seremuHid = null;
  }

  /*
   * A console line goes out as SEREMU out-reports: 32 bytes each, zero-padded,
   * behind the report ID. Windows refuses a write of any other length, and the
   * firmware's console skips the padding (the probe "Z" padded this way is
   * echoed once, on Windows and on Linux). A line longer than one report is
   * cut into several, which the console reads as one byte stream.
   */
  function writeSeremu(frame) {
    if (!seremuHid) {
      throw hidError('ENOSEREMU', `this command needs the OnlyKey's debug console: ${seremuWhy || 'the pipe is not open.'}`);
    }
    let written = 0;
    for (let at = 0; at < Math.max(frame.length, 1); at += SEREMU_OUT) {
      const report = new Uint8Array(SEREMU_OUT);
      report.set(frame.subarray(at, at + SEREMU_OUT));
      const n = seremuHid.write(Array.from(withReportId(report)));
      written += typeof n === 'number' ? n : report.length + 1;
    }
    return written;
  }

  return {
    async start() {
      if (hid) return { started: true, path: opened.path };
      const HID = loadNodeHid(loadHid);
      const found = findOnlyKeys(HID);
      const chosen = selectDevice(found, path);
      HIDmodule = HID;
      fidoPair = pairSibling(found, chosen, 'fido', usbParentOf);
      try {
        hid = new HID.HID(chosen.path);
      } catch (err) {
        /*
         * Listed but not openable: on Linux, the udev rule again (the list is
         * readable by anyone, the device node is not); on Windows, another
         * program holding the interface exclusively.
         */
        throw hidError('EOPEN',
          `Found an OnlyKey but could not open it (${err && err.message}). `
          + 'Another program may be using it; on Linux, check the OnlyKey udev rule.', err);
      }
      opened = chosen;
      lastError = null;
      /* Attaching 'data' is what starts hidapi's read thread. */
      hid.on('data', onData);
      hid.on('error', onError);
      seremuWhy = null;
      openSeremu(found, chosen);
      return { started: true, path: chosen.path };
    },

    async stop() {
      close();
    },

    isRunning() {
      return hid !== null;
    },

    async write(iface, bytes) {
      if (iface !== IFACE.VENDOR && iface !== IFACE.FIDO && iface !== IFACE.SEREMU) {
        throw new Error(
          `the desktop HID pipe opens the vendor (${IFACE.VENDOR}), FIDO (${IFACE.FIDO}) and debug console `
          + `(${IFACE.SEREMU}) interfaces only; interface ${iface} is not open`);
      }
      if (!hid) {
        throw hidError('ENOTOPEN',
          lastError ? `the OnlyKey went away: ${lastError.message}` : 'the OnlyKey is not open');
      }
      const frame = Uint8Array.from(bytes);
      if (iface === IFACE.SEREMU) {
        const written = writeSeremu(frame);
        emit({ iface, dir: DIR.IN, bytes: frame });
        return written;
      }
      const device = iface === IFACE.FIDO ? openFido() : hid;
      /*
       * THE REPORT ID. hidapi takes the first byte of every write as the report
       * ID - on Windows, on Linux (hidraw; usbhid strips a leading 0 before
       * the endpoint) and on macOS - and the OnlyKey's reports have none, so
       * that byte is 0. python-onlykey adds it on Windows only because its
       * Linux path writes without it and gets away with it: its messages all
       * begin 0xFF, which the kernel then sends as data. A frame that began
       * with 0x00 would lose its first byte. The contract keeps payloads free of
       * report IDs everywhere above the pipe (src/transport/contract.js), so
       * THIS is the one place it is added.
       */
      const written = device.write(Array.from(withReportId(frame)));
      /*
       * Echo our own write, dir IN. A USB pipe physically sees inbound reports
       * only; the transport filters on direction, and the emulator's pipe
       * reports both ways, so the host echoes to make `dir` mean the same on
       * every pipe (pipeTransport.js). Emitted synchronously after the write:
       * the device's answer arrives on a later turn, so the echo is always
       * seen before the reply to it.
       */
      emit({ iface, dir: DIR.IN, bytes: frame });
      return typeof written === 'number' ? written : frame.length + 1;
    },

    /**
     * 'stream' - every report, both directions (the pipe contract).
     * 'close'  - (err) the key went away while open (unplugged, restarted);
     *            not fired by stop().
     */
    on(event, listener) {
      const set = event === 'stream' ? listeners : event === 'close' ? closeListeners : null;
      if (!set) throw new Error(`the HID pipe has no "${event}" event`);
      set.add(listener);
      return () => set.delete(listener);
    },

    /** The enumeration entry of the key that was opened, or null. */
    get device() { return opened; },

    /**
     * The interfaces this pipe can reach on the opened key, as
     * {iface, path, interfaceNumber, usagePage, usage}: the vendor interface,
     * FIDO when it is certainly this key's (opened on first use), and the
     * debug console when it is open. Empty while stopped. A GUI decides from
     * this what it can offer - console presses only when SEREMU is here.
     */
    interfaces() {
      if (!hid) return [];
      const entry = (iface, d) => ({
        iface, path: d.path, interfaceNumber: d.interface, usagePage: d.usagePage, usage: d.usage,
      });
      const out = [entry(IFACE.VENDOR, opened)];
      if (fidoPair && fidoPair.device) out.push(entry(IFACE.FIDO, fidoPair.device));
      if (seremuHid) out.push(entry(IFACE.SEREMU, seremuDevice));
      return out;
    },
  };
}

module.exports = { createHidPipe, loadNodeHid, findOnlyKeys, selectDevice, USB_ID };
