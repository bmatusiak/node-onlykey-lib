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
 * WHAT THIS PIPE OPENS: the VENDOR interface only. That is the one that
 * carries the OnlyKey protocol (PIN bracket, labels, slots, keys - see
 * src/transport/usbDescriptors.js). FIDO is a different protocol with its own
 * transport; the keyboard is device-to-host only; SEREMU is compiled out of a
 * production key. A write to any other interface is refused by name rather
 * than sent somewhere it will be ignored.
 */
'use strict';

const { IFACE, DIR, REPORT_SIZE, withReportId } = require('../src/transport/contract');
const { VENDOR_ID, PRODUCT_ID, identify } = require('../src/transport/usbDescriptors');

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
  return { vendor, onlykeys };
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
 * @returns the pipe contract (start/stop/isRunning/write/on) plus `device`,
 *   the enumeration entry of the key that was opened, once started
 */
function createHidPipe({ loadHid, path } = {}) {
  const listeners = new Set();
  let hid = null;
  let opened = null;
  let lastError = null;

  function emit(event) {
    for (const listener of [...listeners]) listener(event);
  }

  function onData(data) {
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
    emit({ iface: IFACE.VENDOR, dir: DIR.OUT, bytes });
  }

  function onError(err) {
    /*
     * An unplugged key surfaces here, from hidapi's read thread. The pipe
     * stops being "running", so the next write fails with this cause instead
     * of hanging on a device that is gone.
     */
    lastError = err;
    close();
  }

  function close() {
    const device = hid;
    hid = null;
    if (!device) return;
    device.removeListener('data', onData);
    device.removeListener('error', onError);
    try { device.close(); } catch (_) { /* already gone: nothing to release */ }
  }

  return {
    async start() {
      if (hid) return { started: true, path: opened.path };
      const HID = loadNodeHid(loadHid);
      const chosen = selectDevice(findOnlyKeys(HID), path);
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
      return { started: true, path: chosen.path };
    },

    async stop() {
      close();
    },

    isRunning() {
      return hid !== null;
    },

    async write(iface, bytes) {
      if (iface !== IFACE.VENDOR) {
        throw new Error(
          `the desktop HID pipe opens only the vendor interface (${IFACE.VENDOR}); `
          + `interface ${iface} is not open`);
      }
      if (!hid) {
        throw hidError('ENOTOPEN',
          lastError ? `the OnlyKey went away: ${lastError.message}` : 'the OnlyKey is not open');
      }
      const frame = Uint8Array.from(bytes);
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
      const written = hid.write(Array.from(withReportId(frame)));
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

    on(event, listener) {
      if (event !== 'stream') throw new Error(`the HID pipe has no "${event}" event`);
      listeners.add(listener);
      return () => listeners.delete(listener);
    },

    /** The enumeration entry of the key that was opened, or null. */
    get device() { return opened; },
  };
}

module.exports = { createHidPipe, loadNodeHid, findOnlyKeys, selectDevice, USB_ID };
