/*
 * transport/usb - a physical OnlyKey on a USB bus.
 *
 * The sibling of transport/embedded, and DELIBERATELY A NEAR-COPY of it rather
 * than a shared factory. The two are being proven against real hardware for the
 * first time; extracting the common part now would mean that a broken suite
 * could be either the new bus or the refactor, and there would be no way to
 * tell which. The factory comes after this is green, and embedded.test.js
 * unchanged is what will prove that extraction preserved behaviour.
 *
 * Like its sibling it does NOT import react-native or reach for a native
 * module. The host passes in a byte pipe through Rectify config:
 *
 *     const plugins = [hostPlugin, usbTransport, sessionPlugin, ...];
 *     plugins.config = { transport: { pipe: UsbPipe } };
 *
 * THE PIPE CONTRACT is the same one embedded uses, and that is the point: the
 * session, the device plugin, the crypto plugin and every screen above them are
 * written once and work against either key.
 *
 *   start()                 -> Promise, open the device
 *   stop()                  -> Promise, release it
 *   isRunning()             -> boolean
 *   write(iface, bytes)     -> Promise, host -> device
 *   on('stream', listener)  -> unsubscribe fn; listener gets
 *                              {iface, dir, bytes} for traffic BOTH ways
 *
 * ## What differs from embedded, and where each difference lives
 *
 * Only one difference is in this file: the name. The rest belong below it,
 * because they are properties of the bus rather than of the demultiplexing:
 *
 *   - A USB pipe physically sees inbound reports only. Rather than make this
 *     plugin cope with a half-silent pipe, the HOST echoes its own writes - so
 *     `dir` means the same thing on both pipes and the filter below is correct
 *     on both rather than dead on one.
 *   - Endpoint widths differ per interface, and the debug console's outbound
 *     endpoint is 32 bytes where the others are 64. The layer that knows the
 *     endpoints enforces that.
 *   - A write to the keyboard interface is refused, because it is device to
 *     host only. The emulator refuses it natively for the same reason.
 *
 * ## NO REPORT ID
 *
 * A desktop client speaking through hidapi or chrome.hid prepends a zero byte,
 * because those APIs use it to select a report. There is no HID API here -
 * Android writes to the endpoint directly - so a leading byte would shift every
 * field along and the firmware would read our message id as its header. That is
 * a message half received rather than an error, which is the worst shape a bug
 * can take on a bus. `withReportId` in the contract exists for the transports
 * that DO need it, and must not be reached for here.
 */
'use strict';

const {
  IFACE,
  DIR,
  assertTransport,
  stripPadding,
  toReport,
} = require('../../src/transport/contract');
const { toLatin1 } = require('../../src/bytes');

function setup(imports, register, config) {
  const { app } = imports;
  const EventEmitter = app.EventEmitter;

  const settings = (config && config.transport) || {};
  const pipe = settings.pipe;

  /*
   * Checked here, not on first use. A missing pipe is a composition mistake,
   * and failing at build time names this plugin; failing later surfaces as a
   * TypeError inside a poll loop with no hint of where the wiring went wrong.
   */
  if (!pipe || typeof pipe !== 'object') {
    throw new TypeError(
      'transport/usb needs a byte pipe: plugins.config = { transport: { pipe } }',
    );
  }
  for (const method of ['start', 'stop', 'isRunning', 'write', 'on']) {
    if (typeof pipe[method] !== 'function') {
      throw new TypeError(`transport/usb: pipe is missing ${method}()`);
    }
  }

  const events = new EventEmitter();

  /**
   * Inbound demultiplexing, and the only place the normalisation rules are
   * applied on this transport.
   *
   * Identical to embedded's, deliberately: the rules are properties of what the
   * FIRMWARE sends, and the firmware is the same firmware.
   */
  function onStream(event) {
    /*
     * Host-bound traffic only. The pipe reports our own writes too, and
     * treating one as a reply would make every request resolve with the bytes
     * it just sent.
     */
    if (event.dir !== DIR.OUT) {
      events.emit('write', { iface: event.iface, data: event.bytes });
      return;
    }

    const bytes = event.bytes;

    if (event.iface === IFACE.SEREMU) {
      /*
       * Text, and the ONLY interface whose padding is stripped. hidprint()
       * memsets its buffer and writes a short line into it, so the tail is
       * buffer rather than message - and a NUL reaching a regex makes it fail
       * to match something that is plainly there.
       */
      const text = toLatin1(stripPadding(bytes));
      if (text) events.emit('log', { text });
      return;
    }

    if (event.iface === IFACE.KEYBOARD) {
      /*
       * What the key TYPES, captured rather than delivered to the operating
       * system. This is the interface a host claims on purpose: left alone, the
       * key types into whatever window has focus instead of into the app.
       */
      events.emit('keyboard', { data: bytes });
      return;
    }

    /*
     * FIDO and vendor keep all 64 bytes. Their readers index by offset, and a
     * NUL inside a vendor report is a real byte - the transit box produces them
     * routinely, being a keystream over arbitrary plaintext. Stripping here
     * would corrupt a sealed payload in a way that only shows up as a
     * decryption that yields noise.
     */
    events.emit('report', { iface: event.iface, data: bytes });
  }

  const unsubscribe = pipe.on('stream', onStream);

  const transport = {
    name: 'usb',

    async open() {
      if (!pipe.isRunning()) await pipe.start();
    },
    async close() {
      if (pipe.isRunning()) await pipe.stop();
    },
    isOpen() {
      return Boolean(pipe.isRunning());
    },

    async write(iface, data) {
      const bytes = Uint8Array.from(data);

      /*
       * SEREMU is not padded, and the others are. The debug console takes a
       * line of text terminated by a return - padding it to a fixed width would
       * append NULs the firmware then has to ignore, which it does, but its
       * outbound endpoint is 32 bytes rather than 64 so a padded write would not
       * even fit. toReport() throws on an over-long frame rather than
       * truncating, so an oversized message is a caller error with a length in
       * it rather than a message the device half-receives.
       */
      const frame = iface === IFACE.SEREMU ? bytes : toReport(bytes);
      return pipe.write(iface, frame);
    },

    async request({ iface, data, timeoutMs = 3000, match = null }) {
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          off();
          reject(new Error(`no reply on interface ${iface} within ${timeoutMs}ms`));
        }, timeoutMs);

        const onReport = (event) => {
          /*
           * Filtered by interface. Four are multiplexed onto one callback, so a
           * console line printed mid-request would otherwise resolve the caller
           * with a fragment of log text.
           */
          if (event.iface !== iface) return;
          /*
           * An unsolicited broadcast is not an answer. A locked device emits
           * its status every second, so without this the reply to a write is
           * whichever arrives first - and the caller is told a slot write was
           * acknowledged "INITIALIZED".
           */
          if (match && !match(event.data)) return;
          clearTimeout(timer);
          off();
          resolve(event.data);
        };
        const off = () => events.removeListener('report', onReport);

        /* Subscribed before the write - the whole reason request() exists. */
        events.on('report', onReport);
        transport.write(iface, data).catch((err) => {
          clearTimeout(timer);
          off();
          reject(err);
        });
      });
    },

    on(event, listener) {
      events.on(event, listener);
      return () => events.removeListener(event, listener);
    },
  };

  assertTransport(transport, 'transport/usb');

  register(null, {
    transport,
    onDestroy: async () => {
      /*
       * Unsubscribe before closing. Reports arrive on a reader thread, so one
       * already in flight would otherwise land on a listener whose app is being
       * torn down.
       */
      if (typeof unsubscribe === 'function') unsubscribe();
      events.removeAllListeners();
      await transport.close();
    },
  });
}

setup.consumes = ['app'];
setup.provides = ['transport'];

module.exports = setup;
