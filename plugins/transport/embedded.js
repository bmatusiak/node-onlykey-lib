/*
 * transport/embedded - the firmware running in this process.
 *
 * On Android the OnlyKey firmware is compiled to a .so and runs on its own
 * thread behind JNI, so "the device" is a function call away rather than a bus
 * away. This plugin is the seam between that and the rest of the library.
 *
 * It does NOT import react-native, or reach for a TurboModule. The host passes
 * in a byte pipe through Rectify config:
 *
 *     const plugins = [hostPlugin, embeddedTransport, sessionPlugin, ...];
 *     plugins.config = { transport: { pipe: OkEmu } };
 *
 * Two reasons. The library has to stay loadable in Node, a browser and nw.js,
 * where that module does not exist and importing it is a hard failure at
 * require time rather than a graceful absence. And a pipe is a small enough
 * surface to fake, so everything below can be tested without a device - which
 * is the only way the normalisation rules get tested at all.
 *
 * THE PIPE CONTRACT (what the host supplies)
 *
 *   start()                 -> Promise, boot the firmware
 *   stop()                  -> Promise, halt it
 *   isRunning()             -> boolean
 *   write(iface, bytes)     -> Promise, host -> device
 *   on('stream', listener)  -> unsubscribe fn; listener gets
 *                              {iface, dir, bytes} for traffic BOTH ways
 *
 * Note the last one. The pipe hands over everything it sees, in both
 * directions and on all four interfaces, and this plugin does the demultiplexing
 * and normalisation itself. It would be easier to let the host pre-filter -
 * ok-rn's OkEmu already emits a convenience `report` event for device-bound
 * traffic - but then half the transport contract would live in the app, and the
 * next host would have to reimplement it and get it subtly different. That is
 * the exact failure the contract exists to prevent.
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
      'transport/embedded needs a byte pipe: plugins.config = { transport: { pipe } }',
    );
  }
  for (const method of ['start', 'stop', 'isRunning', 'write', 'on']) {
    if (typeof pipe[method] !== 'function') {
      throw new TypeError(`transport/embedded: pipe is missing ${method}()`);
    }
  }

  const events = new EventEmitter();

  /**
   * Inbound demultiplexing, and the only place the normalisation rules are
   * applied on this transport.
   *
   * Mirrors onlykey-testing/lib/device/hardware.js:351-375, which is the
   * implementation proven against both a physical key and an emulated one.
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
       * memsets a 64-byte buffer and writes a short line into it, so the tail
       * is buffer rather than message - and a NUL reaching a regex makes it
       * fail to match something that is plainly there.
       *
       * Empty after stripping means the device sent nothing but padding; the
       * reference drops those rather than emitting blank lines into a log that
       * is matched against.
       */
      const text = toLatin1(stripPadding(bytes));
      if (text) events.emit('log', { text });
      return;
    }

    if (event.iface === IFACE.KEYBOARD) {
      events.emit('keyboard', { data: bytes });
      return;
    }

    /*
     * FIDO and vendor keep all 64 bytes. Their readers index by offset, and a
     * NUL inside a vendor report is a real byte - the transit box produces
     * them routinely, since it is a keystream over arbitrary plaintext.
     * Stripping here would corrupt a sealed payload in a way that only shows
     * up as a decryption that yields noise.
     */
    events.emit('report', { iface: event.iface, data: bytes });
  }

  const unsubscribe = pipe.on('stream', onStream);

  const transport = {
    name: 'embedded',

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
       * No report ID, on either side.
       *
       * The proven hardware client prepends a zero byte because hidapi and
       * chrome.hid want one. This bus does not: okemu_hid_deliver() copies the
       * payload straight into a 64-byte packet
       * (`pkt.data.assign(64, 0); memcpy(..., len < 64 ? len : 64)`), so a
       * report ID here would shift every field by one and the firmware would
       * read our message id as its header.
       *
       * That same memcpy also truncates silently at 64. toReport() throws
       * instead, so an over-long frame is a caller error with a length in the
       * message rather than a message the device half-receives.
       */
      const frame = iface === IFACE.SEREMU ? bytes : toReport(bytes);
      return pipe.write(iface, frame);
    },

    async request({ iface, data, timeoutMs = 3000 }) {
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          off();
          reject(new Error(`no reply on interface ${iface} within ${timeoutMs}ms`));
        }, timeoutMs);

        const onReport = (event) => {
          /*
           * Filtered by interface. The firmware multiplexes four onto one
           * callback, so a SEREMU debug line printed mid-request would
           * otherwise resolve the caller with a fragment of log text.
           */
          if (event.iface !== iface) return;
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

  assertTransport(transport, 'transport/embedded');

  register(null, {
    transport,
    onDestroy: async () => {
      /*
       * Unsubscribe before stopping. The pipe delivers on the firmware thread,
       * so a report already in flight would otherwise land on a listener whose
       * app is being torn down.
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
