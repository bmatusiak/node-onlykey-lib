/*
 * pipeTransport - the transport every byte pipe becomes.
 *
 * transport/embedded and transport/usb were, for a while, DELIBERATELY the
 * same file with a different name: the two were being proven against real
 * hardware for the first time, and extracting the common part then would have
 * meant a broken suite could be either the new bus or the refactor. Both went
 * green - the hard key connects, unlocks, types a slot and reads it back
 * through this code - so the common part now lives here, once. embedded.test.js
 * and usb.test.js are unchanged, which is what proves the extraction preserved
 * behaviour.
 *
 * THE PIPE CONTRACT (what a host supplies)
 *
 *   start()                 -> Promise, open the device (boot the firmware)
 *   stop()                  -> Promise, release it (halt the firmware)
 *   isRunning()             -> boolean
 *   write(iface, bytes)     -> Promise, host -> device
 *   on('stream', listener)  -> unsubscribe fn; listener gets
 *                              {iface, dir, bytes} for traffic BOTH ways
 *
 * Note the last one. The pipe hands over everything it sees, in both
 * directions and on all four interfaces, and THIS does the demultiplexing and
 * normalisation. It would be easier to let the host pre-filter - ok-rn's OkEmu
 * emits a convenience `report` event for device-bound traffic - but then half
 * the transport contract would live in the app, and the next host would have
 * to reimplement it and get it subtly different. That is the failure the
 * contract exists to prevent. A USB pipe physically sees inbound reports only;
 * the host ECHOES its own writes so `dir` means the same thing on both pipes
 * and the filter below is correct on both rather than dead on one.
 *
 * NO REPORT ID, on either side. A desktop client speaking through hidapi or
 * chrome.hid prepends a zero byte because those APIs use it to select a
 * report. Neither pipe here has a HID API in between - the emulator copies the
 * payload straight into a 64-byte packet, Android writes to the endpoint
 * directly - so a leading byte would shift every field along and the firmware
 * would read our message id as its header. That is a message half received
 * rather than an error, the worst shape a bug can take on a bus.
 * `withReportId` in the contract exists for the transports that DO need it.
 *
 * The demultiplexing mirrors onlykey-testing/lib/device/hardware.js:351-375,
 * the implementation proven against both a physical key and an emulated one.
 */
'use strict';

const { IFACE, DIR, assertTransport, stripPadding, toReport } = require('./contract');
const { toLatin1 } = require('../bytes');

/**
 * Build a transport over a byte pipe.
 *
 * @param {object} opts
 * @param {string} opts.name          the transport's name, and the plugin's, for errors
 * @param {object} opts.pipe          the host's byte pipe (contract above)
 * @param {Function} opts.EventEmitter the host's EventEmitter class
 * @returns {{ transport: object, destroy: () => Promise<void> }}
 */
function createPipeTransport({ name, pipe, EventEmitter }) {
  const label = `transport/${name}`;

  /*
   * Checked here, not on first use. A missing pipe is a composition mistake,
   * and failing at build time names the plugin; failing later surfaces as a
   * TypeError inside a poll loop with no hint of where the wiring went wrong.
   */
  if (!pipe || typeof pipe !== 'object') {
    throw new TypeError(
      `${label} needs a byte pipe: plugins.config = { transport: { pipe } }`,
    );
  }
  for (const method of ['start', 'stop', 'isRunning', 'write', 'on']) {
    if (typeof pipe[method] !== 'function') {
      throw new TypeError(`${label}: pipe is missing ${method}()`);
    }
  }

  const events = new EventEmitter();

  /**
   * Inbound demultiplexing, and the only place the normalisation rules are
   * applied. They are properties of what the FIRMWARE sends, and the firmware
   * is the same firmware on either pipe.
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
       * to match something that is plainly there. Empty after stripping means
       * the device sent nothing but padding; those are dropped rather than
       * emitted as blank lines into a log that is matched against.
       */
      const text = toLatin1(stripPadding(bytes));
      if (text) events.emit('log', { text });
      return;
    }

    if (event.iface === IFACE.KEYBOARD) {
      /*
       * What the key TYPES, captured rather than delivered to the operating
       * system. This is the interface a host claims on purpose: left alone, a
       * real key types into whatever window has focus instead of into the app.
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
    name,

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
       * append NULs the firmware then has to ignore, which it does, but on a
       * real key its outbound endpoint is 32 bytes rather than 64 so a padded
       * write would not even fit. toReport() throws on an over-long frame
       * rather than truncating (the emulator's memcpy truncates silently), so
       * an oversized message is a caller error with a length in it rather than
       * a message the device half-receives.
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

  assertTransport(transport, label);

  /*
   * Unsubscribe before closing. Reports arrive on another thread - the
   * firmware's, or a USB reader's - so one already in flight would otherwise
   * land on a listener whose app is being torn down.
   */
  const destroy = async () => {
    if (typeof unsubscribe === 'function') unsubscribe();
    events.removeAllListeners();
    await transport.close();
  };

  return { transport, destroy };
}

module.exports = { createPipeTransport };
