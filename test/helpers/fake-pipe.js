/*
 * A stand-in for the JNI byte pipe, faithful to the parts that matter.
 *
 * Modelled on ok_hal.cpp's okemu_hid_deliver(), not on a convenient idea of
 * what a device does. Two of its behaviours are the reason this exists:
 *
 *   - It ECHOES every inbound write back through the same stream callback with
 *     dir = IN, exactly as stream_emit() does. A transport that does not filter
 *     on direction will resolve each request with the bytes it just sent, and
 *     against a real device that looks like a device that mirrors rather than a
 *     bug in the host.
 *
 *   - It pads inbound frames to 64 itself and takes the payload verbatim - no
 *     report ID. A transport that prepends one shifts every field by a byte.
 */
'use strict';

const { IFACE, DIR, REPORT_SIZE } = require('../../src/transport/contract');

function fakePipe({ autoStart = false } = {}) {
  const listeners = new Set();
  let running = autoStart;

  const writes = [];

  function emit(event) {
    for (const listener of [...listeners]) listener(event);
  }

  return {
    /* ---- the pipe contract ------------------------------------------- */

    async start() {
      running = true;
      return { started: true, storageDir: '/fake/okemu' };
    },
    async stop() {
      running = false;
    },
    isRunning() {
      return running;
    },
    async write(iface, bytes) {
      const frame = Uint8Array.from(bytes);
      writes.push({ iface, data: frame });

      /* The emulator pads to 64 on the way in and echoes what it received. */
      const delivered =
        iface === IFACE.SEREMU ? frame : padTo(frame, REPORT_SIZE);
      emit({ iface, dir: DIR.IN, bytes: delivered });
      return delivered.length;
    },
    on(event, listener) {
      if (event !== 'stream') throw new Error(`fake pipe has no "${event}" event`);
      listeners.add(listener);
      return () => listeners.delete(listener);
    },

    /* ---- test controls ------------------------------------------------ */

    /** Everything the transport asked us to write, in order. */
    writes,

    /** Push a device -> host report. Bytes are delivered exactly as given. */
    deliver(bytes, { iface = IFACE.VENDOR } = {}) {
      emit({ iface, dir: DIR.OUT, bytes: Uint8Array.from(bytes) });
    },

    /** Push a SEREMU line, padded to a full report the way hidprint() does. */
    deliverText(text, { iface = IFACE.SEREMU, pad = true } = {}) {
      const body = new Uint8Array(text.length);
      for (let i = 0; i < text.length; i++) body[i] = text.charCodeAt(i) & 0xff;
      emit({
        iface,
        dir: DIR.OUT,
        bytes: pad ? padTo(body, REPORT_SIZE) : body,
      });
    },

    get listenerCount() {
      return listeners.size;
    },
  };
}

function padTo(bytes, size) {
  if (bytes.length >= size) return bytes.subarray(0, size);
  const out = new Uint8Array(size);
  out.set(bytes, 0);
  return out;
}

module.exports = { fakePipe };
