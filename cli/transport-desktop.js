'use strict';

/**
 * cli/transport-desktop.js - the key, reached through the ok-edge desktop app on this machine
 * (`onlykey-js --desktop`, and plain `onlykey-js` while the app runs; ok-edge TODO B4b).
 *
 * The app holds the hard key on USB; this is a pipe with transport-hid's contract (start, stop,
 * isRunning, write, on 'stream' / 'close', device, interfaces) whose reports travel over the app's
 * local socket (desktop/serve.js). So everything above it - the transport plugin, the device, Edge's
 * wire channel to the host - is the same code as on USB and over Bluetooth.
 *
 * Trust: the app's desktop.json in the shared home (desktop/trust.js) - its socket and its token;
 * the hello carries the token. The write is echoed (dir IN) here, as every pipe echoes its own writes
 * (cli/transport-hid.js); the app forwards only the key's own reports (dir OUT).
 */

const net = require('net');
const { DIR } = require('../src/transport/contract');
const trust = require('../desktop/trust');
const { HELLO_MS, send, readLines, toB64, fromB64 } = require('../desktop/protocol');

const desktopError = (code, message) => Object.assign(new Error(message), { code });

/**
 * @param {object} [o]
 * @param {object} [o.record] the app's trust record (default: the live desktop.json)
 * @param {string} [o.root] the shared home (tests)
 * @param {(path: string) => import('net').Socket} [o.connect]
 */
function createDesktopPipe({ record, root, connect = (p) => net.connect(p) } = {}) {
  const listeners = new Set();
  const closeListeners = new Set();
  let sock = null;
  let ready = null; /* { device, interfaces } once accepted */
  const emit = (ev) => { for (const l of [...listeners]) l(ev); };

  return {
    async start() {
      if (sock && ready) return { started: true, path: 'desktop' };
      const r = record || trust.liveTrust(root);
      if (!r) throw desktopError('ENODESKTOP', 'the ok-edge desktop app is not running on this computer (no live desktop.json in ~/.onlykey-js)');
      const s = connect(r.socket);
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => { s.destroy(); reject(desktopError('EDESKTOP', 'the desktop app did not answer the hello')); }, HELLO_MS);
        s.once('error', (e) => { clearTimeout(timer); reject(desktopError('EDESKTOP', `could not reach the desktop app (${e && e.message})`)); });
        s.once('connect', () => send(s, { t: 'hello', v: trust.VERSION, token: r.token }));
        readLines(s, (m) => {
          if (m.t === 'ready' && !ready) {
            clearTimeout(timer);
            ready = { device: m.device || null, interfaces: Array.isArray(m.interfaces) ? m.interfaces : [] };
            resolve();
          } else if (m.t === 'refused') {
            clearTimeout(timer);
            reject(desktopError('EDESKTOP', `the desktop app refused: ${m.why}`));
          } else if (m.t === 'report') {
            emit({ iface: m.iface, dir: DIR.OUT, bytes: fromB64(m.b64) });
          } else if (m.t === 'close' || m.t === 'error') {
            const err = new Error(`the desktop app: ${m.why}`);
            if (m.t === 'close') for (const l of [...closeListeners]) l(err);
          }
        });
        s.on('close', () => {
          const was = Boolean(ready);
          sock = null;
          ready = null;
          if (was) for (const l of [...closeListeners]) l(new Error('the desktop app closed the connection'));
        });
      });
      sock = s;
      return { started: true, path: 'desktop' };
    },

    async stop() {
      const s = sock;
      sock = null;
      ready = null;
      if (s) s.end();
    },

    isRunning() { return Boolean(sock && ready); },

    async write(iface, bytes) {
      if (!sock || !ready) throw desktopError('ENOTOPEN', 'the desktop app is not connected');
      const frame = Uint8Array.from(bytes);
      send(sock, { t: 'write', iface, b64: toB64(frame) });
      emit({ iface, dir: DIR.IN, bytes: frame });
      return frame.length + 1;
    },

    on(event, listener) {
      const set = event === 'stream' ? listeners : event === 'close' ? closeListeners : null;
      if (!set) throw new Error(`the desktop pipe has no "${event}" event`);
      set.add(listener);
      return () => set.delete(listener);
    },

    /** the key the app holds, as it described it */
    get device() { return ready ? ready.device : null; },
    interfaces() { return ready ? ready.interfaces : []; },
    /** this pipe goes through the desktop app (register.js: the app is the host) */
    desktop: true,
  };
}

module.exports = { createDesktopPipe };
