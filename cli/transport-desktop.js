'use strict';

/**
 * cli/transport-desktop.js - the key, reached through an app that holds it (`onlykey-js --desktop`, and plain
 * `onlykey-js` while the desktop app runs; ok-edge TODO B4b) - and, since 2026-11-01, a phone's key through the room
 * on a local mcp-server (`--ble`, ok-edge plan B4).
 *
 * The app holds the key; this is a pipe with transport-hid's contract (start, stop, isRunning, write, on 'stream' /
 * 'close', device, interfaces) whose reports travel as desktop/protocol.js messages to the app's key session
 * (desktop/session.js). So everything above it - the transport plugin, the device, Edge's wire channel to the host -
 * is the same code as on USB.
 *
 * THE CHANNEL is the one thing that differs: by default the desktop app's local socket, its gate the token in
 * desktop.json (desktop/trust.js) carried by the hello; or one given (`channel`), e.g. the room on a local mcp-server
 * (bucket/src/room-agent.js), its gate the room's accepted agent. The write is echoed (dir IN) here, as every pipe
 * echoes its own writes (cli/transport-hid.js); the app forwards only the key's own reports (dir OUT).
 */

const net = require('net');
const { DIR } = require('../src/transport/contract');
const trust = require('../desktop/trust');
const { HELLO_MS, send, readLines, toB64, fromB64 } = require('../desktop/protocol');

const desktopError = (code, message) => Object.assign(new Error(message), { code });

/*
 * A CHANNEL: what the pipe needs of a carrier, once it is open -
 *   send(obj)          one protocol message out
 *   onMessage(fn)      each message in
 *   onClose(fn)        the carrier went
 *   close()            let it go
 *   hello              the first message to send (the desktop's carries its token)
 *   name               who holds the key, for errors ('the desktop app', 'the phone')
 */

/*
 * WHAT THIS CONNECTION IS FOR, IN THE COMPUTER'S OWN WORDS (Brad, 2026-11-03: "cant onlykey-js send the reason? im
 * expecting the agent using the mcp to send a reason"): the app holding the key says it beside this CLI's requests (its
 * "Working with your key" sheet). ONLYKEY_JS_WHY when the caller set it (edge control ship sets it for each step: the
 * budget's reason, the use an exec signs); else the command's own words - its leading subcommands and, for an exec, the
 * program it runs - never a path, an option's value or a secret. At most WHY_MAX characters.
 */
const WHY_MAX = 200;
function whyOfProcess(argv = process.argv.slice(2), env = process.env) {
  const set = String(env.ONLYKEY_JS_WHY || '').replace(/\s+/g, ' ').trim();
  if (set) return set.slice(0, WHY_MAX);
  const dd = argv.indexOf('--');
  const words = [];
  for (const w of dd >= 0 ? argv.slice(0, dd) : argv) {
    if (words.length >= 3 || w.startsWith('-') || /[\\/]/.test(w)) break;
    words.push(w);
  }
  const ran = dd >= 0 ? argv.slice(dd + 1, dd + 3).filter((w) => !w.startsWith('-') && !/[\\/]/.test(w)) : [];
  return `onlykey-js ${words.join(' ')}${ran.length ? `: ${ran.join(' ')}` : ''}`.trim().slice(0, WHY_MAX);
}

/* the desktop app's local socket, opened (rejects when it cannot be reached) */
function socketChannel({ record, root, connect }) {
  const r = record || trust.liveTrust(root);
  if (!r) return Promise.reject(desktopError('ENODESKTOP', 'the ok-edge desktop app is not running on this computer (no live desktop.json in ~/.onlykey-js)'));
  const s = connect(r.socket);
  return new Promise((resolve, reject) => {
    s.once('error', (e) => reject(desktopError('EDESKTOP', `could not reach the desktop app (${e && e.message})`)));
    s.once('connect', () => {
      const msgs = new Set();
      const closes = new Set();
      readLines(s, (m) => { for (const f of [...msgs]) f(m); });
      s.on('close', () => { for (const f of [...closes]) f(); });
      resolve({
        send: (obj) => send(s, obj),
        onMessage: (f) => msgs.add(f),
        onClose: (f) => closes.add(f),
        close: () => s.end(),
        hello: { t: 'hello', v: trust.VERSION, token: r.token, why: whyOfProcess() },
        name: 'the desktop app',
      });
    });
  });
}

/**
 * @param {object} [o]
 * @param {object} [o.record] the app's trust record (default: the live desktop.json)
 * @param {string} [o.root] the shared home (tests)
 * @param {(path: string) => import('net').Socket} [o.connect]
 * @param {() => Promise<object>} [o.channel] another carrier (see A CHANNEL above) - in place of the local socket
 */
/* a request's progress, as the sheet reads it (ok-edge src/keyBusy.ts) - plain fields, never bytes */
const BUSY_FIELDS = ['phase', 'id', 'msg', 'slot', 'sub', 'step', 'steps', 'waiting', 'limitMs', 'pressAt', 'answered', 'ok', 'error', 'code'];

function createDesktopPipe({ record, root, connect = (p) => net.connect(p), channel = null } = {}) {
  const listeners = new Set();
  const closeListeners = new Set();
  let chan = null;
  let ready = null; /* { device, interfaces } once accepted */
  let name = 'the desktop app';
  const emit = (ev) => { for (const l of [...listeners]) l(ev); };

  return {
    async start() {
      if (chan && ready) return { started: true, path: 'desktop' };
      const c = await (channel ? channel() : socketChannel({ record, root, connect }));
      name = c.name || name;
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => { c.close(); reject(desktopError('EDESKTOP', `${name} did not answer the hello`)); }, HELLO_MS);
        c.onMessage((m) => {
          if (m.t === 'ready' && !ready) {
            clearTimeout(timer);
            ready = { device: m.device || null, interfaces: Array.isArray(m.interfaces) ? m.interfaces : [] };
            resolve();
          } else if (m.t === 'refused') {
            clearTimeout(timer);
            reject(desktopError('EDESKTOP', `${name} refused: ${m.why}`));
          } else if (m.t === 'report') {
            emit({ iface: m.iface, dir: DIR.OUT, bytes: fromB64(m.b64) });
          } else if (m.t === 'close' || m.t === 'error') {
            const err = new Error(`${name}: ${m.why}`);
            if (m.t === 'close') for (const l of [...closeListeners]) l(err);
          }
        });
        c.onClose(() => {
          const was = Boolean(ready);
          chan = null;
          ready = null;
          clearTimeout(timer);
          if (was) for (const l of [...closeListeners]) l(new Error(`${name} closed the connection`));
          else reject(desktopError('EDESKTOP', `${name} closed the connection before it was ready`));
        });
        c.send(c.hello);
      });
      chan = c;
      return { started: true, path: 'desktop' };
    },

    async stop() {
      const c = chan;
      chan = null;
      ready = null;
      if (c) c.close();
    },

    isRunning() { return Boolean(chan && ready); },

    async write(iface, bytes) {
      if (!chan || !ready) throw desktopError('ENOTOPEN', `${name} is not connected`);
      const frame = Uint8Array.from(bytes);
      chan.send({ t: 'write', iface, b64: toB64(frame) });
      emit({ iface, dir: DIR.IN, bytes: frame });
      return frame.length + 1;
    },

    on(event, listener) {
      const set = event === 'stream' ? listeners : event === 'close' ? closeListeners : null;
      if (!set) throw new Error(`the desktop pipe has no "${event}" event`);
      set.add(listener);
      return () => set.delete(listener);
    },

    /*
     * THE CLI'S OWN REQUESTS, SHOWN BY THE APP (Brad, 2026-11-02, Windows: the agent identity's certificate waited for a press
     * through the desktop app and no press sheet came - "i thought we covered press sheets are shown if a press is
     * required"). The app sees only the CLI's bytes; the CLI says each request's progress (okcrypto 'tunnel', edge
     * onRequest) and the app's page feeds them to the same sheet its own requests use. Progress only - nothing of a key.
     */
    tell(kind, e) {
      if (!chan || !ready || !e) return;
      const pick = {};
      for (const k of BUSY_FIELDS) if (e[k] !== undefined && (typeof e[k] !== 'object' || e[k] === null)) pick[k] = e[k];
      chan.send({ t: 'busy', kind, e: pick });
    },

    /** the key the app holds, as it described it */
    get device() { return ready ? ready.device : null; },
    interfaces() { return ready ? ready.interfaces : []; },
    /** this pipe goes through an app that holds the key (register.js: the app is the host) */
    desktop: true,
  };
}

module.exports = { createDesktopPipe, whyOfProcess };
