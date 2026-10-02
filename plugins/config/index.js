/*
 * config - OKGETCONFIG, the soft key's settings as INI (read-only).
 *
 * The firmware plugin (ok-rn/android/okemu/plugins/config) prints the key's
 * settings; this sends the request and collects the text - whole 64-byte
 * reports, ended by a NUL - and src/config/ini.js reads it. Import is the
 * device plugin's setPreference, one value at a time (see the CLI's `config
 * import`): nothing here writes.
 *
 * WHO ANSWERS: a soft key or emulator built with the config plugin, unlocked,
 * out of config mode (the firmware's config-mode allow-list stops the request
 * first), on the vendor interface. Over the WebAuthn tunnel it is refused. A
 * hard key never has it (owner, 2026-10-02: not emulated, the app is not in
 * the middle) - and says nothing, so read() times out with EUNSUPPORTED.
 *
 * REMOVABLE: nothing else in the library depends on it.
 */
'use strict';

const okmsg = require('../../src/protocol/okmsg');
const { IFACE } = require('../../src/protocol/msg');
const { assertTransport } = require('../../src/transport/contract');
const ini = require('../../src/config/ini');

const OKGETCONFIG = 0x80 | 0x79; /* CHOSEN, next to edge's 0x78 */

function setup(imports, register) {
  const { transport } = imports;
  assertTransport(transport, 'transport (consumed by config)');

  /* the bus carries traffic nobody asked for (edge/index.js busQuiet): let it settle first */
  function busQuiet(quietMs = 150, capMs = 1500) {
    return new Promise((resolve) => {
      let timer = null;
      const finish = () => { clearTimeout(timer); clearTimeout(giveUp); off(); resolve(); };
      const giveUp = setTimeout(finish, capMs);
      const off = transport.on('report', (event) => {
        if (event.iface !== IFACE.VENDOR) return;
        clearTimeout(timer);
        timer = setTimeout(finish, quietMs);
      });
      timer = setTimeout(finish, quietMs);
    });
  }

  /** The key's INI text, whole. */
  async function readText({ timeoutMs = 4000 } = {}) {
    await busQuiet();
    return new Promise((resolve, reject) => {
      const chunks = [];
      let off = null;
      const timer = setTimeout(() => {
        off();
        reject(Object.assign(new Error(
          'config: no answer to OKGETCONFIG - this key has no config plugin (a hard key never does), or it is locked or in config mode'),
        { code: 'EUNSUPPORTED' }));
      }, timeoutMs);
      off = transport.on('report', (event) => {
        if (event.iface !== IFACE.VENDOR) return;
        const bytes = event.data instanceof Uint8Array ? event.data : Uint8Array.from(event.data);
        const text = okmsg.text(bytes);
        if (!chunks.length && /^(UNLOCKED|INITIALIZED)/.test(text)) return; /* a status broadcast, not ours */
        if (!chunks.length && /^Error/.test(text)) {
          clearTimeout(timer);
          off();
          reject(Object.assign(new Error(`config: the key refused OKGETCONFIG: ${text.trim()}`), { code: 'EREFUSED' }));
          return;
        }
        chunks.push(bytes);
        const nul = bytes.indexOf(0);
        if (nul >= 0) {
          clearTimeout(timer);
          off();
          const all = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
          let at = 0;
          for (const c of chunks) { all.set(c, at); at += c.length; }
          let end = all.indexOf(0);
          if (end < 0) end = all.length;
          let s = '';
          for (let i = 0; i < end; i++) s += String.fromCharCode(all[i]);
          resolve(s);
        }
      });
      try {
        transport.write(IFACE.VENDOR, okmsg.build({ msg: OKGETCONFIG, payload: [] }));
      } catch (e) {
        clearTimeout(timer);
        off();
        reject(e);
      }
    });
  }

  const config = {
    OKGETCONFIG,
    readText,
    /** -> {text, version, input, preferences, advanced, unset} */
    async read(opts) {
      const text = await readText(opts);
      return { text, ...ini.parse(text) };
    },
  };
  register(null, { config });
}

setup.consumes = ['transport'];
setup.provides = ['config'];

module.exports = setup;
