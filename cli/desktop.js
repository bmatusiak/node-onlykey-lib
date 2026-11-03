/*
 * cli/desktop.js - the library composed for a desktop Node process, in one call.
 *
 *   const { startDesktop } = require('node-onlykey-lib/cli/desktop');
 *   const app = await startDesktop();            // opens the one OnlyKey
 *   const { device } = app.services;
 *   await device.connect();
 *   ...
 *   await app.destroy();                          // releases it
 *
 * The sibling of plugins/browser.js. A page reaches the key only through
 * WebAuthn, so its stack is tunnel-only; a desktop process can open the VENDOR
 * interface directly, so this one is the full stack ok-rn runs:
 *
 *   [host, transport/usb, session, device, okcrypto]
 *
 * with transport/usb fed by the node-hid pipe in ./transport-hid.js. It is the
 * same transport plugin the phone uses for a hard key - only the pipe beneath it
 * differs - so a CLI command exercises the code the GUIs ship, not a copy.
 *
 * The other pipes go under the same transport/usb: `desktop: true` is the key
 * the ok-edge desktop app holds, over its local socket (./transport-desktop.js) - its soft key
 * included (the soft key is the app's alone since 2026-11-02) - and `ble: true` the phone's key through the room it joined over Bluetooth on this
 * computer's mcp-server (./ble-room.js, the desktop pipe on another channel). Nothing above the transport changes, which is what
 * lets every command (agent and gpg-agent included) take any of them.
 *
 * WHY A HELPER. Every Node consumer - this CLI now, the test kit's hardware
 * runs and any script after them - would otherwise repeat the composition and
 * drift: which plugins, in what order, where the pipe goes, and who OPENS the
 * transport. That last one is easy to miss: no plugin opens it (it is the
 * host's decision when to take the device), so a stack that forgets gets
 * "the OnlyKey is not open" on its first request.
 *
 * @param {object} [opts]
 * @param {object} [opts.pipe]     a byte pipe to use instead of node-hid - the
 *                                 test fakes, or the emulator's bus
 * @param {string} [opts.path]     which key, when more than one is plugged in
 * @param {() => object} [opts.loadHid]  returns node-hid; injectable
 * @param {boolean} [opts.desktop] the key the ok-edge desktop app holds
 * @param {boolean} [opts.ble]     the phone's key, through its room on this computer's mcp-server
 * @param {object} [opts.config]   further plugins.config, merged under the pipe
 * @returns {Promise<object>} the started Rectify app with the transport OPEN;
 *   its services (device, okcrypto, transport) are the API
 */
'use strict';

function startDesktop({ pipe, path, loadHid, desktop = false, ble = false, config = {} } = {}) {
  const Rectify = require('@bmatusiak/rectify');
  /*
   * The pipe is built lazily per bus: a desktop-app run must not
   * touch hidapi (it would enumerate, and on a machine with a hard key plugged
   * in that is the wrong key's business).
   */
  /* desktop: the key the ok-edge desktop app holds, over its local socket (cli/transport-desktop.js) */
  /* ble: the same pipe, its channel the phone's room (./ble-room.js); what the owner must do is said on stderr */
  const makePipe = () => (ble ? require('./transport-desktop').createDesktopPipe({ channel: require('./ble-room').phoneChannel({ say: (l) => process.stderr.write(`${l}\n`) }) })
    : desktop ? require('./transport-desktop').createDesktopPipe()
    : require('./transport-hid').createHidPipe({ path, loadHid }));
  const plugins = [
    require('../plugins/host'),
    require('../plugins/transport/usb'),
    require('../plugins/session'),
    require('../plugins/device'),
    require('../plugins/okcrypto'),
    /* OKGETCONFIG (soft key only): silent until a command asks it to read */
    require('../plugins/config'),
    /*
     * WHO THE KEY IS, READ ONCE (plugins/identity; PROPOSAL-sync-and-identity.md Phase 1): the bucket identity the Key
     * Chain, the Edge logs and the bucket trade all file under - one held read per command instead of each reading it.
     * Lazy: nothing is asked until something calls load().
     */
    require('../plugins/identity'),
  ];
  const thePipe = pipe || makePipe();
  plugins.config = {
    ...config,
    transport: {
      ...(config.transport || {}),
      pipe: thePipe,
    },
  };

  return new Promise((resolve, reject) => {
    const app = Rectify.build(plugins, (err, started) => (err ? reject(err) : resolve(started)));
    app.start();
  }).then(async (app) => {
    try {
      await app.services.transport.open();
    } catch (err) {
      /*
       * Torn down before rethrowing. A half-built app still holds the pipe's
       * listeners, and a CLI that exits on the error would otherwise leave the
       * cleanup to process exit - fine for a process, wrong for a test runner
       * or a long-lived host that retries.
       */
      await app.destroy().catch(() => {});
      throw err;
    }
    /*
     * THROUGH THE DESKTOP APP, ITS PRESS SHEET (cli/transport-desktop.js tell): each request's progress - the press wait
     * included - goes to the app, which shows it as it shows its own. app.tellHolder: Edge's requests too (register.js).
     */
    /* the key is the desktop app's (its pipe), not one this process opened itself - a plugin's wrapper reads it (edge/cli/plugin.js) */
    app.throughDesktopApp = thePipe.desktop === true;
    if (typeof thePipe.tell === 'function') {
      const tell = (kind, e) => { try { thePipe.tell(kind, e); } catch (_) { /* the sheet is not the request */ } };
      if (app.services.okcrypto && typeof app.services.okcrypto.on === 'function') {
        app.services.okcrypto.on('tunnel', (e) => tell('tunnel', e));
        /* and each press it asks (okcrypto 'press'): the app's log says it, and its sheet is inspected against it */
        app.services.okcrypto.on('press', (e) => tell('press', e));
      }
      app.tellHolder = tell;
    }
    return app;
  });
}

module.exports = { startDesktop };
