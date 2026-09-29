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
 * @param {object} [opts.config]   further plugins.config, merged under the pipe
 * @returns {Promise<object>} the started Rectify app with the transport OPEN;
 *   its services (device, okcrypto, transport) are the API
 */
'use strict';

function startDesktop({ pipe, path, loadHid, config = {} } = {}) {
  const Rectify = require('@bmatusiak/rectify');
  const { createHidPipe } = require('./transport-hid');
  const plugins = [
    require('../plugins/host'),
    require('../plugins/transport/usb'),
    require('../plugins/session'),
    require('../plugins/device'),
    require('../plugins/okcrypto'),
  ];
  plugins.config = {
    ...config,
    transport: {
      ...(config.transport || {}),
      pipe: pipe || createHidPipe({ path, loadHid }),
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
    return app;
  });
}

module.exports = { startDesktop };
