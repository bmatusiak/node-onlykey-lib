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
 * With `ble: true` the transport is transport/ble instead, over the Bluetooth
 * pipe in ./transport-ble.js - a phone running ok-rn, its soft key's vendor
 * interface published as a GATT service. Nothing above the transport changes,
 * which is what lets every command (agent and gpg-agent included) take --ble.
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
 * @param {boolean} [opts.ble]     reach a phone over Bluetooth LE, not USB
 * @param {string} [opts.address]  with ble: which phone (address or name)
 * @param {() => object} [opts.loadNoble]  returns @stoprocent/noble; injectable
 * @param {() => object} [opts.loadDbus]   returns dbus-next; injectable
 * @param {object} [opts.config]   further plugins.config, merged under the pipe
 * @returns {Promise<object>} the started Rectify app with the transport OPEN;
 *   its services (device, okcrypto, transport) are the API
 */
'use strict';

function startDesktop({ pipe, path, loadHid, ble = false, address, loadNoble, loadDbus, config = {}, pairingHome } = {}) {
  const Rectify = require('@bmatusiak/rectify');
  /*
   * The pipe is built lazily per bus: a --ble run must not touch hidapi (it
   * would enumerate, and on a machine with a hard key plugged in that is the
   * wrong key's business), and a USB run must not load a Bluetooth stack.
   *
   * Part T: over Bluetooth, when THIS user is paired with that phone, the pipe
   * opens an encrypted session first (cli/btpair-store.js); a renewal on day 6
   * of 7 is saved back to the same owner-only file.
   */
  const makeBlePipe = () => {
    const store = require('./btpair-store');
    /*
     * ok-rn answers only paired computers (Part T) and refuses everything else
     * with silence - so without a pairing, say so before a request times out
     * with nothing but "no reply". Plaintext still works only against a phone
     * in testing mode with transit switched off.
     */
    if (!store.pairingFor(address, pairingHome)) {
      process.stderr.write(`onlykey-js: this computer user is not paired with ${address || 'the phone'} - ok-rn answers only paired computers. `
        + `Pair first: onlykey-js --ble${address ? ` --address ${address}` : ''} pair (and ok-rn > Bluetooth > Pair a computer).\n`);
    }
    return require('./transport-ble').createBlePipe({
      address, loadNoble, loadDbus,
      pairing: store.pairingFor(address, pairingHome),
      computerName: store.computerName(),
      onPairingRenewed: (record) => store.savePairing(address, record, pairingHome),
      /* the link going down and coming back, said where a long-running edge-agent's log shows it */
      onLink: (line) => process.stderr.write(`onlykey-js ble: ${line}\n`),
    });
  };
  const makePipe = () => (ble ? makeBlePipe() : require('./transport-hid').createHidPipe({ path, loadHid }));
  const plugins = [
    require('../plugins/host'),
    ble ? require('../plugins/transport/ble') : require('../plugins/transport/usb'),
    require('../plugins/session'),
    require('../plugins/device'),
    require('../plugins/okcrypto'),
    /* OKGETCONFIG (soft key only): silent until a command asks it to read */
    require('../plugins/config'),
  ];
  plugins.config = {
    ...config,
    transport: {
      ...(config.transport || {}),
      pipe: pipe || makePipe(),
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
