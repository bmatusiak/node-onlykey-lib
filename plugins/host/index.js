/*
 * host - the only per-platform plugin.
 *
 * It used to need much more. The browser client's own test shim
 * (test-api/window_replacements/index.js) had to supply crypto.subtle, atob,
 * btoa, location.hostname and navigator.credentials.get. Moving the crypto to
 * @noble removed all but one of those: everything hashing, signing and
 * deriving is now pure JS that runs the same in Node, a browser and Hermes.
 *
 * What is left is randomness, a clock, and - for the WebAuthn tunnel only -
 * a way to run a CTAP2 ceremony. The tunnel is a browser concern, so it is
 * optional here and a transport that needs it says so.
 *
 * Rectify's own "app" service already carries EventEmitter, window/global and
 * the isBrowser/isNode/isElectron/isNWJS flags, so this does not duplicate any
 * of that.
 */
'use strict';

const { randomBytes } = require('@noble/hashes/utils.js');

function setup(imports, register, config) {
  const { app } = imports;
  /*
   * Rectify hands config as the THIRD argument, the same way
   * plugins/transport/embedded.js takes its pipe:
   *
   *     plugins.config = { host: { store: AsyncStorage } };
   */
  const settings = (config && config.host) || {};

  register(null, {
    host: {
      /** Cryptographically secure bytes. Backed by webcrypto in every runtime. */
      randomBytes,

      /** Injectable so a test can pin the OKCONNECT timestamp. */
      now: () => Date.now(),

      /*
       * Persistent key/value storage, or null.
       *
       * Supplied by the host for the same reason randomness is: AsyncStorage
       * on a phone, localStorage in a browser, a Map in Node, and none of
       * them belong in a platform-free library. Three methods - getItem,
       * setItem, removeItem - because that is the intersection of what every
       * platform offers.
       *
       * NULL is a legitimate answer. A host with nowhere to persist still
       * works; what it loses is the vault surviving a relaunch, and the code
       * that needs it says so rather than failing at a write.
       */
      store: settings.store || null,

      /*
       * Which runtime this is, taken from rectify rather than re-sniffed.
       * The OKCONNECT payload carries a browser byte and an OS byte, but they
       * are display-only - nothing on the device branches on them.
       */
      env: {
        isNode: app.isNode,
        isBrowser: app.isBrowser,
        isElectron: app.isElectron,
        isNWJS: app.isNWJS,
      },
    },
  });
}

setup.consumes = ['app'];
setup.provides = ['host'];

module.exports = setup;
