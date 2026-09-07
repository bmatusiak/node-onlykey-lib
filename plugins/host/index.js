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

function setup(imports, register) {
  const { app } = imports;

  register(null, {
    host: {
      /** Cryptographically secure bytes. Backed by webcrypto in every runtime. */
      randomBytes,

      /** Injectable so a test can pin the OKCONNECT timestamp. */
      now: () => Date.now(),

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
