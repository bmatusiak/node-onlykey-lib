/*
 * browser.js - the library composed for a web page, in one call.
 *
 *   const { startBrowser } = require('node-onlykey-lib/browser');
 *   const app = await startBrowser({ credentials: navigator.credentials });
 *   await app.services.okcrypto.connectTunnel();
 *
 * A page reaches the key only through WebAuthn, so the stack is TUNNEL-ONLY:
 * [host, tunnel transport, session, device, okcrypto], with okcrypto's ctap
 * run by navigator.credentials (transport/webauthn). The tunnel transport is a
 * placeholder that refuses vendor writes by name, so an operation that needs
 * the vendor interface fails saying so instead of hanging.
 *
 * WHY HERE. Every browser GUI - the web app now, anything after it - would
 * otherwise repeat this composition, and each copy would drift: which plugins,
 * in which order, where the ctap goes. It also keeps Rectify (this library's
 * plugin framework) a detail of the library rather than a dependency of every
 * page. The test kit composes the same stack for its tunnel tests.
 *
 * @param {object} opts
 * @param {object} opts.credentials   navigator.credentials (injected, never read from a global)
 * @param {string} [opts.rpId]        one of the admitted origins - see RP_ID in src/protocol/ctap.js
 * @param {number} [opts.timeoutMs]   per WebAuthn request
 * @param {object} [opts.config]      further plugins.config, merged under the ctap
 * @returns {Promise<object>} the started Rectify app; its services are the API
 */
'use strict';

function startBrowser({ credentials, rpId, timeoutMs, config = {} } = {}) {
  if (!credentials || typeof credentials.get !== 'function') {
    return Promise.reject(new TypeError(
      'startBrowser needs { credentials } - navigator.credentials in a page',
    ));
  }
  const Rectify = require('@bmatusiak/rectify');
  const { createWebAuthnCtap } = require('../src/transport/webauthn');
  const plugins = [
    require('./host'),
    require('./transport/tunnel'),
    require('./session'),
    require('./device'),
    require('./okcrypto'),
  ];
  plugins.config = {
    ...config,
    okcrypto: {
      ...(config.okcrypto || {}),
      ctap: createWebAuthnCtap({ credentials, rpId, timeoutMs }),
    },
  };
  return new Promise((resolve, reject) => {
    const app = Rectify.build(plugins, (err, started) => (err ? reject(err) : resolve(started)));
    app.start();
  });
}

module.exports = { startBrowser };
