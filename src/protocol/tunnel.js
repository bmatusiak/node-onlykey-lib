/*
 * tunnel.js - vendor commands smuggled through a WebAuthn assertion.
 *
 * The third protocol plane, and the one that reaches everything the vendor
 * interface cannot: the transit key exchange, the X-Wing derives, and the
 * composite sign/decrypt halves. All three are read by bridge_to_onlykey() in
 * libraries/fido2/ok_extension.cpp - see
 * FINDING-okconnect-is-two-protocols.md for why OKCONNECT over vendor HID is a
 * different protocol that only sets the clock.
 *
 * The trick, which the firmware is built around: a request is hidden in the
 * `allowList` credential ID of an ordinary authenticatorGetAssertion, and the
 * answer comes back in the one field of the response that carries arbitrary
 * bytes, the assertion's SIGNATURE. A browser cannot reach the vendor
 * interface at all - WebHID would prompt and RawHID is not exposed to pages -
 * so this is how the web app has always talked to the device.
 *
 * This library does NOT need the browser's reason: over the embedded transport
 * it can write to IFACE.FIDO directly. It still uses the same encoding,
 * because the encoding is what the firmware parses.
 *
 * Composed from parts that already exist: protocol/ctap.js encodes the
 * credential ID and decodes the signature, protocol/ctaphid.js runs the CTAP2
 * ceremony. This file is only the join.
 */
'use strict';

const { encodeRequest, decodeAssertion, assertionParams, RP_ID } = require('./ctap');

/**
 * Send one vendor command through the tunnel.
 *
 * @param {object} ctap   a CtapHid with a channel already allocated
 * @param {object} req    {cmd, opt1, opt2, opt3, data}
 * @param {object} opts
 * @param {function} opts.randomBytes  required unless clientDataHash is given
 * @param {Uint8Array} [opts.clientDataHash]  32 bytes, for a reproducible test
 * @param {string} [opts.rpId]
 * @param {function} [opts.onKeepAlive]  called while the device waits for a press
 * @param {number} [opts.timeoutMs]
 */
async function send(ctap, req, opts = {}) {
  const credentialId = encodeRequest(req);

  /*
   * The clientDataHash is 32 bytes of host randomness. It is not decoration:
   * it is what stops a captured assertion being replayed, and the device signs
   * over it.
   *
   * Randomness is INJECTED rather than reached for. There is no portable global
   * here - Node has crypto, Hermes has nothing until a polyfill is installed -
   * and a library that reaches for one fails at the point of use on the
   * platform that lacks it. Asking for it makes the requirement visible at
   * composition time instead.
   */
  let clientDataHash = opts.clientDataHash;
  if (!clientDataHash) {
    if (typeof opts.randomBytes !== 'function') {
      throw new TypeError(
        'tunnel.send needs randomBytes (from the host plugin) or an explicit clientDataHash',
      );
    }
    clientDataHash = opts.randomBytes(32);
  }

  /*
   * The rpId is not a free choice. okcrypto.cpp stages "onlyagent.app" where
   * okcrypto_hkdf() reads it, so everything derived through this path is bound
   * to that origin - asking with a different one derives DIFFERENT KEYS, with
   * no error at any layer. It surfaces much later as "no identity matched any
   * of the recipients" against a file that is perfectly intact.
   */
  const params = assertionParams(credentialId, {
    rpId: opts.rpId || RP_ID,
    clientDataHash,
  });

  const assertion = await ctap.getAssertion(params, opts);
  return decodeAssertion(assertion);
}

/**
 * Bind a tunnel to one CtapHid and one source of randomness.
 *
 * The form a plugin wants: everything platform-specific is supplied once, and
 * callers afterwards pass only the request.
 */
function createTunnel(ctap, { randomBytes, rpId = RP_ID } = {}) {
  return {
    rpId,
    send(req, opts = {}) {
      return send(ctap, req, { randomBytes, rpId, ...opts });
    },
  };
}

module.exports = { send, createTunnel, RP_ID };
