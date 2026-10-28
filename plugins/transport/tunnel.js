/*
 * transport/tunnel - a transport with NO vendor interface, for a host that can
 * reach the key only through the WebAuthn tunnel.
 *
 *     plugins = [host, tunnelTransport, session, device, okcrypto];
 *     plugins.config = { okcrypto: { ctap: createWebAuthnCtap({ credentials }) } };
 *
 * WHY A PLACEHOLDER, rather than making the transport optional. `transport` is
 * consumed by session, device AND okcrypto, and each of them validates or uses
 * it; teaching all three to run without one would touch every vendor code path
 * that ok-rn and the kit depend on, to serve a host that never calls them. A
 * stand-in that satisfies the contract (src/transport/contract.js) changes
 * nothing for any existing host - they keep composing embedded/usb/ble exactly
 * as before - and a browser composes this one instead.
 *
 * What a browser CAN do goes through okcrypto's supplied ctap: the tunnel
 * connect that reads the firmware version (okcrypto.connectTunnel), the
 * derives, the vault, the X-Wing pair and the composite sign/decrypt halves.
 *
 * What it cannot do is everything on the vendor interface - setting a PIN,
 * writing a slot, reading a stored public key, session.connect(). Those REFUSE,
 * by name, at the call. Resolving quietly or waiting out a timeout would leave a
 * page author looking for a slow key when the answer is that a web page has no
 * such interface at all (RawHID is not exposed to pages, and WebHID blocks the
 * FIDO usage pages).
 */
'use strict';

const { assertTransport } = require('../../src/transport/contract');
const { laneOf } = require('../../src/transport/lane');

const WHY = 'this host has no vendor interface - it reaches the key only '
  + 'through the WebAuthn tunnel (plugins/transport/tunnel). Use okcrypto with a '
  + 'supplied ctap for what the tunnel carries: connectTunnel(), the derives, the '
  + 'vault, the X-Wing pair and composite_sign/composite_decrypt.';

function refusal(what) {
  const err = new Error(`${what}: ${WHY}`);
  err.code = 'NO_VENDOR_INTERFACE';
  return err;
}

function setup(imports, register) {
  const transport = {
    name: 'tunnel',
    /** Stated, so a host or plugin can ask instead of discovering it by failing. */
    tunnelOnly: true,

    /* Nothing to open or close: the browser owns the only channel there is. */
    async open() {},
    async close() {},
    /** False: no vendor interface is, or ever will be, open here. */
    isOpen() { return false; },

    async write(iface) {
      throw refusal(`write to interface ${iface}`);
    },
    async request({ iface } = {}) {
      throw refusal(`request on interface ${iface}`);
    },
    async requestNow({ iface } = {}) {
      throw refusal(`request on interface ${iface}`);
    },
    /*
     * A REAL LANE, not a stand-in (box, 2026-10-28). The vendor side is refused, but Edge and okcrypto run their
     * tunnel conversations in this lane (inLane), and a conversation over the tunnel is several ceremonies: a request
     * and its polls, an Edge answer and its SUB.MORE (the key keeps the ML-DSA half only until its next Edge request).
     * The stand-in ran every caller at once: the web app's head poll landed between CHECKPOINT and MORE, the key
     * answered MORE "unknown request", and a new copy could never verify ("unsigned"). The WebAuthn ctap's own lane
     * keeps single ceremonies apart; this one keeps conversations apart.
     */
    exclusive(fn, opts) {
      return laneOf(transport)(fn, opts);
    },
    urgentWaiting() {
      return laneOf(transport).urgentWaiting();
    },

    /*
     * Subscribing is allowed and hears nothing. Plugins subscribe to 'report'
     * BEFORE they write (see transport.request in the contract), so refusing
     * here would throw from inside the listener set-up and hide the refusal
     * the write is about to give.
     */
    on() {
      return () => {};
    },
  };

  assertTransport(transport, 'transport/tunnel');
  register(null, { transport });
}

setup.consumes = ['app'];
setup.provides = ['transport'];

module.exports = setup;
