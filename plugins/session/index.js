/*
 * session - the OKCONNECT handshake and the transit box.
 *
 * Provides one service holding the session key. `allowed` restricts who may
 * consume it: a logging or UI plugin that asks for "session" fails at build()
 * with a named error, rather than quietly getting a handle on key material.
 * That is the whole reason rectify's allowed exists and this is the obvious
 * place for it.
 *
 * The box this exposes is NOT authenticated encryption. src/session/transit.js
 * has the full account; the short version is that the firmware uses a 12-byte
 * zero IV on every message and has computeTag/checkTag commented out, so one
 * session is one keystream with no integrity at all. It cannot be fixed from
 * the host. The method is called `box`, never `encrypt`, for that reason.
 */
'use strict';

const transit = require('../../src/session/transit');
const { assertTransport } = require('../../src/transport/contract');
const okmsg = require('../../src/protocol/okmsg');
const { IFACE } = require('../../src/protocol/msg');

function setup(imports, register) {
  const { host, transport } = imports;

  /*
   * Validate at the CONSUMER, not only inside each transport. A transport is
   * often a thin wrapper someone wrote in an afternoon; checking here means a
   * missing method is a build failure naming the gap, rather than a TypeError
   * from inside a poll loop twenty seconds in.
   */
  assertTransport(transport, 'transport (consumed by session)');

  /* Per-session state. Replaced wholesale by connect(), never mutated. */
  let keys = null;
  let key = null;
  let device = null;

  const session = {
    /** True once a key exchange has completed. */
    get established() { return Boolean(key); },

    /** The device's reported status string from the last connect(). */
    get status() { return device ? device.status : null; },

    /**
     * Run OKCONNECT.
     *
     * The payload goes out UNENCRYPTED - it is the key exchange itself. A
     * fresh keypair per connect is what scopes the keystream reuse to one
     * session; reusing one across connects would widen it.
     */
    async connect(opts = {}) {
      keys = transit.keypair();
      key = null;
      device = null;

      const payload = transit.connectPayload(keys.publicKey, {
        when: opts.when || host.now(),
      });

      const reply = await transport.request({
        iface: IFACE.VENDOR,
        data: payload,
        timeoutMs: opts.timeoutMs,
      });

      /*
       * Derive from a PROBE parse first, then keep the key only if the reply
       * actually carried a key exchange.
       *
       * Over the vendor interface OKCONNECT is not a key exchange at all -
       * okcore.cpp dispatches it to set_time(), which replies with a plaintext
       * status string and no public key. Deriving unconditionally, as this used
       * to, produced a transit key from the ASCII of that status: `established`
       * went true, box() returned confident nonsense, and the failure appeared
       * later somewhere with no connection to the cause.
       *
       * So a session is established only by an exchange. On the vendor path
       * connect() still succeeds and still reports the device's status - that
       * is genuinely what it is for there - but the session stays unkeyed, and
       * box() says so rather than guessing.
       */
      const probe = transit.parseConnectReply(reply, null);

      if (probe.kind === 'exchange') {
        key = transit.transitKey(probe.devicePublic, keys.secretKey);
        device = transit.parseConnectReply(reply, key);
      } else {
        key = null;
        device = probe;
      }

      return { status: device.status, sealed: device.sealed, kind: device.kind };
    },

    /**
     * Seal or open - the same call, because the operation is its own inverse.
     * Throws rather than silently passing bytes through when no session
     * exists: sending unboxed bytes to a device expecting boxed ones is
     * decrypted into noise and dispatched, with no error anywhere.
     */
    box(data) {
      if (!key) {
        throw new Error('no session: call connect() before box()');
      }
      return transit.box(key, data);
    },

    /** A bound sealer for chunk.sendChunked's `seal` option. */
    sealer() {
      return (chunkBytes) => session.box(chunkBytes);
    },

    /** Forget the key. Called on teardown and by connect() before rekeying. */
    reset() {
      keys = null;
      key = null;
      device = null;
    },
  };

  register(null, {
    session,
    onDestroy: () => session.reset(),
  });
}

setup.consumes = ['host', 'transport'];
setup.provides = ['session'];

/*
 * Only these may consume the session. Anything else asking for it fails at
 * build(), naming itself.
 *
 * ONE GROUP PER PERMITTED PLUGIN, and a group is everything that plugin
 * provides. A flat ['device', 'okcrypto'] is the one-plugin shorthand - it
 * would admit a single plugin providing BOTH names, and reject the two
 * separate plugins actually intended.
 *
 * Note this is stronger than it first appears: a restricted service is never
 * announced, so it does not appear in app.services either. The only way to
 * reach the session is to be a plugin listed here and take it through imports.
 */
setup.allowed = [['device'], ['okcrypto']];

module.exports = setup;
