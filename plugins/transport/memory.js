/*
 * transport/memory - an in-process fake device.
 *
 * Two jobs. It is the test double every consumer of this library needs, and it
 * is the only transport that can run in a unit test with no hardware, no
 * emulator process and no socket.
 *
 * It answers OKCONNECT for real - a genuine X25519 keypair, the same
 * beforenm/SHA-256 derivation the firmware does, and a status tail sealed with
 * the resulting key. That is deliberate: a fake that returns a canned reply
 * would let a broken key derivation pass, which is exactly the bug that is
 * hardest to see from the outside.
 *
 * Rectify v2's setup takes (imports, register) with no options argument, so a
 * transport is selected by putting its plugin in the config array rather than
 * by configuring one generic transport. This is one of several; the embedded,
 * USB and tunnel ones are the same shape.
 */
'use strict';

const transit = require('../../src/session/transit');
const okmsg = require('../../src/protocol/okmsg');
const { IFACE, MSG } = require('../../src/protocol/msg');
const { assertTransport, toReport } = require('../../src/transport/contract');
const { fromLatin1 } = require('../../src/bytes');

/**
 * What the fake device reports. Matches the shape a real uninitialised device
 * returns, including the trailing version string.
 */
const DEFAULT_STATUS = 'UNINITIALIZEDv3.0.4-testc';

function setup(imports, register) {
  const { app } = imports;
  const EventEmitter = app.EventEmitter;

  const events = new EventEmitter();
  let open = false;

  /* The fake device's own long-lived identity, as a real key would have. */
  const deviceKeys = transit.keypair();
  let sessionKey = null;
  let status = DEFAULT_STATUS;

  /** Queued canned replies, for tests that need a specific answer. */
  const queued = [];

  function handle(iface, frame) {
    if (iface !== IFACE.VENDOR) return null;

    if (queued.length) return queued.shift();

    const msg = frame[4];

    if (msg === MSG.OKCONNECT) {
      /*
       * Derive exactly as the firmware does, so a client whose beforenm is
       * wrong fails here rather than passing and failing later against
       * hardware.
       */
      const hostPublic = frame.subarray(9, 41);
      sessionKey = transit.transitKey(hostPublic, deviceKeys.secretKey);

      const tail = transit.box(sessionKey, fromLatin1(status));
      const reply = new Uint8Array(32 + tail.length);
      reply.set(deviceKeys.publicKey, 0);
      reply.set(tail, 32);
      return reply;
    }

    /* Anything else gets the status broadcast a real device emits. */
    return toReport(fromLatin1(status));
  }

  const transport = {
    name: 'memory',

    async open() { open = true; },
    async close() { open = false; sessionKey = null; },
    isOpen() { return open; },

    async write(iface, data) {
      /*
       * Padded here, like every other transport. This used to forward the
       * caller's bytes unchanged, which made memory the odd one out: a short
       * frame reached the fake device as a short frame, while the same call
       * over the embedded transport arrived as a full 64-byte report. Any test
       * that passed here could still fail against a device whose read is a
       * fixed-size descriptor - which is the divergence test/parity.test.js
       * exists to catch, and did.
       */
      const frame = iface === IFACE.SEREMU ? Uint8Array.from(data) : toReport(data);
      events.emit('write', { iface, data: frame });

      /*
       * The fake device's failure is not the transport's failure.
       *
       * handle() does real crypto - that is the point of it - so a malformed
       * frame can make @noble throw, and that used to reject write() itself. No
       * real transport behaves that way: a write succeeds once the bytes are on
       * the bus, whatever the device makes of them. A device that cannot parse
       * a message simply does not answer, so that is what happens here.
       */
      let reply = null;
      try {
        reply = handle(iface, frame);
      } catch (err) {
        events.emit('device-error', { iface, error: err });
      }

      if (reply) {
        // Asynchronous, like a real device - so a caller that subscribes
        // after writing still misses it, exactly as it would on hardware.
        setTimeout(() => events.emit('report', { iface, data: reply }), 0);
      }
      return frame.length;
    },

    async request({ iface, data, timeoutMs = 3000 }) {
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          off();
          reject(new Error(`no reply on interface ${iface} within ${timeoutMs}ms`));
        }, timeoutMs);

        const onReport = (event) => {
          if (event.iface !== iface) return;
          clearTimeout(timer);
          off();
          resolve(event.data);
        };
        const off = () => events.removeListener('report', onReport);

        // Subscribed BEFORE the write, which is the whole point of request().
        events.on('report', onReport);
        transport.write(iface, data).catch((err) => {
          clearTimeout(timer);
          off();
          reject(err);
        });
      });
    },

    on(event, listener) {
      events.on(event, listener);
      return () => events.removeListener(event, listener);
    },

    /* ---- test controls, not part of the transport contract ------------- */

    /** Change what the device reports, e.g. to simulate an unlock. */
    setStatus(next) { status = next; },

    /** Queue an exact reply for the next vendor request. */
    queueReply(bytes) { queued.push(Uint8Array.from(bytes)); },

    /** The key the device derived, so a test can verify both sides agree. */
    get sessionKey() { return sessionKey; },
  };

  assertTransport(transport, 'transport/memory');
  register(null, {
    transport,
    onDestroy: () => transport.close(),
  });
}

setup.consumes = ['app'];
setup.provides = ['transport'];

module.exports = setup;
module.exports.DEFAULT_STATUS = DEFAULT_STATUS;
