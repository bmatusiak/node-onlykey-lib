/*
 * A CTAP2 bridge: bytes in from a host, bytes out to an authenticator.
 *
 * The phone is not the authenticator here - the firmware is. A desktop browser
 * speaks CTAP-over-BLE to the phone, the phone speaks CTAPHID to the firmware
 * running in its own process, and the CTAP2 message in the middle is IDENTICAL.
 * That is the whole reason this is small: BLE and HID differ only in how they
 * chop a message into fragments, and both sides of that are already written.
 *
 *     browser --BLE--> [Kotlin reassembles] --> handle() --CTAPHID--> firmware
 *                                                      <--------------
 *
 * TWO RULES, both of which a naive bridge breaks.
 *
 * IT DOES NOT INTERPRET. The response goes back exactly as it arrived, status
 * byte and all. Decoding the CBOR and re-encoding it is not a no-op: authData
 * and the attestation statement are SIGNED over exact bytes, so a map that
 * comes back with one integer at a different width verifies as a forgery at the
 * relying party. Errors are forwarded for the same reason - a browser told
 * CTAP2_ERR_NO_CREDENTIALS tries another authenticator, where one told "it
 * failed" gives up.
 *
 * IT ALWAYS ANSWERS. A host waiting on a BLE notification has no other way out;
 * if this throws and nothing is sent, the browser hangs until its own timeout,
 * which is minutes. So every failure below becomes a CTAP2 error frame - the
 * bridge's own status byte is still a truthful answer, where silence is not.
 */
'use strict';

const { CtapHid } = require('./ctaphid');

/** Status codes this layer produces ITSELF, when the device produced none. */
const BRIDGE_STATUS = {
  /* The device never answered. CTAP1_ERR_TIMEOUT. */
  TIMEOUT: 0x05,
  /* Anything else went wrong on the way. CTAP1_ERR_OTHER. */
  OTHER: 0x7f,
  /* Nothing to forward - an empty write from the host. */
  INVALID_LENGTH: 0x03,
};

/**
 * @param {object} ctapOrTransport a CtapHid, or a transport to build one from
 * @param {object} [opts]
 * @param {function} [opts.onKeepAlive] called with the keepalive status byte
 *   while the device waits. A BLE host needs these RELAYED - the firmware sends
 *   one and then goes quiet for up to nineteen seconds waiting for a finger,
 *   and a browser hearing nothing for that long gives up on a ceremony the user
 *   is midway through confirming.
 * @param {function} [opts.log] (level, message)
 * @param {number} [opts.timeoutMs]
 * @param {number} [opts.presenceTimeoutMs]
 */
function createCtapBridge(ctapOrTransport, opts = {}) {
  const {
    onKeepAlive = null,
    log = () => {},
    timeoutMs = 10000,
    presenceTimeoutMs = 25000,
  } = opts;

  const ctap = ctapOrTransport instanceof CtapHid
    ? ctapOrTransport
    : new CtapHid(ctapOrTransport);

  let channel = null;

  /**
   * One channel for the life of the bridge.
   *
   * The firmware keeps ten (ctaphid.cpp:67) and never frees them, so opening a
   * fresh one per request exhausts them after ten and every request after that
   * is answered with an error that has nothing to do with what was asked.
   */
  async function ensureChannel() {
    if (channel) return channel;
    channel = await ctap.init({ timeoutMs });
    return channel;
  }

  /**
   * Carry one whole CTAP2 message to the device and bring its answer back.
   *
   * @param {Uint8Array} request CTAP2 command byte followed by CBOR
   * @param {object} [perCall] overrides for this request only. onKeepAlive
   *   belongs here rather than at construction for transports that address
   *   their host per request - CTAP-over-BLE relays a keepalive against the id
   *   of the request it belongs to, and the bridge cannot know that id when it
   *   is built.
   * @returns {Promise<Uint8Array>} status byte followed by CBOR - ALWAYS
   */
  async function handle(request, perCall = {}) {
    const keepAlive = perCall.onKeepAlive || onKeepAlive;
    if (!(request instanceof Uint8Array) || request.length === 0) {
      /*
       * Answered rather than thrown. An empty Control Point write is a host
       * bug, but a bridge that goes silent turns that into a hang on a device
       * whose logs the person debugging cannot see.
       */
      log('warn', 'empty CTAP2 request');
      return Uint8Array.of(BRIDGE_STATUS.INVALID_LENGTH);
    }

    const cmd = request[0];
    const params = request.subarray(1);

    try {
      await ensureChannel();
      const response = await ctap.sendRaw(cmd, params, {
        timeoutMs,
        presenceTimeoutMs,
        onKeepAlive: keepAlive
          ? async status => {
              log('info', `keepalive 0x${status.toString(16)} - relaying to the host`);
              await keepAlive(status);
            }
          : undefined,
      });

      log('info', `cmd 0x${cmd.toString(16)} -> status 0x${response[0].toString(16)}, ${response.length} bytes`);
      return response;
    } catch (error) {
      /*
       * The channel is suspect after a failure - a timeout usually means a
       * reply is still in flight, and it would be read as the answer to the
       * NEXT request. Dropping it costs one INIT and removes a whole class of
       * off-by-one-response bugs.
       */
      channel = null;

      /*
       * Matched against the messages the layers below actually produce:
       * "no CTAPHID reply within Nms" from the frame reader, and "no reply on
       * interface N within Nms" from the transport. Worth pinning, because a
       * regex that misses turns every timeout into CTAP1_ERR_OTHER and the
       * host loses the one distinction it can act on - retry, or give up.
       */
      const timedOut = /no CTAPHID reply|no reply|timed out|timeout/i.test(
        String(error && error.message),
      );
      const status = timedOut ? BRIDGE_STATUS.TIMEOUT : BRIDGE_STATUS.OTHER;
      log('error', `cmd 0x${cmd.toString(16)}: ${String(error && error.message)}`);
      return Uint8Array.of(status);
    }
  }

  return {
    handle,
    /** The CTAPHID channel in use, or null before the first request. */
    get channel() {
      return channel;
    },
    /** Forget the channel, so the next request opens a new one. */
    reset() {
      channel = null;
    },
  };
}

module.exports = { createCtapBridge, BRIDGE_STATUS };
