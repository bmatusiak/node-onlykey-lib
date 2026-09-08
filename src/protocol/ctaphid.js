/*
 * ctaphid.js - the FIDO2 client protocol, over this library's transport.
 *
 * WHY THIS EXISTS. The vendor interface cannot reach three things the app
 * needs: the transit key exchange, the X-Wing derives, and the composite
 * sign/decrypt halves. All three are read by bridge_to_onlykey() in
 * libraries/fido2/ok_extension.cpp, which is the CTAP path - okcore.cpp's
 * vendor dispatch has an OKCONNECT case of its own that only calls set_time().
 * See FINDING-okconnect-is-two-protocols.md.
 *
 * PORTED, AND WHERE IT DIVERGES. The framing, constants and KEEPALIVE loop come
 * from onlykey-testing/lib/device/ctap2.js, itself ported from
 * @vincss-public-projects/fido2-client (MIT) and proven against a physical key.
 * Buffer became Uint8Array throughout.
 *
 * The receive loop is deliberately NOT a port, and getting it right took two
 * attempts. The original is built on a Device that buffers reports and hands
 * out cursors, and its own comment records the bug that model creates: taking a
 * fresh cursor after the init packet arrives excludes the continuation packets,
 * because on an in-process bus they have ALREADY arrived - measured there as a
 * 10-second timeout on a GET_INFO the firmware had answered in three blocks.
 *
 * Subscribing per MESSAGE looks like the event-driven answer to that and is
 * not: a KEEPALIVE burst puts several complete messages on the wire at once and
 * the answer follows immediately, so re-subscribing after each keepalive means
 * the answer goes past with nobody listening. That reproduces the original's
 * bug through a different mechanism, and the KEEPALIVE tests caught it.
 *
 * So the subscription is per EXCHANGE and completed messages are QUEUED until
 * asked for. Nothing that arrives between the write and the read can be lost,
 * which is the same guarantee request() gives on the vendor interface.
 *
 * Three things about the wire are worth knowing:
 *
 *   Fragmentation. A message is an init packet (channel, command, 16-bit total
 *   length, then 57 bytes) followed by continuation packets (channel, sequence
 *   0..127, then 59 bytes).
 *
 *   KEEPALIVE is not noise, it is the user-presence prompt. While the
 *   authenticator waits for a button press it sends KEEPALIVE(0x02) roughly ten
 *   times a second. A client that treats those as errors cannot complete a
 *   ceremony at all.
 *
 *   The first byte of a CBOR response is the CTAP status, not CBOR. Zero is
 *   success; everything else is an error code. The payload has to be split
 *   before it is decoded.
 */
'use strict';

const cbor = require('./cbor');
const { IFACE } = require('./msg');
const { concat } = require('../bytes');

const CTAPHID = {
  PING: 0x01,
  MSG: 0x03,
  LOCK: 0x04,
  INIT: 0x06,
  WINK: 0x08,
  CBOR: 0x10,
  CANCEL: 0x11,
  KEEPALIVE: 0x3b,
  ERROR: 0x3f,
};

const TYPE_INIT = 0x80;

const BROADCAST_CID = Uint8Array.of(0xff, 0xff, 0xff, 0xff);
const PACKET_SIZE = 64;
const INIT_PAYLOAD = PACKET_SIZE - 7; // cid(4) + cmd(1) + bcnt(2)
const CONT_PAYLOAD = PACKET_SIZE - 5; // cid(4) + seq(1)

const CTAP2_CMD = {
  MAKE_CREDENTIAL: 0x01,
  GET_ASSERTION: 0x02,
  GET_INFO: 0x04,
  CLIENT_PIN: 0x06,
  RESET: 0x07,
  GET_NEXT_ASSERTION: 0x08,
};

const CTAP2_ERROR = {
  0x00: 'CTAP2_OK',
  0x01: 'CTAP1_ERR_INVALID_COMMAND',
  0x02: 'CTAP1_ERR_INVALID_PARAMETER',
  0x03: 'CTAP1_ERR_INVALID_LENGTH',
  0x11: 'CTAP2_ERR_CBOR_UNEXPECTED_TYPE',
  0x12: 'CTAP2_ERR_INVALID_CBOR',
  0x14: 'CTAP2_ERR_MISSING_PARAMETER',
  0x15: 'CTAP2_ERR_LIMIT_EXCEEDED',
  0x19: 'CTAP2_ERR_CREDENTIAL_EXCLUDED',
  0x21: 'CTAP2_ERR_PROCESSING',
  0x22: 'CTAP2_ERR_INVALID_CREDENTIAL',
  0x23: 'CTAP2_ERR_USER_ACTION_PENDING',
  0x24: 'CTAP2_ERR_OPERATION_PENDING',
  0x25: 'CTAP2_ERR_NO_OPERATIONS',
  0x26: 'CTAP2_ERR_UNSUPPORTED_ALGORITHM',
  0x27: 'CTAP2_ERR_OPERATION_DENIED',
  0x2b: 'CTAP2_ERR_NO_CREDENTIALS',
  0x2d: 'CTAP2_ERR_NOT_ALLOWED',
  0x2e: 'CTAP2_ERR_PIN_INVALID',
  0x31: 'CTAP2_ERR_PIN_NOT_SET',
  0x36: 'CTAP2_ERR_PIN_AUTH_INVALID',
  0x6a: 'CTAP2_ERR_UNSUPPORTED_OPTION',
};

const KEEPALIVE = { PROCESSING: 0x01, UP_NEEDED: 0x02 };

class Ctap2Error extends Error {
  constructor(code) {
    const name = CTAP2_ERROR[code] || `0x${code.toString(16)}`;
    super(`CTAP2 error ${name}`);
    this.name = 'Ctap2Error';
    this.code = code;
    this.ctapName = name;
  }
}

/** A DataView honouring the array's own offset - see cbor.js for why. */
function view(bytes) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function sameCid(packet, cid) {
  return (
    packet[0] === cid[0] && packet[1] === cid[1] &&
    packet[2] === cid[2] && packet[3] === cid[3]
  );
}

/**
 * Split a message into 64-byte CTAPHID packets.
 *
 * Pure, so it can be tested against the reference without a device.
 */
function frame(cid, cmd, payload) {
  const packets = [];

  const init = new Uint8Array(PACKET_SIZE);
  init.set(cid.subarray(0, 4), 0);
  init[4] = cmd | TYPE_INIT;
  view(init).setUint16(5, payload.length, false);
  init.set(payload.subarray(0, Math.min(payload.length, INIT_PAYLOAD)), 7);
  packets.push(init);

  let offset = INIT_PAYLOAD;
  let seq = 0;
  while (offset < payload.length) {
    const cont = new Uint8Array(PACKET_SIZE);
    cont.set(cid.subarray(0, 4), 0);
    cont[4] = seq++; // sequence, high bit clear
    cont.set(payload.subarray(offset, offset + CONT_PAYLOAD), 5);
    packets.push(cont);
    offset += CONT_PAYLOAD;
  }

  return packets;
}

/**
 * The client protocol, bound to a transport.
 *
 * Takes anything satisfying src/transport/contract.js, so the same ceremony
 * runs over the embedded emulator, a USB key, or a socket.
 */
class CtapHid {
  /**
   * @param {object} transport  must provide on() and write()
   * @param {object} [opts] {iface}
   */
  constructor(transport, { iface = IFACE.FIDO } = {}) {
    this.transport = transport;
    this.iface = iface;
    this.cid = null;
    /** Every KEEPALIVE status seen, so a caller can tell a press was demanded. */
    this.keepAlives = [];
  }

  /**
   * Open a reader over one channel's traffic.
   *
   * ONE subscription for a whole exchange, with a QUEUE - not a fresh
   * subscription per message. That distinction is the entire difficulty of this
   * protocol on an in-process bus.
   *
   * A KEEPALIVE burst puts several complete messages on the wire at once, and
   * the firmware answers immediately after them. Subscribing again after
   * handling a keepalive means the answer has already gone past with nobody
   * listening, and the exchange waits out its timeout against a device that
   * replied correctly. onlykey-testing hit the same wall from the other
   * direction and solved it with a cursor over buffered reports; here the
   * subscription simply stays up and completed messages are queued until asked
   * for.
   *
   * @returns {{next: function, close: function}}
   */
  _open(cid, { timeoutMs = 10000 } = {}) {
    const ready = [];      // complete messages nobody has asked for yet
    const waiting = [];    // askers with nothing to give them yet

    let chunks = [];
    let cmd = null;
    let total = null;
    let have = 0;
    let seq = 0;

    const off = this.transport.on('report', (event) => {
      if (event.iface !== this.iface) return;
      const packet = event.data;
      if (packet.length < 5 || !sameCid(packet, cid)) return;

      if (total === null) {
        // Only an init packet starts a message; a stray continuation is not
        // ours to reassemble, and reading its sequence byte as a command would
        // invent one.
        if ((packet[4] & TYPE_INIT) === 0) return;
        cmd = packet[4] & 0x7f;
        total = view(packet).getUint16(5, false);
        const n = Math.min(total, INIT_PAYLOAD);
        chunks = [packet.subarray(7, 7 + n)];
        have = n;
        seq = 0;
      } else {
        if (packet[4] !== seq) return;
        const n = Math.min(total - have, CONT_PAYLOAD);
        chunks.push(packet.subarray(5, 5 + n));
        have += n;
        seq++;
      }

      if (have >= total) {
        const message = { cmd, payload: concat(chunks) };
        total = null;
        chunks = [];
        if (waiting.length) waiting.shift().resolve(message);
        else ready.push(message);
      }
    });

    const reader = {
      next() {
        if (ready.length) return Promise.resolve(ready.shift());

        return new Promise((resolve, reject) => {
          const timer = setTimeout(() => {
            const at = waiting.findIndex((w) => w.timer === timer);
            if (at !== -1) waiting.splice(at, 1);
            reject(new Error(
              `no CTAPHID reply within ${timeoutMs}ms` +
              (total === null ? '' : ` (had ${have} of ${total} bytes)`),
            ));
          }, timeoutMs);

          waiting.push({
            timer,
            resolve: (message) => { clearTimeout(timer); resolve(message); },
            reject,
          });
        });
      },
      close() {
        off();
        for (const w of waiting.splice(0)) clearTimeout(w.timer);
      },
    };
    return reader;
  }

  /** Write a framed message. The reader must already be open. */
  async _write(cid, cmd, payload) {
    for (const packet of frame(cid, cmd, payload)) {
      await this.transport.write(this.iface, packet);
    }
  }

  /**
   * Allocate a channel. Must happen before anything else.
   *
   * The nonce is echoed back, which is how a reply is recognised as ours on a
   * bus that other clients may share.
   */
  async init(opts = {}) {
    const nonce = Uint8Array.of(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88);

    const reader = this._open(BROADCAST_CID, { timeoutMs: 5000, ...opts });
    try {
      await this._write(BROADCAST_CID, CTAPHID.INIT, nonce);

      for (;;) {
        const { cmd, payload } = await reader.next();
        if (cmd !== CTAPHID.INIT) continue;

        // The echoed nonce identifies the reply as ours on a shared bus.
        let matches = payload.length >= 8;
        for (let i = 0; matches && i < 8; i++) matches = payload[i] === nonce[i];
        if (!matches) continue;

        this.cid = Uint8Array.from(payload.subarray(8, 12));
        return this.cid;
      }
    } finally {
      reader.close();
    }
  }

  /**
   * One CBOR command, with the KEEPALIVE loop.
   *
   * @param {number} cmd CTAP2_CMD.*
   * @param {Uint8Array} [data] already-encoded CBOR parameters
   * @param {object} [opts] {timeoutMs, onKeepAlive}
   * @returns {Promise<*>} the decoded response, or undefined for an empty one
   */
  async send(cmd, data = new Uint8Array(0), opts = {}) {
    if (!this.cid) throw new Error('no CTAPHID channel - call init() first');

    const request = concat([Uint8Array.of(cmd), data]);
    const reader = this._open(this.cid, opts);

    try {
      await this._write(this.cid, CTAPHID.CBOR, request);
      return await this._await(reader, opts);
    } finally {
      reader.close();
    }
  }

  /** Read until something that is not a keepalive. */
  async _await(reader, opts) {
    for (;;) {
      const { cmd: replyCmd, payload } = await reader.next();

      if (replyCmd === CTAPHID.KEEPALIVE) {
        /*
         * The device is saying it is alive and, when the status is UP_NEEDED,
         * that it is waiting for a finger. Recorded so a caller can tell user
         * presence was demanded, and handed over so a UI can prompt.
         *
         * Waiting again rather than re-sending: the command is already with the
         * device, and sending it twice would start a second ceremony.
         */
        const status = payload[0];
        this.keepAlives.push(status);
        if (opts.onKeepAlive) await opts.onKeepAlive(status);
        continue;
      }

      if (replyCmd === CTAPHID.ERROR) {
        throw new Error(`CTAPHID error 0x${(payload[0] || 0).toString(16)}`);
      }

      if (replyCmd !== CTAPHID.CBOR) {
        throw new Error(
          `unexpected CTAPHID command 0x${replyCmd.toString(16)} in a CBOR exchange`,
        );
      }

      /* First byte is the status, the rest is CBOR - or nothing. */
      const status = payload[0];
      if (status !== 0x00) throw new Ctap2Error(status);
      return payload.length > 1 ? cbor.decode(payload.subarray(1)) : undefined;
    }
  }

  getInfo(opts = {}) {
    return this.send(CTAP2_CMD.GET_INFO, new Uint8Array(0), opts);
  }

  makeCredential(params, opts = {}) {
    return this.send(CTAP2_CMD.MAKE_CREDENTIAL, cbor.encode(params), opts);
  }

  getAssertion(params, opts = {}) {
    return this.send(CTAP2_CMD.GET_ASSERTION, cbor.encode(params), opts);
  }

  /** Did the device ask for a finger during the last exchange? */
  get askedForUserPresence() {
    return this.keepAlives.includes(KEEPALIVE.UP_NEEDED);
  }
}

module.exports = {
  CtapHid,
  Ctap2Error,
  frame,
  CTAPHID,
  CTAP2_CMD,
  CTAP2_ERROR,
  KEEPALIVE,
  BROADCAST_CID,
  TYPE_INIT,
  PACKET_SIZE,
  INIT_PAYLOAD,
  CONT_PAYLOAD,
};
