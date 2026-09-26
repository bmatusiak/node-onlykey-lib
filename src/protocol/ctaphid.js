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
const { STATUS } = require('./ctap');
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
  /*
   * Credential management, and the firmware answers on BOTH bytes.
   *
   * 0x0A is the standard opcode; 0x41 is the CTAP2.1-PRE preview one that
   * platforms shipped before the spec settled. ctap.cpp:2443 routes them to
   * the same handler, so either reaches it - the preview byte is kept because
   * a bridge forwarding a browser's request will see whichever that browser
   * chose, and a table missing one would reject a perfectly good request.
   */
  CREDENTIAL_MANAGEMENT: 0x0a,
  CREDENTIAL_MANAGEMENT_PREVIEW: 0x41,
};

/**
 * Status codes a RESPONDER sends, by name.
 *
 * CTAP2_ERROR below maps a byte to its spec name, which is what a client needs
 * when it RECEIVES one. Answering a request needs the other direction, and
 * having only the first is how ok-rn came to keep its own table.
 *
 * ## Both tables here were WRONG, and the comment that said so was too
 *
 * This pair used to be transcribed by hand, and the transcription had slid:
 * NO_CREDENTIALS was 0x2b (really UNSUPPORTED_OPTION), NOT_ALLOWED was 0x2d
 * (really KEEPALIVE_CANCEL), and UNSUPPORTED_OPTION was 0x6a, which the spec
 * does not define at all. An earlier comment right here claimed to have
 * corrected ok-rn's table, which had `NOT_ALLOWED: 0x30` - and 0x30 is the
 * RIGHT value (ctap_errors.h:42). The app's table was replaced with a wrong
 * one and a test pinned the wrong values in place.
 *
 * It surfaced on a real device: a wrong FIDO2 PIN answered
 * CTAP2_ERR_PIN_NOT_SET on a key that plainly had a PIN set, because 0x31 was
 * labelled PIN_NOT_SET when it is PIN_INVALID. See
 * FINDING-ctap2-status-table-was-shifted.md.
 *
 * ## So there is now ONE table
 *
 * CTAP2_ERROR is built from ctap.js's STATUS, which was transcribed
 * separately, from the shipped web client, and is correct. Two hand-written
 * copies of one table is the bug; deriving one from the other is the fix.
 * CTAP2_STATUS names a subset of it for the responder direction, and a test
 * checks every value against ctap_errors.h's numbers.
 */
const CTAP2_STATUS = {
  OK: 0x00,
  INVALID_COMMAND: 0x01,
  INVALID_PARAMETER: 0x02,
  INVALID_LENGTH: 0x03,
  MISSING_PARAMETER: 0x14,
  INVALID_CREDENTIAL: 0x22,
  USER_ACTION_PENDING: 0x23,
  OPERATION_DENIED: 0x27,
  NO_CREDENTIALS: 0x2e,
  NOT_ALLOWED: 0x30,
  UNSUPPORTED_OPTION: 0x2b,
};

/**
 * Byte to spec name, for a status a device SENT us.
 *
 * Derived, not retyped: see the note above CTAP2_STATUS. 0x00 keeps the
 * CTAP2 spelling here because this table describes CTAP2 command replies,
 * while ctap.js reads byte 0 of a tunnelled U2F signature, where the same
 * zero means CTAP1_SUCCESS.
 */
const CTAP2_ERROR = { ...STATUS, 0x00: 'CTAP2_OK' };

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
 * A channel id as four bytes, from either four bytes or a number.
 *
 * This file is bytes-oriented, but a channel id reads naturally as a number -
 * BROADCAST is "0xffffffff", and that is how it appears in a log line. Both
 * spellings arrive here, so both are accepted and one is stored.
 */
function cidBytes(cid) {
  if (cid instanceof Uint8Array) return cid.subarray(0, 4);
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, cid >>> 0, false);
  return out;
}

/** The same id as a number, for logs and for comparing against BROADCAST. */
function cidNumber(cid) {
  if (typeof cid === 'number') return cid >>> 0;
  return view(cid).getUint32(0, false);
}

/**
 * Split a message into packets of `packetSize` bytes.
 *
 * Pure, so it can be tested against the reference without a device.
 *
 * `packetSize` is a parameter rather than the constant because a USB endpoint
 * reports its own packet size on connect, and the descriptor is what decides
 * how much fits in a report - not our assumption about it.
 */
function frame(cid, cmd, payload, packetSize = PACKET_SIZE) {
  const initPayload = packetSize - 7;
  const contPayload = packetSize - 5;
  const id = cidBytes(cid);

  /*
   * The length field is two bytes. Anything longer cannot be described, and a
   * caller finding out by receiving a truncated message at the other end is
   * worse than finding out here.
   */
  if (payload.length > 0xffff) {
    throw new Error(`frame: payload ${payload.length} exceeds 65535 bytes`);
  }

  const packets = [];

  const init = new Uint8Array(packetSize);
  init.set(id, 0);
  init[4] = cmd | TYPE_INIT;
  view(init).setUint16(5, payload.length, false);
  init.set(payload.subarray(0, Math.min(payload.length, initPayload)), 7);
  packets.push(init);

  let offset = initPayload;
  let seq = 0;
  while (offset < payload.length) {
    // The sequence byte's high bit marks an INIT packet, so it counts to 0x7f.
    if (seq > 0x7f) {
      throw new Error('frame: sequence overflow (payload too large)');
    }
    const cont = new Uint8Array(packetSize);
    cont.set(id, 0);
    cont[4] = seq++; // sequence, high bit clear
    cont.set(payload.subarray(offset, offset + contPayload), 5);
    packets.push(cont);
    offset += contPayload;
  }

  return packets;
}

/**
 * Reassembles inbound packets into whole messages.
 *
 * Stateful on purpose: a continuation packet is meaningless without the
 * initialization packet before it, so the buffer has to outlive one callback.
 *
 * ## On an unexpected continuation, the packet is dropped and the message kept
 *
 * ok-rn carried a second copy of this that ABANDONED the whole message when a
 * continuation arrived with the wrong sequence or the wrong channel, on the
 * reasoning that splicing corrupt bytes together is worse. The two copies are
 * now one, and this is the behaviour that survived, for three reasons:
 *
 *   - Neither version splices the bad packet, so the choice is only about the
 *     good bytes already collected. Throwing those away because something
 *     unrelated arrived turns one stray packet into a lost message.
 *   - A stray packet on this bus is usually a LEFTOVER from the previous
 *     exchange, not corruption of this one - the emulator's report queue can
 *     deliver one after the next message has started.
 *   - When a message really is lost, waiting produces a timeout that names how
 *     many of how many bytes arrived. Abandoning produces silence.
 *
 * A fresh initialization packet always resets, so both recover at the same
 * point either way: the next message.
 *
 * The spec's own rule for the case with no state at all - CTAP §11.2.4,
 * "spurious continuation packets will be ignored" - is what both copies already
 * did, and still do.
 */
class Assembler {
  constructor({ packetSize = PACKET_SIZE } = {}) {
    this.packetSize = packetSize;
    this.initPayload = packetSize - 7;
    this.contPayload = packetSize - 5;
    this.reset();
  }

  reset() {
    this.cid = null;
    this.cmd = null;
    this.total = null;
    this.chunks = [];
    this.have = 0;
    this.seq = 0;
  }

  /** How much of a message is outstanding, for a timeout message to quote. */
  get progress() {
    return this.total === null ? null : { have: this.have, total: this.total };
  }

  /**
   * @param {Uint8Array} packet
   * @returns {{cid: Uint8Array, cmd: number, payload: Uint8Array}|null}
   */
  push(packet) {
    if (packet.length < 5) return null;

    if (this.total === null) {
      // Only an init packet starts a message; reading a continuation's
      // sequence byte as a command would invent one.
      if ((packet[4] & TYPE_INIT) === 0) return null;
      this.cid = packet.slice(0, 4);
      this.cmd = packet[4] & 0x7f;
      this.total = view(packet).getUint16(5, false);
      const n = Math.min(this.total, this.initPayload);
      this.chunks = [packet.subarray(7, 7 + n)];
      this.have = n;
      this.seq = 0;
    } else if ((packet[4] & TYPE_INIT) !== 0) {
      // A new message starting on top of an unfinished one. The old one is
      // never coming; take the new one rather than dropping both.
      this.reset();
      return this.push(packet);
    } else {
      if (!sameCid(packet, this.cid) || packet[4] !== this.seq) return null;
      const n = Math.min(this.total - this.have, this.contPayload);
      this.chunks.push(packet.subarray(5, 5 + n));
      this.have += n;
      this.seq++;
    }

    if (this.have >= this.total) {
      const message = { cid: this.cid, cmd: this.cmd, payload: concat(this.chunks) };
      this.reset();
      return message;
    }
    return null;
  }
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

    const assembler = new Assembler();

    const off = this.transport.on('report', (event) => {
      if (event.iface !== this.iface) return;
      const packet = event.data;
      // The reader is bound to ONE channel, so another channel's traffic is
      // filtered before the assembler ever sees it.
      if (packet.length < 5 || !sameCid(packet, cid)) return;

      const message = assembler.push(packet);
      if (!message) return;
      if (waiting.length) waiting.shift().resolve(message);
      else ready.push(message);
    });

    const reader = {
      /** @param {number} [waitMs] override for this read only. */
      next(waitMs) {
        if (ready.length) return Promise.resolve(ready.shift());
        const limit = waitMs === undefined ? timeoutMs : waitMs;

        return new Promise((resolve, reject) => {
          const timer = setTimeout(() => {
            const at = waiting.findIndex((w) => w.timer === timer);
            if (at !== -1) waiting.splice(at, 1);
            const at2 = assembler.progress;
            reject(new Error(
              `no CTAPHID reply within ${limit}ms` +
              (at2 === null ? '' : ` (had ${at2.have} of ${at2.total} bytes)`),
            ));
          }, limit);

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
    let payload = await this.sendRaw(cmd, data, opts);

    /*
     * ONE RESEND, on CTAP1_ERR_INVALID_COMMAND, for a request that spans more
     * than one packet.
     *
     * The firmware's 5-second wipe timer zeroes ctap_buffer, and until
     * libraries fix/ctaphid-wipe-mid-message it did so even while a
     * multi-packet message was still arriving. The continuation was then
     * appended after zeros, the command byte read as 0, and the request was
     * refused as INVALID_COMMAND - BEFORE anything in it was looked at, so no
     * PIN attempt or other state was spent (measured: retries unchanged, and
     * the same request sent again succeeds). Every key already in use keeps
     * that firmware, so the host recovers: the one case it applies to is the
     * one the firmware cut, and a single-packet request - which the timer
     * cannot cut - is never resent. It was ok-rn's intermittent fidoPin
     * failure (getPinToken, two packets).
     */
    if (payload[0] === CTAP2_STATUS.INVALID_COMMAND && 1 + data.length > INIT_PAYLOAD) {
      payload = await this.sendRaw(cmd, data, opts);
    }

    /* First byte is the status, the rest is CBOR - or nothing. */
    const status = payload[0];
    if (status !== 0x00) throw new Ctap2Error(status);
    return payload.length > 1 ? cbor.decode(payload.subarray(1)) : undefined;
  }

  /**
   * The same exchange, handed back UNDECODED: the status byte followed by
   * whatever CBOR came with it.
   *
   * This exists for BRIDGING. A bridge carries bytes between a host and an
   * authenticator and must not develop opinions about them - it has to forward
   * the device's own error rather than throw its own, because the host is the
   * thing entitled to interpret CTAP2 status codes. send() throwing on a
   * non-zero status is right for a caller acting on the result and wrong for
   * one relaying it: a browser told "the request failed" learns nothing, where
   * CTAP2_ERR_NO_CREDENTIALS tells it to try another authenticator.
   *
   * Decoding and re-encoding the CBOR would be worse still. A round trip is
   * not guaranteed to be byte-identical, and the response is SIGNED - authData
   * and the attestation cover exact bytes, so a re-encoded map that differs by
   * one integer width verifies as a forgery at the relying party.
   *
   * @returns {Promise<Uint8Array>} status byte followed by the CBOR body
   */
  async sendRaw(cmd, data = new Uint8Array(0), opts = {}) {
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

  /**
   * Read until something that is not a keepalive.
   *
   * The wait AFTER a keepalive is much longer than the ordinary one, and that
   * is not a safety margin - it is what the firmware does.
   * device.cpp:172 sends KEEPALIVE only when the status CHANGES:
   *
   *     if (status != CTAPHID_STATUS_IDLE && __device_status != status)
   *         ctaphid_update_status(status);
   *
   * so a user-presence wait produces exactly ONE keepalive and then silence
   * for up to CTAP2_UP_DELAY_MS - 19 seconds (ctap.h:173) - while the device
   * waits for a finger. The spec suggests a ~100ms cadence and this firmware
   * does not follow it, so a client using its ordinary timeout gives up at ten
   * seconds on a ceremony the user is halfway through confirming.
   */
  async _await(reader, opts) {
    const presenceTimeoutMs = opts.presenceTimeoutMs === undefined
      ? 30000
      : opts.presenceTimeoutMs;
    let waiting = undefined;

    for (;;) {
      const { cmd: replyCmd, payload } = await reader.next(waiting);

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
        waiting = presenceTimeoutMs;
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

      /*
       * Returned whole - status byte and all - and decoded a layer up. A
       * bridge needs these bytes exactly as they arrived; see sendRaw().
       */
      return payload;
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
  Assembler,
  cidBytes,
  cidNumber,
  Ctap2Error,
  frame,
  CTAPHID,
  CTAP2_CMD,
  CTAP2_STATUS,
  CTAP2_ERROR,
  KEEPALIVE,
  BROADCAST_CID,
  TYPE_INIT,
  PACKET_SIZE,
  INIT_PAYLOAD,
  CONT_PAYLOAD,
};
