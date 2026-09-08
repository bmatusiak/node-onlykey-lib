/*
 * A fake CTAPHID authenticator, as a transport.
 *
 * Satisfies src/transport/contract.js well enough for CtapHid to drive it, and
 * reproduces the behaviours that make this protocol awkward:
 *
 *   It fragments. Anything over 57 bytes comes back as an init packet plus
 *   continuations, which is the path a real getAssertion always takes.
 *
 *   It can answer SYNCHRONOUSLY inside write(). That is the worst case for
 *   ordering and the reason CtapHid subscribes before writing: a client that
 *   listens afterwards has already missed the reply.
 *
 *   It can send KEEPALIVE before the real answer, which is what a device
 *   waiting for a finger does about ten times a second.
 */
'use strict';

const { EventEmitter } = require('events');
const {
  CTAPHID,
  BROADCAST_CID,
  TYPE_INIT,
  PACKET_SIZE,
  INIT_PAYLOAD,
  CONT_PAYLOAD,
  frame,
} = require('../../src/protocol/ctaphid');
const { IFACE } = require('../../src/protocol/msg');
const cbor = require('../../src/protocol/cbor');

/**
 * @param {object} [opts]
 *   cid          - the channel id to hand out at INIT
 *   onCbor       - (cmd, params) => value | {status}  the CBOR answer
 *   keepAlives   - how many KEEPALIVE(UP_NEEDED) to send before answering
 *   hidError     - send a CTAPHID ERROR with this code instead of answering
 *   deferReply   - answer on a later turn instead of inside write()
 */
function fakeCtapHid(opts = {}) {
  const {
    cid = Uint8Array.of(0xde, 0xad, 0xbe, 0xef),
    onCbor = null,
    keepAlives = 0,
    hidError = null,
    deferReply = false,
  } = opts;

  const events = new EventEmitter();
  const writes = [];
  let open = true;

  /* Reassembles what the client sends, so the fake sees whole messages. */
  let inbound = null;

  function emitPackets(packets) {
    for (const packet of packets) {
      events.emit('report', { iface: IFACE.FIDO, data: packet });
    }
  }

  function handleMessage(cmd, payload) {
    if (cmd === CTAPHID.INIT) {
      /*
       * The INIT reply comes back on the BROADCAST channel - the one the
       * request arrived on - and carries the newly assigned channel id in its
       * payload. Answering on the new channel instead would be invisible to a
       * client that is still listening on broadcast, which is where it was
       * told to listen.
       */
      const body = new Uint8Array(17);
      body.set(payload.subarray(0, 8), 0);   // the nonce, echoed
      body.set(cid, 8);                       // the channel being granted
      body[12] = 2;                           // CTAPHID protocol version
      emitPackets(frame(BROADCAST_CID, CTAPHID.INIT, body));
      return;
    }

    if (cmd === CTAPHID.CBOR) {
      if (hidError !== null) {
        emitPackets(frame(cid, CTAPHID.ERROR, Uint8Array.of(hidError)));
        return;
      }

      for (let i = 0; i < keepAlives; i++) {
        emitPackets(frame(cid, CTAPHID.KEEPALIVE, Uint8Array.of(0x02)));
      }

      const ctapCmd = payload[0];
      const params = payload.length > 1 ? cbor.decode(payload.subarray(1)) : undefined;
      const answer = onCbor ? onCbor(ctapCmd, params) : undefined;

      if (answer && typeof answer === 'object' && 'status' in answer) {
        emitPackets(frame(cid, CTAPHID.CBOR, Uint8Array.of(answer.status)));
        return;
      }

      const body = answer === undefined
        ? Uint8Array.of(0x00)
        : new Uint8Array([0x00, ...cbor.encode(answer)]);
      emitPackets(frame(cid, CTAPHID.CBOR, body));
    }
  }

  const transport = {
    name: 'fake-ctaphid',

    async open() { open = true; },
    async close() { open = false; },
    isOpen() { return open; },

    async write(iface, data) {
      const packet = Uint8Array.from(data);
      writes.push({ iface, data: packet });
      if (iface !== IFACE.FIDO) return packet.length;

      // Reassemble the client's message before answering it.
      if ((packet[4] & TYPE_INIT) !== 0) {
        const total = (packet[5] << 8) | packet[6];
        const n = Math.min(total, INIT_PAYLOAD);
        inbound = { cmd: packet[4] & 0x7f, total, chunks: [packet.subarray(7, 7 + n)], have: n };
      } else if (inbound) {
        const n = Math.min(inbound.total - inbound.have, CONT_PAYLOAD);
        inbound.chunks.push(packet.subarray(5, 5 + n));
        inbound.have += n;
      }

      if (inbound && inbound.have >= inbound.total) {
        const payload = new Uint8Array(inbound.total);
        let at = 0;
        for (const c of inbound.chunks) { payload.set(c, at); at += c.length; }
        const { cmd } = inbound;
        inbound = null;

        if (deferReply) {
          Promise.resolve().then(() => handleMessage(cmd, payload));
        } else {
          // Synchronously, inside write() - the worst case for ordering.
          handleMessage(cmd, payload);
        }
      }
      return packet.length;
    },

    async request({ iface, data }) {
      await transport.write(iface, data);
      throw new Error('fake-ctaphid has no request(); CtapHid uses on()+write()');
    },

    on(event, listener) {
      events.on(event, listener);
      return () => events.removeListener(event, listener);
    },

    writes,
    get packetCount() { return writes.length; },

    /** Push raw packets onto the bus, e.g. another client's traffic. */
    inject(packets) { emitPackets(packets); },
  };

  return transport;
}

module.exports = { fakeCtapHid, PACKET_SIZE };
