/*
 * CTAPHID - the framing, and the loop that drives a ceremony.
 *
 * The framing is cross-checked against onlykey-testing's, which has run against
 * a physical key. The receive loop is NOT a port and so gets tested on its own
 * terms: that one is built on a cursor over buffered reports, and its own
 * comment records the bug that model creates. This one subscribes before
 * writing, which is the same rule request() follows on the vendor interface.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const {
  CtapHid, Ctap2Error, frame, Assembler, cidBytes, cidNumber,
  CTAPHID, CTAP2_CMD, CTAP2_STATUS, CTAP2_ERROR, KEEPALIVE, BROADCAST_CID,
  PACKET_SIZE, INIT_PAYLOAD, CONT_PAYLOAD,
} = require('../src/protocol/ctaphid');
const { fakeCtapHid } = require('./helpers/fake-ctaphid');
const cbor = require('../src/protocol/cbor');
const { toHex } = require('../src/bytes');

let reference = null;
try {
  reference = require(
    path.resolve(__dirname, '..', '..', 'onlykey-testing', 'lib', 'device', 'ctap2.js'),
  );
} catch { /* cross-checks skip themselves */ }

/* ------------------------------------------------------------- framing */

test('a short message is one init packet', () => {
  const packets = frame(BROADCAST_CID, CTAPHID.INIT, Uint8Array.of(1, 2, 3));
  assert.equal(packets.length, 1);
  assert.equal(packets[0].length, PACKET_SIZE);
  assert.equal(packets[0][4], CTAPHID.INIT | 0x80, 'the init bit is set on the command');
  assert.equal((packets[0][5] << 8) | packets[0][6], 3, 'the 16-bit length is big-endian');
});

test('a long message fragments into init plus continuations', () => {
  // 57 bytes in the init packet, 59 in each continuation.
  const payload = new Uint8Array(200);
  for (let i = 0; i < payload.length; i++) payload[i] = i & 0xff;

  const packets = frame(BROADCAST_CID, CTAPHID.CBOR, payload);
  assert.equal(packets.length, 1 + Math.ceil((200 - INIT_PAYLOAD) / CONT_PAYLOAD));
  assert.equal(packets[1][4], 0, 'continuations are numbered from zero');
  assert.equal(packets[2][4], 1);
  assert.equal(packets[1][4] & 0x80, 0, 'and the init bit stays CLEAR on them');
});

test('framing matches onlykey-testing byte for byte', { skip: !reference }, () => {
  // The port is mechanical, so the original is the strongest oracle available.
  for (const len of [0, 1, 57, 58, 116, 200, 1024]) {
    const payload = new Uint8Array(len);
    for (let i = 0; i < len; i++) payload[i] = (i * 7) & 0xff;

    const mine = frame(BROADCAST_CID, CTAPHID.CBOR, payload);
    const theirs = reference.frame(
      Buffer.from(BROADCAST_CID), CTAPHID.CBOR, Buffer.from(payload),
    );

    assert.equal(mine.length, theirs.length, `packet count differs at ${len} bytes`);
    for (let i = 0; i < mine.length; i++) {
      assert.equal(toHex(mine[i]), theirs[i].toString('hex'), `packet ${i} differs at ${len} bytes`);
    }
  }
});

/* ---------------------------------------------------------------- init */

test('init allocates a channel from the broadcast one', async () => {
  const transport = fakeCtapHid({ cid: Uint8Array.of(0x01, 0x02, 0x03, 0x04) });
  const ctap = new CtapHid(transport);

  const cid = await ctap.init();

  assert.equal(toHex(cid), '01020304');
  assert.equal(toHex(transport.writes[0].data.subarray(0, 4)), 'ffffffff', 'asked on broadcast');
});

test('a CBOR command before init is refused', async () => {
  const ctap = new CtapHid(fakeCtapHid());
  await assert.rejects(() => ctap.getInfo(), /call init\(\) first/);
});

/* ------------------------------------------------------------- exchange */

test('a reply arriving synchronously inside write() is not missed', async () => {
  /*
   * The whole reason the subscription goes up before the write. This fake
   * answers from inside write(), so a client that listened afterwards would
   * have nothing to hear.
   */
  const transport = fakeCtapHid({ onCbor: () => new Map([[1, 'ok']]) });
  const ctap = new CtapHid(transport);
  await ctap.init();

  const info = await ctap.send(CTAP2_CMD.GET_INFO);
  assert.equal(info.get(1), 'ok');
});

test('a reply arriving on a later turn is also fine', async () => {
  const transport = fakeCtapHid({ deferReply: true, onCbor: () => new Map([[1, 'later']]) });
  const ctap = new CtapHid(transport);
  await ctap.init();

  assert.equal((await ctap.getInfo()).get(1), 'later');
});

test('a fragmented RESPONSE is reassembled', async () => {
  /*
   * A getAssertion carrying authData and a signature does not fit in 57 bytes,
   * so this is the ordinary path rather than an edge case. The reassembly must
   * collect continuations that have ALREADY arrived - on an in-process bus they
   * all land before the client looks.
   */
  const big = new Uint8Array(600);
  for (let i = 0; i < big.length; i++) big[i] = i & 0xff;

  const transport = fakeCtapHid({ onCbor: () => new Map([[2, big]]) });
  const ctap = new CtapHid(transport);
  await ctap.init();

  const out = await ctap.send(CTAP2_CMD.GET_ASSERTION, cbor.encode(new Map([[1, 'x']])));
  assert.equal(toHex(out.get(2)), toHex(big), 'every continuation was collected in order');
});

test('a fragmented REQUEST goes out as ordered packets', async () => {
  const transport = fakeCtapHid({ onCbor: () => undefined });
  const ctap = new CtapHid(transport);
  await ctap.init();
  const before = transport.writes.length;

  await ctap.send(CTAP2_CMD.MAKE_CREDENTIAL, cbor.encode(new Uint8Array(300)));

  const sent = transport.writes.slice(before);
  assert.ok(sent.length > 1, 'it fragmented');
  assert.equal(sent[0].data[4] & 0x80, 0x80, 'first packet is an init');
  for (let i = 1; i < sent.length; i++) {
    assert.equal(sent[i].data[4], i - 1, 'continuations are sequential');
  }
});

/* ------------------------------------------------------------ KEEPALIVE */

test('KEEPALIVE keeps waiting instead of failing', async () => {
  /*
   * KEEPALIVE is the user-presence prompt, not an error. A client that treats
   * it as one cannot complete any ceremony that needs a button press - which is
   * every signing operation on this device.
   */
  const transport = fakeCtapHid({ keepAlives: 3, onCbor: () => new Map([[1, 'pressed']]) });
  const ctap = new CtapHid(transport);
  await ctap.init();

  const out = await ctap.send(CTAP2_CMD.GET_ASSERTION, new Uint8Array(0));

  assert.equal(out.get(1), 'pressed');
  assert.equal(ctap.keepAlives.length, 3);
  assert.equal(ctap.askedForUserPresence, true, 'a finger was demanded');
});

test('KEEPALIVE does not resend the command', async () => {
  /*
   * Waiting again is not the same as asking again. Re-sending would start a
   * SECOND ceremony on a device already waiting for a press on the first.
   */
  const transport = fakeCtapHid({ keepAlives: 2, onCbor: () => undefined });
  const ctap = new CtapHid(transport);
  await ctap.init();
  const before = transport.writes.length;

  await ctap.send(CTAP2_CMD.GET_ASSERTION, new Uint8Array(0));

  assert.equal(transport.writes.length - before, 1, 'exactly one packet went out');
});

test('a keepalive handler is told the status, so a UI can prompt', async () => {
  const seen = [];
  const transport = fakeCtapHid({ keepAlives: 2, onCbor: () => undefined });
  const ctap = new CtapHid(transport);
  await ctap.init();

  await ctap.send(CTAP2_CMD.GET_ASSERTION, new Uint8Array(0), {
    onKeepAlive: status => seen.push(status),
  });

  assert.deepEqual(seen, [KEEPALIVE.UP_NEEDED, KEEPALIVE.UP_NEEDED]);
});

/* ---------------------------------------------------------------- errors */

test('a non-zero CTAP status becomes a named error', async () => {
  // The name matters: "CTAP2_ERR_NO_CREDENTIALS" says the keyhandle was not
  // recognised, which is a completely different problem from a refusal.
  const transport = fakeCtapHid({ onCbor: () => ({ status: 0x2b }) });
  const ctap = new CtapHid(transport);
  await ctap.init();

  const err = await ctap.send(CTAP2_CMD.GET_ASSERTION).catch(e => e);
  assert.equal(err instanceof Ctap2Error, true);
  assert.equal(err.code, 0x2b);
  assert.equal(err.ctapName, 'CTAP2_ERR_NO_CREDENTIALS');
});

test('an unknown status still reports its code rather than nothing', async () => {
  const transport = fakeCtapHid({ onCbor: () => ({ status: 0x99 }) });
  const ctap = new CtapHid(transport);
  await ctap.init();

  const err = await ctap.send(CTAP2_CMD.GET_INFO).catch(e => e);
  assert.match(err.message, /0x99/);
});

test('a CTAPHID-level error is distinguished from a CTAP2 one', async () => {
  // Different layer, different meaning: this is the transport refusing, not
  // the authenticator.
  const transport = fakeCtapHid({ hidError: 0x01 });
  const ctap = new CtapHid(transport);
  await ctap.init();

  await assert.rejects(() => ctap.getInfo(), /CTAPHID error 0x1/);
});

test('a silent device times out saying how much it had', async () => {
  const transport = fakeCtapHid({ onCbor: () => undefined });
  const ctap = new CtapHid(transport);
  await ctap.init();

  // Swallow the write so nothing is ever answered.
  transport.write = async () => 64;

  await assert.rejects(
    () => ctap.send(CTAP2_CMD.GET_INFO, new Uint8Array(0), { timeoutMs: 40 }),
    /no CTAPHID reply within 40ms/,
  );
});

/* ------------------------------------------------------------- isolation */

test('traffic for another channel is ignored', async () => {
  /*
   * A shared bus carries other clients' packets. Reassembling one of those into
   * our message would produce a reply that decodes as garbage rather than
   * anything that errors.
   */
  const transport = fakeCtapHid({ cid: Uint8Array.of(0xaa, 0xbb, 0xcc, 0xdd) });
  const ctap = new CtapHid(transport);
  await ctap.init();

  const reader = ctap._open(ctap.cid, { timeoutMs: 60 });

  // A complete, well-formed message - for somebody else's channel.
  transport.inject(
    frame(Uint8Array.of(0x11, 0x22, 0x33, 0x44), CTAPHID.CBOR, Uint8Array.of(0x00)),
  );

  await assert.rejects(() => reader.next(), /no CTAPHID reply/);
  reader.close();
});

test('a stray continuation packet does not start a message', async () => {
  // Only an init packet begins one. Treating a continuation as a start would
  // read its sequence byte as a command and its payload as a length.
  const transport = fakeCtapHid({ cid: Uint8Array.of(0xaa, 0xbb, 0xcc, 0xdd) });
  const ctap = new CtapHid(transport);
  await ctap.init();

  const reader = ctap._open(ctap.cid, { timeoutMs: 60 });

  const orphan = new Uint8Array(64);
  orphan.set(ctap.cid, 0);
  orphan[4] = 0x00; // a sequence number, not a command
  transport.inject([orphan]);

  await assert.rejects(() => reader.next(), /no CTAPHID reply/);
  reader.close();
});

test('the wait after a KEEPALIVE is much longer than the ordinary one', async () => {
  /*
   * Not a safety margin - it is what the firmware does. device.cpp:172 sends
   * KEEPALIVE only when the status CHANGES, so a user-presence wait produces
   * exactly ONE keepalive and then silence for up to CTAP2_UP_DELAY_MS (19
   * seconds, ctap.h:173) while the device waits for a finger.
   *
   * A client using its ordinary timeout gives up partway through a ceremony
   * the user is still confirming. This asserts the two waits are different:
   * the ordinary one expires, the post-keepalive one survives past it.
   */
  const transport = fakeCtapHid({ cid: Uint8Array.of(1, 2, 3, 4) });
  const ctap = new CtapHid(transport);
  await ctap.init();

  const reader = ctap._open(ctap.cid, { timeoutMs: 30 });

  // The ordinary wait gives up quickly...
  await assert.rejects(() => reader.next(), /within 30ms/);
  // ...but an explicit longer wait is honoured, and reports ITS limit.
  await assert.rejects(() => reader.next(60), /within 60ms/);
  reader.close();
});

test('a slow press still completes, where the ordinary timeout would not', async () => {
  const transport = fakeCtapHid({ onCbor: () => new Map([[1, 'pressed']]) });
  const ctap = new CtapHid(transport);
  await ctap.init();

  // One keepalive, then the answer arrives later than the ordinary timeout.
  const slow = {
    ...transport,
    async write(iface, bytes) {
      const n = await transport.write(iface, bytes);
      return n;
    },
  };
  const ctapSlow = new CtapHid(slow);
  ctapSlow.cid = ctap.cid;

  const out = await ctapSlow.send(CTAP2_CMD.GET_ASSERTION, new Uint8Array(0), {
    timeoutMs: 500,
    presenceTimeoutMs: 2000,
  });
  assert.equal(out.get(1), 'pressed');
});

test('every status we can send is one the spec defines', () => {
  /*
   * CTAP2_ERROR answers "what did the device send me". CTAP2_STATUS answers
   * "what may I send back", and until it existed, callers that needed the
   * second direction wrote their own - ok-rn's copy had NOT_ALLOWED as 0x30,
   * which is not a CTAP2 status at all, and UNSUPPORTED_OPTION as 0x2b, which
   * is NO_CREDENTIALS. Every rejected BLE request carried an undefined byte.
   *
   * Asserting one table against the other is what stops the pair drifting
   * apart again: a name here without a code there is a code nobody defined.
   */
  for (const [name, code] of Object.entries(CTAP2_STATUS)) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(CTAP2_ERROR, code),
      `CTAP2_STATUS.${name} = 0x${code.toString(16)} is not a defined CTAP2 status`,
    );
  }

  /* And the two that were wrong, pinned by value so a typo cannot pass. */
  assert.equal(CTAP2_STATUS.NOT_ALLOWED, 0x2d);
  assert.equal(CTAP2_STATUS.NO_CREDENTIALS, 0x2b);
  assert.equal(CTAP2_STATUS.UNSUPPORTED_OPTION, 0x6a);
  assert.equal(CTAP2_ERROR[0x2d], 'CTAP2_ERR_NOT_ALLOWED');
});

/*
 * ## Assembler
 *
 * These came from ok-rn's `src/transport/framing.ts`, a second implementation
 * of this framing that the app kept for its USB path. That file is gone; its
 * tests are here, against the one implementation, with the two that asserted
 * the OTHER answer to an unexpected continuation rewritten to assert this one.
 * See the class comment for why this behaviour is the one that survived.
 */

const CID = Uint8Array.of(0x11, 0x22, 0x33, 0x44);
const filler = (n) => Uint8Array.from({ length: n }, (_, i) => i & 0xff);

test('a channel id round-trips between four bytes and a number', () => {
  assert.deepEqual(Array.from(cidBytes(0xffffffff)), [0xff, 0xff, 0xff, 0xff]);
  assert.equal(cidNumber(CID), 0x11223344);
  // The high bit set must not come back negative, which a bare << 24 would.
  assert.equal(cidNumber(cidBytes(0xffffffff)), 0xffffffff);
});

test('frame refuses a payload longer than the length field can describe', () => {
  assert.throws(
    () => frame(CID, CTAPHID.MSG, new Uint8Array(0x10000)),
    /exceeds 65535/,
    'a truncated message discovered at the other end is worse than throwing',
  );
});

test('the assembler puts a fragmented message back together', () => {
  const data = filler(400);
  const packets = frame(CID, CTAPHID.CBOR, data);
  const assembler = new Assembler();

  const done = packets.map((p) => assembler.push(p)).filter(Boolean);
  assert.equal(done.length, 1, 'exactly one message, on the last packet');
  assert.equal(done[0].cmd, CTAPHID.CBOR);
  assert.deepEqual(Array.from(done[0].payload), Array.from(data));
});

test('a continuation with no init before it is ignored', () => {
  const assembler = new Assembler();
  const stray = new Uint8Array(PACKET_SIZE);
  stray.set(CID, 0);
  stray[4] = 0x00; // a sequence byte, not a command
  assert.equal(assembler.push(stray), null);
});

test('an out-of-order continuation is dropped, the message is not', () => {
  /*
   * ok-rn's copy abandoned the message here and returned null for the rest of
   * it. Dropping the one bad packet keeps the good bytes, so the message still
   * completes when the packet it was actually waiting for arrives.
   */
  const data = filler(400);
  const packets = frame(CID, CTAPHID.CBOR, data);
  const assembler = new Assembler();

  assembler.push(packets[0]);
  assert.equal(assembler.push(packets[3]), null, 'seq 2 while seq 0 is due');
  assert.equal(assembler.progress.have, INIT_PAYLOAD, 'the init payload is still held');

  for (const p of packets.slice(1)) {
    const message = assembler.push(p);
    if (message) {
      assert.deepEqual(Array.from(message.payload), Array.from(data));
      return;
    }
  }
  assert.fail('the message never completed');
});

test('a continuation on another channel is dropped, the message is not', () => {
  const data = filler(200);
  const packets = frame(CID, CTAPHID.CBOR, data);
  const assembler = new Assembler();

  assembler.push(packets[0]);
  const wrongChannel = Uint8Array.from(packets[1]);
  wrongChannel[0] = 0x99;
  assert.equal(assembler.push(wrongChannel), null);
  assert.equal(assembler.progress.have, INIT_PAYLOAD, 'and took nothing from it');

  const done = packets.slice(1).map((p) => assembler.push(p)).filter(Boolean);
  assert.equal(done.length, 1, 'the real continuations still complete it');
  assert.deepEqual(Array.from(done[0].payload), Array.from(data));
});

test('a fresh init replaces a message that was left unfinished', () => {
  const assembler = new Assembler();
  assembler.push(frame(CID, CTAPHID.CBOR, filler(400))[0]); // start, then walk away

  const data = filler(10);
  const [init] = frame(CID, CTAPHID.PING, data);
  const message = assembler.push(init);

  assert.ok(message, 'the new message is not held up by the abandoned one');
  assert.equal(message.cmd, CTAPHID.PING);
  assert.deepEqual(Array.from(message.payload), Array.from(data));
});

test('both ends honour a report size that is not 64', () => {
  /*
   * A USB endpoint reports its own packet size on connect. This is the reason
   * `packetSize` is a parameter and not the constant.
   */
  const data = filler(100);
  const packets = frame(CID, CTAPHID.CBOR, data, 32);
  assert.ok(packets.every((p) => p.length === 32));

  const assembler = new Assembler({ packetSize: 32 });
  const done = packets.map((p) => assembler.push(p)).filter(Boolean);
  assert.deepEqual(Array.from(done[0].payload), Array.from(data));
});
