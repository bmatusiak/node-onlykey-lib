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
  CtapHid, Ctap2Error, frame,
  CTAPHID, CTAP2_CMD, KEEPALIVE, BROADCAST_CID,
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
