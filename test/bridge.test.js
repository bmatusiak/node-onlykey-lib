/*
 * The CTAP2 bridge - the middle of "browser -> phone -> firmware".
 *
 * The tests that matter here are about what the bridge must NOT do: interpret,
 * re-encode, or go quiet. Each of those breaks something that only shows up
 * against a real browser, which is the hardest place to debug it.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { createCtapBridge, BRIDGE_STATUS } = require('../src/protocol/bridge');
const { CtapHid, CTAP2_CMD } = require('../src/protocol/ctaphid');
const cbor = require('../src/protocol/cbor');
const { fakeCtapHid } = require('./helpers/fake-ctaphid');
const { toHex } = require('../src/bytes');

/** A whole CTAP2 message, the way it arrives off the Control Point. */
function request(cmd, params) {
  return params === undefined
    ? Uint8Array.of(cmd)
    : new Uint8Array([cmd, ...cbor.encode(params)]);
}

test('a request reaches the device and its answer comes back whole', async () => {
  const seen = [];
  const transport = fakeCtapHid({
    onCbor: (cmd, params) => {
      seen.push({ cmd, params });
      return new Map([[1, ['FIDO_2_0']], [3, new Uint8Array(16).fill(7)]]);
    },
  });

  const bridge = createCtapBridge(transport);
  const response = await bridge.handle(request(CTAP2_CMD.GET_INFO));

  assert.equal(seen.length, 1);
  assert.equal(seen[0].cmd, CTAP2_CMD.GET_INFO);

  assert.equal(response[0], 0x00, 'status byte leads the response');
  const decoded = cbor.decode(response.subarray(1));
  assert.deepEqual(decoded.get(1), ['FIDO_2_0']);
});

test('the response is forwarded BYTE FOR BYTE, not re-encoded', async () => {
  /*
   * The reason this matters: authData and the attestation statement are signed
   * over exact bytes. A bridge that decodes CBOR and encodes it again can
   * change an integer's width or a map's order and produce something that
   * verifies as a forgery at the relying party - with every layer reporting
   * success.
   *
   * So the bytes the device emitted are compared with the bytes that came out.
   */
  const answer = new Map([[1, 'packed'], [2, new Uint8Array(37).fill(0xab)]]);
  const expected = new Uint8Array([0x00, ...cbor.encode(answer)]);

  const transport = fakeCtapHid({ onCbor: () => answer });

  const bridge = createCtapBridge(transport);
  const response = await bridge.handle(request(CTAP2_CMD.MAKE_CREDENTIAL, new Map([[1, 1]])));

  assert.equal(toHex(response), toHex(expected), 'the response was altered in transit');
});

test('a device error is relayed, not converted into a thrown error', async () => {
  /*
   * A browser told CTAP2_ERR_NO_CREDENTIALS tries another authenticator. One
   * told "the request failed" gives up - and one told nothing at all hangs
   * until its own timeout, which is minutes.
   */
  const transport = fakeCtapHid({ onCbor: () => ({ status: 0x2b }) });
  const bridge = createCtapBridge(transport);

  const response = await bridge.handle(request(CTAP2_CMD.GET_ASSERTION, new Map([[1, 'x']])));

  assert.equal(response.length, 1);
  assert.equal(response[0], 0x2b, 'the device status was not passed through');
});

test('keepalives are relayed while the device waits for a finger', async () => {
  /*
   * The firmware sends ONE keepalive on the status change and then goes silent
   * for up to nineteen seconds. A BLE host hearing nothing for that long
   * abandons a ceremony the user is halfway through, so these have to reach it.
   */
  const relayed = [];
  const transport = fakeCtapHid({ keepAlives: 3, onCbor: () => new Map([[1, 'ok']]) });

  const bridge = createCtapBridge(transport, {
    onKeepAlive: status => relayed.push(status),
  });
  const response = await bridge.handle(request(CTAP2_CMD.MAKE_CREDENTIAL, new Map([[1, 1]])));

  assert.equal(relayed.length, 3, 'the host was not told to keep waiting');
  assert.deepEqual(relayed, [0x02, 0x02, 0x02], 'UP_NEEDED is the status that matters');
  assert.equal(response[0], 0x00);
});

test('a device that never answers still produces a response', async () => {
  // Silence on BLE is the one failure a host cannot recover from.
  const transport = fakeCtapHid({ onCbor: () => undefined });
  transport.write = async () => {};

  const bridge = createCtapBridge(transport, { timeoutMs: 60 });
  const response = await bridge.handle(request(CTAP2_CMD.GET_INFO));

  assert.equal(response.length, 1);
  assert.equal(response[0], BRIDGE_STATUS.TIMEOUT, 'a timeout must be reported as one');
});

test('an empty request is answered rather than ignored', async () => {
  const transport = fakeCtapHid({});
  const bridge = createCtapBridge(transport);

  const response = await bridge.handle(new Uint8Array(0));
  assert.deepEqual([...response], [BRIDGE_STATUS.INVALID_LENGTH]);
});

test('one channel serves every request', async () => {
  /*
   * The firmware allocates ten channels and never frees one (ctaphid.cpp:67),
   * so a bridge that runs INIT per request dies on the eleventh - and the
   * error it returns then has nothing to do with what was asked.
   */
  let inits = 0;
  const transport = fakeCtapHid({ onCbor: () => new Map([[1, 'ok']]) });
  const write = transport.write.bind(transport);
  transport.write = async (iface, data) => {
    // The command byte follows the 4-byte channel id, with TYPE_INIT set:
    // CTAPHID_INIT is 0x06 | 0x80.
    if (data[4] === 0x86) inits += 1;
    return write(iface, data);
  };

  const bridge = createCtapBridge(transport);
  for (let i = 0; i < 12; i++) {
    const response = await bridge.handle(request(CTAP2_CMD.GET_INFO));
    assert.equal(response[0], 0x00, `request ${i} failed`);
  }

  assert.equal(inits, 1, `opened ${inits} channels for 12 requests`);
});

test('a failure drops the channel, so a late reply cannot answer the next request', async () => {
  /*
   * After a timeout the device may still be about to reply. Kept on the same
   * channel, that stale frame is read as the answer to whatever is asked next
   * - an off-by-one-response bug that is very hard to see, because every
   * response looks well-formed and merely belongs to the previous question.
   */
  const transport = fakeCtapHid({ onCbor: () => new Map([[1, 'ok']]) });
  const real = transport.write.bind(transport);
  let swallow = true;
  transport.write = async (iface, data) => {
    // CBOR is 0x10 | TYPE_INIT, not 0x10 - the framed byte carries the flag.
    if (swallow && data[4] === 0x90) return; // eat the CBOR request only
    return real(iface, data);
  };

  const bridge = createCtapBridge(transport, { timeoutMs: 60 });
  const first = await bridge.handle(request(CTAP2_CMD.GET_INFO));
  assert.equal(first[0], BRIDGE_STATUS.TIMEOUT);
  assert.equal(bridge.channel, null, 'the suspect channel was kept');

  swallow = false;
  const second = await bridge.handle(request(CTAP2_CMD.GET_INFO));
  assert.equal(second[0], 0x00, 'the bridge did not recover');
});

test('it accepts a CtapHid as readily as a transport', async () => {
  // The app already has one for its own use; making it build a second would
  // mean two channels and two readers on one bus.
  const transport = fakeCtapHid({ onCbor: () => new Map([[1, 'ok']]) });
  const ctap = new CtapHid(transport);
  await ctap.init();

  const bridge = createCtapBridge(ctap);
  const response = await bridge.handle(request(CTAP2_CMD.GET_INFO));
  assert.equal(response[0], 0x00);
});
