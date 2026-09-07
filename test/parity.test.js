/*
 * Transport parity.
 *
 * Every transport normalises independently - that is unavoidable, since each
 * sits on a different bus with different rules about report ids and padding.
 * The risk is that identical library code puts different bytes on the wire
 * depending on where it runs, which is invisible in unit tests of either
 * transport alone and shows up as "it works under the emulator but not on
 * hardware".
 *
 * So: the same frames, through each transport, compared byte for byte at the
 * point where they leave for the bus.
 *
 * The one legitimate difference is the report id, and it is asserted rather
 * than waved through. A transport whose platform needs one adds it on the way
 * out; the payload underneath must still be identical.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const Rectify = require('@bmatusiak/rectify');
const hostPlugin = require('../plugins/host');
const memoryTransport = require('../plugins/transport/memory');
const embedded = require('../plugins/transport/embedded');
const { fakePipe } = require('./helpers/fake-pipe');
const { IFACE, REPORT_SIZE } = require('../src/transport/contract');
const { MSG } = require('../src/protocol/msg');
const okmsg = require('../src/protocol/okmsg');
const { toHex, fromLatin1 } = require('../src/bytes');

function start(plugins, config) {
  if (config) plugins.config = config;
  return new Promise((resolve, reject) => {
    const app = Rectify.build(plugins, (err, started) => {
      if (err) reject(err);
      else resolve(started);
    });
    app.start();
  });
}

/** Frames chosen to exercise each branch of the normalisation rules. */
const FRAMES = [
  { what: 'a bare OKCONNECT header', bytes: okmsg.build({ msg: MSG.OKCONNECT }) },
  { what: 'a slot write with contents', bytes: okmsg.build({ msg: MSG.OKSETSLOT, slot: 1, field: 5, payload: fromLatin1('FooPassword') }) },
  { what: 'a frame that is already a full report', bytes: new Uint8Array(REPORT_SIZE).fill(0x5a) },
  { what: 'a frame ending in real NUL bytes', bytes: (() => { const b = new Uint8Array(10); b[0] = 0xff; return b; })() },
];

async function bytesFromMemory(frame) {
  const app = await start([hostPlugin, memoryTransport]);
  const seen = [];
  app.services.transport.on('write', (e) => seen.push(e.data));
  await app.services.transport.write(IFACE.VENDOR, frame);
  await app.destroy();
  return seen[0];
}

async function bytesFromEmbedded(frame) {
  const pipe = fakePipe({ autoStart: true });
  const app = await start([hostPlugin, embedded], { transport: { pipe } });
  await app.services.transport.write(IFACE.VENDOR, frame);
  await app.destroy();
  return pipe.writes[0].data;
}

for (const { what, bytes } of FRAMES) {
  test(`memory and embedded agree on ${what}`, async () => {
    const [viaMemory, viaEmbedded] = await Promise.all([
      bytesFromMemory(bytes),
      bytesFromEmbedded(bytes),
    ]);
    assert.equal(toHex(viaEmbedded), toHex(viaMemory));
  });
}

test('every transport pads a vendor frame to exactly one report', async () => {
  /*
   * Stated as its own assertion because it is the rule most easily lost: a
   * transport that forwards a short frame unchanged works against anything
   * that reassembles by length, and fails against a device whose read is a
   * fixed 64-byte descriptor - it waits for bytes that never arrive.
   */
  const short = okmsg.build({ msg: MSG.OKPING });
  for (const [name, get] of [['memory', bytesFromMemory], ['embedded', bytesFromEmbedded]]) {
    const sent = await get(short);
    assert.equal(sent.length, REPORT_SIZE, `${name} did not pad to a full report`);
  }
});

test('no transport prepends a report id of its own accord', async () => {
  // Both of these sit on an in-process bus. A hidapi-backed transport WILL
  // prepend one - and when it exists it must do so in write(), never at a
  // higher layer, or two transports disagree about whose job it is.
  const frame = okmsg.build({ msg: MSG.OKCONNECT });
  for (const get of [bytesFromMemory, bytesFromEmbedded]) {
    const sent = await get(frame);
    assert.equal(toHex(sent.subarray(0, 5)), 'ffffffffe4', 'header starts at byte 0');
  }
});

test('an OKCONNECT over either transport has the same shape on the wire', async () => {
  /*
   * Byte-for-byte is impossible here and should not be faked: connect()
   * generates a fresh X25519 keypair and stamps the current time, so two runs
   * differ by design. What must not differ is the framing around them - the
   * header, the length, and where the public key sits.
   *
   * The frame is captured from the write event rather than by awaiting
   * connect(). The fake pipe is a byte pipe with no device behind it, so it
   * never answers and connect() would sit there until it timed out - which
   * would be a test of the timeout, not of the framing.
   */
  const sessionPlugin = require('../plugins/session');

  // A permitted consumer: `session` is restricted to device and okcrypto.
  const harness = (imports, register) => {
    register(null, { device: { session: imports.session } });
  };
  harness.consumes = ['session'];
  harness.provides = ['device'];

  async function connectFrame(plugins, config) {
    const app = await start(plugins, config);
    const frame = await new Promise((resolve) => {
      app.services.transport.on('write', (e) => resolve(e.data));
      // Deliberately not awaited, and its rejection is absorbed: we want the
      // bytes it puts on the wire, not its answer.
      app.services.device.session.connect({ timeoutMs: 50 }).catch(() => {});
    });
    await app.destroy();
    return frame;
  }

  const viaMemory = await connectFrame([hostPlugin, memoryTransport, sessionPlugin, harness]);

  const pipe = fakePipe({ autoStart: true });
  const viaEmbedded = await connectFrame(
    [hostPlugin, embedded, sessionPlugin, harness],
    { transport: { pipe } },
  );

  assert.equal(viaEmbedded.length, REPORT_SIZE, 'one full report');
  assert.equal(viaMemory.length, REPORT_SIZE);
  assert.equal(
    toHex(viaEmbedded.subarray(0, 5)),
    toHex(viaMemory.subarray(0, 5)),
    'same header and message id',
  );
  assert.equal(toHex(viaMemory.subarray(0, 5)), 'ffffffffe4');
  assert.notEqual(
    toHex(viaEmbedded.subarray(9, 41)),
    toHex(viaMemory.subarray(9, 41)),
    'the key really is fresh each time, so this is not comparing a constant',
  );
});
