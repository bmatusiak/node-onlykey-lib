/*
 * transport/embedded - the firmware in this process.
 *
 * These are the first tests of the normalisation rules. transport/memory never
 * exercised them: it never calls stripPadding or withReportId, and it invents
 * its own replies rather than receiving them, so the rules that decide what a
 * report MEANS have until now been documented and unverified.
 *
 * The rules come from onlykey-testing/lib/device/hardware.js:351-375,479-516,
 * the one implementation proven against both a physical key and an emulated
 * one, and each assertion below says which behaviour it pins and what breaks
 * without it.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const Rectify = require('@bmatusiak/rectify');
const hostPlugin = require('../plugins/host');
const embedded = require('../plugins/transport/embedded');
const { fakePipe } = require('./helpers/fake-pipe');
const { IFACE, REPORT_SIZE } = require('../src/transport/contract');
const { toHex, fromLatin1 } = require('../src/bytes');

/** Boot an app with the embedded transport over a given pipe. */
function start(pipe, extra = []) {
  const plugins = [hostPlugin, embedded, ...extra];
  plugins.config = { transport: { pipe } };
  return new Promise((resolve, reject) => {
    const app = Rectify.build(plugins, (err, started) => {
      if (err) reject(err);
      else resolve(started);
    });
    app.start();
  });
}

/* ------------------------------------------------------------ composition */

test('the plugin provides a contract-complete transport', async () => {
  const app = await start(fakePipe());
  assert.equal(app.services.transport.name, 'embedded');
  await app.destroy();
});

test('a missing pipe fails at build, naming the plugin', async () => {
  // A composition mistake should not survive to become a TypeError inside a
  // poll loop with no hint of where the wiring went wrong.
  await assert.rejects(
    () => start(undefined),
    /transport\/embedded needs a byte pipe/,
  );
});

test('a pipe missing a method is named, not merely rejected', async () => {
  const broken = fakePipe();
  delete broken.write;
  await assert.rejects(() => start(broken), /pipe is missing write/);
});

/* -------------------------------------------------------------- outbound */

test('a vendor frame goes out as exactly one report', async () => {
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  await app.services.transport.write(IFACE.VENDOR, fromLatin1('short'));

  assert.equal(pipe.writes.length, 1);
  assert.equal(pipe.writes[0].data.length, REPORT_SIZE, 'padded to a full report');
  await app.destroy();
});

test('NO report id is prepended - this bus does not use one', async () => {
  /*
   * The proven hardware client writes [0x00, ...frame] because hidapi and
   * chrome.hid want a report id. okemu_hid_deliver() does not: it memcpys the
   * payload straight into a 64-byte packet. A report id here shifts every
   * field by one, so the firmware reads our message id as part of its header
   * and the message is silently wrong rather than rejected.
   */
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  await app.services.transport.write(IFACE.VENDOR, Uint8Array.from([0xff, 0xff, 0xff, 0xff, 0xe4]));

  const sent = pipe.writes[0].data;
  assert.equal(sent[0], 0xff, 'first byte is ours, not a report id');
  assert.equal(toHex(sent.subarray(0, 5)), 'ffffffffe4');
  await app.destroy();
});

test('an over-long frame is refused with its length, not truncated', async () => {
  // okemu_hid_deliver() does `len < 64 ? len : 64` and drops the rest without
  // a word, so the device would act on a half message.
  const app = await start(fakePipe({ autoStart: true }));
  await assert.rejects(
    () => app.services.transport.write(IFACE.VENDOR, new Uint8Array(65)),
    /frame is 65 bytes/,
  );
  await app.destroy();
});

test('SEREMU is a byte stream, so it is not padded to a report', async () => {
  // The debug console takes bytes, not 64-byte reports - padding a keystroke
  // to 64 would send 63 NULs to a console that echoes them.
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  await app.services.transport.write(IFACE.SEREMU, fromLatin1('12'));

  assert.equal(pipe.writes[0].data.length, 2, 'sent as-is');
  await app.destroy();
});

/* --------------------------------------------------------------- inbound */

test('our own write is not mistaken for a reply', async () => {
  /*
   * The pipe reports traffic in BOTH directions on one callback. Without the
   * direction filter every request resolves with the bytes it just sent, which
   * against a real device reads as a device that echoes rather than as a host
   * bug.
   */
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  const reports = [];
  app.services.transport.on('report', (e) => reports.push(e));

  await app.services.transport.write(IFACE.VENDOR, fromLatin1('ping'));

  assert.deepEqual(reports, [], 'the echo produced no report');
  await app.destroy();
});

test('a vendor report keeps all 64 bytes, padding included', async () => {
  /*
   * Vendor payloads are indexed by offset and can contain real NULs - the
   * transit box is a keystream over arbitrary plaintext, so it produces them
   * routinely. Stripping here corrupts a sealed payload, and the damage only
   * surfaces as a decryption that yields noise.
   */
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  const reports = [];
  app.services.transport.on('report', (e) => reports.push(e.data));

  const withNuls = new Uint8Array(REPORT_SIZE);
  withNuls[0] = 0xaa;
  withNuls[5] = 0x00; // interior NUL, a real byte
  withNuls[6] = 0xbb;
  pipe.deliver(withNuls);

  assert.equal(reports[0].length, REPORT_SIZE, 'nothing was stripped');
  assert.equal(reports[0][6], 0xbb);
  await app.destroy();
});

test('SEREMU text has its NUL padding stripped', async () => {
  // hidprint() memsets 64 bytes and writes a short line into it. A NUL
  // reaching a regex makes it fail to match a prompt that is plainly there -
  // and the PIN flow is driven entirely by matching those prompts.
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  const lines = [];
  app.services.transport.on('log', (e) => lines.push(e.text));

  pipe.deliverText('Enter PIN');

  assert.deepEqual(lines, ['Enter PIN']);
  assert.match(lines[0], /Enter PIN/, 'and it matches the prompt pattern');
  await app.destroy();
});

test('a SEREMU report that is all padding produces no line', async () => {
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  const lines = [];
  app.services.transport.on('log', (e) => lines.push(e.text));

  pipe.deliverText('');

  assert.deepEqual(lines, [], 'blank lines do not reach a log that is matched against');
  await app.destroy();
});

test('keyboard traffic is its own event, not a report', async () => {
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  const keys = [];
  const reports = [];
  app.services.transport.on('keyboard', (e) => keys.push(e.data));
  app.services.transport.on('report', (e) => reports.push(e));

  pipe.deliver(new Uint8Array(8), { iface: IFACE.KEYBOARD });

  assert.equal(keys.length, 1);
  assert.deepEqual(reports, []);
  await app.destroy();
});

/* --------------------------------------------------------------- request */

test('request resolves with the reply for its own interface', async () => {
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  const pending = app.services.transport.request({
    iface: IFACE.VENDOR,
    data: fromLatin1('go'),
    timeoutMs: 1000,
  });
  pipe.deliver(Uint8Array.from([1, 2, 3, 4]));

  assert.equal(toHex(await pending), '01020304');
  await app.destroy();
});

test('request ignores a report from another interface', async () => {
  // The firmware multiplexes four interfaces onto one callback, so a debug
  // line printed mid-request would otherwise resolve the caller with log text.
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  const pending = app.services.transport.request({
    iface: IFACE.VENDOR,
    data: fromLatin1('go'),
    timeoutMs: 1000,
  });
  pipe.deliverText('Enter PIN');
  pipe.deliver(Uint8Array.from([9, 9]));

  assert.equal(toHex(await pending), '0909');
  await app.destroy();
});

test('request subscribes before writing, so a fast reply is not lost', async () => {
  /*
   * The reason request() exists rather than write-then-wait at the caller.
   * This pipe answers synchronously inside write(), which is the worst case: a
   * caller that subscribed afterwards would already have missed it.
   */
  const pipe = fakePipe({ autoStart: true });
  const instant = {
    ...pipe,
    async write(iface, bytes) {
      const n = await pipe.write(iface, bytes);
      pipe.deliver(Uint8Array.from([0x42]));
      return n;
    },
  };
  const app = await start(instant);

  const reply = await app.services.transport.request({
    iface: IFACE.VENDOR,
    data: fromLatin1('go'),
    timeoutMs: 1000,
  });

  assert.equal(toHex(reply), '42');
  await app.destroy();
});

test('request times out with the interface in the message', async () => {
  const app = await start(fakePipe({ autoStart: true }));
  await assert.rejects(
    () =>
      app.services.transport.request({
        iface: IFACE.VENDOR,
        data: fromLatin1('go'),
        timeoutMs: 20,
      }),
    /no reply on interface 2 within 20ms/,
  );
  await app.destroy();
});

/* --------------------------------------------------------- lifecycle */

test('open starts the firmware and isOpen follows it', async () => {
  const pipe = fakePipe();
  const app = await start(pipe);
  const { transport } = app.services;

  assert.equal(transport.isOpen(), false);
  await transport.open();
  assert.equal(transport.isOpen(), true);
  await transport.close();
  assert.equal(transport.isOpen(), false);

  await app.destroy();
});

test('open is idempotent - it does not restart a running firmware', async () => {
  // Restarting would wipe the session key on a device that was already up.
  const pipe = fakePipe({ autoStart: true });
  let starts = 0;
  const counted = {
    ...pipe,
    async start() {
      starts++;
      return pipe.start();
    },
  };
  const app = await start(counted);

  await app.services.transport.open();
  await app.services.transport.open();

  assert.equal(starts, 0, 'already running, so never started');
  await app.destroy();
});

test('destroy unsubscribes from the pipe', async () => {
  // The pipe delivers on the firmware thread, so a report still in flight
  // would otherwise land on a listener whose app is being torn down.
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);
  assert.equal(pipe.listenerCount, 1);

  await app.destroy();

  assert.equal(pipe.listenerCount, 0);
});
