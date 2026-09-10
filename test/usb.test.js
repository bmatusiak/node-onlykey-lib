/*
 * transport/usb - a physical OnlyKey on a USB bus.
 *
 * The sibling of embedded.test.js, and it checks the same rules for the same
 * reason: the firmware is the same firmware, so what a report MEANS does not
 * change with the bus it arrived on. Where the two plugins agree, these tests
 * are the proof of that agreement - which is what will make extracting a shared
 * factory a refactor rather than a rewrite.
 *
 * Driven over the same fake pipe embedded uses. That is deliberate: this plugin
 * consumes exactly the pipe contract, so nothing about USB needs to be faked
 * here beyond it. The parts that ARE USB-specific - claiming interfaces,
 * identifying them by usage page, endpoint widths - live below the pipe and are
 * measured against a real key by ok-rn's hardware suite.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const Rectify = require('@bmatusiak/rectify');
const hostPlugin = require('../plugins/host');
const usb = require('../plugins/transport/usb');
const { fakePipe } = require('./helpers/fake-pipe');
const { IFACE, DIR, REPORT_SIZE } = require('../src/transport/contract');
const { toHex, fromLatin1 } = require('../src/bytes');

function start(pipe, extra = []) {
  const plugins = [hostPlugin, usb, ...extra];
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

test('the plugin provides a contract-complete transport, named usb', async () => {
  // assertTransport runs at registration, so a missing method is a build-time
  // failure naming this plugin rather than a TypeError from inside a poll loop.
  const app = await start(fakePipe());
  assert.equal(app.services.transport.name, 'usb');
  await app.destroy();
});

test('a missing or malformed pipe is refused at BUILD time', async () => {
  // Composition mistakes should name the plugin. Discovering this on first use
  // surfaces as a TypeError with no hint of where the wiring went wrong.
  await assert.rejects(() => start(null), /needs a byte pipe/);
  await assert.rejects(
    () => start({ start() {}, stop() {}, isRunning() {} }),
    /pipe is missing write/,
  );
});

/* ----------------------------------------------------- normalisation rules */

test('SEREMU is the ONLY interface whose padding is stripped', async () => {
  // hidprint() memsets its buffer and writes a short line into it, so the tail
  // is buffer rather than message. A NUL reaching a regex makes it fail to
  // match something that is plainly there.
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  const lines = [];
  app.services.transport.on('log', (e) => lines.push(e.text));

  const padded = new Uint8Array(64);
  padded.set(fromLatin1('UNLOCKED'));
  pipe.deliver(padded, { iface: IFACE.SEREMU });

  assert.deepEqual(lines, ['UNLOCKED']);
  await app.destroy();
});

test('a SEREMU report that is nothing but padding is dropped', async () => {
  // Otherwise every idle poll emits a blank line into a log that is matched
  // against.
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  const lines = [];
  app.services.transport.on('log', (e) => lines.push(e.text));
  pipe.deliver(new Uint8Array(64), { iface: IFACE.SEREMU });

  assert.deepEqual(lines, []);
  await app.destroy();
});

test('vendor reports keep ALL their bytes, NULs included', async () => {
  // A NUL inside a vendor report is a real byte - the transit box produces them
  // routinely, being a keystream over arbitrary plaintext. Stripping would
  // corrupt a sealed payload in a way that shows up only as noise after
  // decryption.
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  const seen = [];
  app.services.transport.on('report', (e) => seen.push(e));

  const withNuls = new Uint8Array(64);
  withNuls[0] = 0xff;
  withNuls[63] = 0xee;
  pipe.deliver(withNuls, { iface: IFACE.VENDOR });

  assert.equal(seen.length, 1);
  assert.equal(seen[0].iface, IFACE.VENDOR);
  assert.equal(seen[0].data.length, 64);
  assert.equal(seen[0].data[63], 0xee);
  await app.destroy();
});

test('the keyboard interface is CAPTURED, on its own event', async () => {
  // The reason a host claims this interface at all: left alone, a real key
  // types into whatever window has focus instead of into the app.
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  const typed = [];
  app.services.transport.on('keyboard', (e) => typed.push(e.data));
  app.services.transport.on('report', () => {
    assert.fail('keyboard traffic must not reach the report event');
  });

  pipe.deliver(Uint8Array.from([0, 0, 0x04, 0, 0, 0, 0, 0]), { iface: IFACE.KEYBOARD });

  assert.equal(typed.length, 1);
  assert.equal(typed[0][2], 0x04);
  await app.destroy();
});

/* ------------------------------------------------------------------ writes */

test('outbound frames are padded to a full report, and NEVER truncated', async () => {
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  await app.services.transport.write(IFACE.VENDOR, Uint8Array.from([1, 2, 3]));
  const sent = pipe.writes[pipe.writes.length - 1];
  assert.equal(sent.data.length, REPORT_SIZE);
  assert.equal(toHex(sent.data.slice(0, 3)), '010203');

  // An over-long frame is a caller error with a length in the message, not a
  // message the device half-receives.
  await assert.rejects(
    () => app.services.transport.write(IFACE.VENDOR, new Uint8Array(65)),
  );
  await app.destroy();
});

test('SEREMU writes are NOT padded', async () => {
  // The debug console takes a line terminated by a return. Padding would append
  // NULs, and its outbound endpoint is 32 bytes rather than 64 - a padded write
  // would not even fit.
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  await app.services.transport.write(IFACE.SEREMU, fromLatin1('1\n'));
  const sent = pipe.writes[pipe.writes.length - 1];
  assert.equal(sent.iface, IFACE.SEREMU);
  assert.equal(sent.data.length, 2);
  await app.destroy();
});

test('NO report id is prepended - this bus has no HID layer', async () => {
  // A hidapi or chrome.hid client prepends a zero byte because those APIs use
  // it to select a report. Android writes to the endpoint directly, so a
  // leading byte would shift every field and the firmware would read our
  // message id as its header.
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  await app.services.transport.write(IFACE.VENDOR, Uint8Array.from([0xab, 0xcd]));
  const sent = pipe.writes[pipe.writes.length - 1];
  assert.equal(sent.data[0], 0xab, 'first byte must be the message, not a report id');
  await app.destroy();
});

/* ---------------------------------------------------------------- request */

test('request subscribes BEFORE it writes', async () => {
  // A fast device answers before a caller that writes first can start
  // listening, and the reply is lost with no error - just a timeout somewhere
  // unrelated. This is the whole reason request() is one method.
  const pipe = fakePipe({ autoStart: true });
  /*
   * The fake has no reply hook, so the write is wrapped. Answering from
   * inside the write is exactly the race request() exists for: a device that
   * is quicker than the caller.
   */
  const realWrite = pipe.write;
  pipe.write = async (iface, bytes) => {
    const n = await realWrite(iface, bytes);
    pipe.deliver(Uint8Array.from([0x99]), { iface: IFACE.VENDOR });
    return n;
  };

  const app = await start(pipe);
  const reply = await app.services.transport.request({
    iface: IFACE.VENDOR,
    data: Uint8Array.from([1]),
  });
  assert.equal(reply[0], 0x99);
  await app.destroy();
});

test('an unsolicited broadcast is not mistaken for an answer', async () => {
  // A locked device broadcasts its status once a second. Without a match
  // predicate the caller is told a slot write was acknowledged "INITIALIZED".
  const pipe = fakePipe({ autoStart: true });
  const realWrite = pipe.write;
  pipe.write = async (iface, bytes) => {
    const n = await realWrite(iface, bytes);
    pipe.deliver(fromLatin1('INITIALIZED'), { iface: IFACE.VENDOR });
    pipe.deliver(Uint8Array.from([0x42]), { iface: IFACE.VENDOR });
    return n;
  };

  const app = await start(pipe);
  const reply = await app.services.transport.request({
    iface: IFACE.VENDOR,
    data: Uint8Array.from([1]),
    match: (data) => data[0] === 0x42,
  });
  assert.equal(reply[0], 0x42);
  await app.destroy();
});

test('a reply on ANOTHER interface does not resolve the request', async () => {
  // Four interfaces are multiplexed onto one callback, so a console line
  // printed mid-request would otherwise resolve the caller with log text.
  const pipe = fakePipe({ autoStart: true });
  const realWrite = pipe.write;
  pipe.write = async (iface, bytes) => {
    const n = await realWrite(iface, bytes);
    pipe.deliver(fromLatin1('chatter'), { iface: IFACE.SEREMU });
    return n;
  };

  const app = await start(pipe);
  await assert.rejects(
    () => app.services.transport.request({
      iface: IFACE.VENDOR,
      data: Uint8Array.from([1]),
      timeoutMs: 120,
    }),
    /no reply on interface 2/,
  );
  await app.destroy();
});

/* ------------------------------------------------------------ the echo */

test('a host-bound echo is reported as a write, not as a reply', async () => {
  // A USB pipe only sees inbound traffic, so the host echoes its own writes to
  // keep `dir` meaning the same thing on both pipes. Treating one as a reply
  // would make every request resolve with the bytes it just sent.
  const pipe = fakePipe({ autoStart: true });
  const app = await start(pipe);

  const writes = [];
  const reports = [];
  app.services.transport.on('write', (e) => writes.push(e));
  app.services.transport.on('report', (e) => reports.push(e));

  /*
   * The fake echoes every write with dir IN, exactly as the emulator HAL
   * does - so writing is how the echo is produced, and no hand-made event
   * is needed.
   */
  await app.services.transport.write(IFACE.VENDOR, Uint8Array.from([7]));

  assert.equal(writes.length, 1);
  assert.equal(reports.length, 0, 'an echo must never look like an answer');
  await app.destroy();
});
