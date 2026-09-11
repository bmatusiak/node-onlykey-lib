'use strict';

/*
 * Firmware update, without a key.
 *
 * Nothing here has run on hardware, on purpose (src/device/firmware.js
 * says why). What CAN be pinned without one is the byte layout the desktop
 * sends and the conversation the firmware and bootloader hold - both read
 * from source - so the fake below answers exactly what okcore.cpp and the
 * desktop's listenForMessageIncludes expect, and the test asserts every
 * frame that reached it.
 */

const test = require('node:test');
const assert = require('node:assert');

const Rectify = require('@bmatusiak/rectify');
const hostPlugin = require('../plugins/host');
const embedded = require('../plugins/transport/embedded');
const sessionPlugin = require('../plugins/session');
const devicePlugin = require('../plugins/device');
const { fakePipe } = require('./helpers/fake-pipe');
const { IFACE, DIR } = require('../src/transport/contract');
const { MSG } = require('../src/protocol/msg');
const okmsg = require('../src/protocol/okmsg');
const firmware = require('../src/device/firmware');
const { toHex } = require('../src/bytes');

const BEGIN = '-----BEGIN SIGNED FIRMWARE-----';
const END = '-----END SIGNED FIRMWARE-----';

/** A block line: 64 hex of signature, 2 of info, 64 of next signature, then data - whole bytes. */
function block(dataBytes, n = 1) {
  const sig = (n.toString(16).padStart(2, '0')).repeat(32);
  const next = ((n + 1).toString(16).padStart(2, '0')).repeat(32);
  const data = Array.from({ length: dataBytes }, (_, i) => ((i + n) & 0xff).toString(16).padStart(2, '0')).join('');
  return `${sig}a0${next}${data}`;
}

/* ------------------------------------------------------------ the file */

test('a signed firmware file is its blocks, whole and in order', () => {
  const b1 = block(10, 1);
  const b2 = block(20, 2);
  assert.deepEqual(firmware.parseSignedFirmware(`${BEGIN}\n${b1}\n${b2}\n${END}\n`), [b1, b2]);
  /* Without the END marker every block is kept: the desktop's "drop the last line" is END going. */
  assert.deepEqual(firmware.parseSignedFirmware(`${BEGIN}\n${b1}\n${b2}\n`), [b1, b2]);
  /* CRLF and blank lines are not blocks. */
  assert.deepEqual(firmware.parseSignedFirmware(`\r\n${BEGIN}\r\n${b1}\r\n\r\n${END}\r\n`), [b1]);
});

test('a file that is not signed firmware, or has a block that is not hex, is refused before anything is sent', () => {
  assert.throws(() => firmware.parseSignedFirmware('hello'), /not a signed firmware file/);
  assert.throws(() => firmware.parseSignedFirmware(`${BEGIN}\n${END}`), /no blocks/);
  assert.throws(() => firmware.parseSignedFirmware(`${BEGIN}\n${block(4)}zz\n${END}`), /block 1 is not hex/);
  assert.throws(() => firmware.parseSignedFirmware(`${BEGIN}\nabcdef\n${END}`), /shorter than its two signatures/);
});

test('describeBlock reads the chain the way loadFirmware logs it', () => {
  const d = firmware.describeBlock(block(3, 7));
  assert.equal(d.signature, '07'.repeat(32));
  assert.equal(d.info, 'a0');
  assert.equal(d.nextSignature, '08'.repeat(32));
  assert.equal(d.bytes, (64 + 2 + 64 + 6) / 2);
});

/* ---------------------------------------------------------- the frames */

test('the kick is OKFWUPDATE with a length header of 2 and the bytes 12 34', () => {
  const frame = firmware.kickFrame();
  const expected = okmsg.build({ msg: MSG.OKFWUPDATE, payload: Uint8Array.from([2, 0x12, 0x34]) });
  assert.equal(toHex(frame), toHex(expected));
});

test('a block goes as 57-byte packets, 0xFF on all but the last, whose header is its length', () => {
  const line = block(50);
  /* The line is hex; its byte length decides the split. */
  const bytes = line.length / 2;
  const frames = firmware.blockFrames(line);
  const full = Math.floor(bytes / 57);
  const rest = bytes % 57;
  assert.equal(frames.length, full + (rest ? 1 : 0));
  frames.forEach((f, i) => {
    const header = f.frame[5];
    const last = i === frames.length - 1;
    assert.equal(f.final, last);
    assert.equal(header, last ? (rest || 57) : 0xff, `packet ${i} header`);
    assert.equal(f.frame[4], MSG.OKFWUPDATE);
  });
  /* Reassembled, the packets are the line. */
  const joined = frames.map((f) => toHex(f.frame.subarray(6, 6 + f.bytes))).join('');
  assert.equal(joined, line.toLowerCase());
});

/* ---------------------------------------------------- the conversation */

/**
 * A device that speaks the firmware half of okcore.cpp and the bootloader.
 * `mode` is what it is right now; the kick flips it the way CPU_RESTART
 * would, minus the re-enumeration.
 */
function fakeUpdatableKey({ configMode = true, blocks = 2 } = {}) {
  const pipe = fakePipe({ autoStart: true });
  const state = { mode: 'firmware', configMode, kicked: 0, packets: [], blocksDone: 0 };
  const say = (text) => {
    const bytes = new Uint8Array(64);
    for (let i = 0; i < text.length && i < 64; i++) bytes[i] = text.charCodeAt(i) & 0xff;
    pipe.deliver(bytes);
  };
  pipe.on('stream', ({ iface, dir, bytes }) => {
    if (iface !== IFACE.VENDOR || dir !== DIR.IN) return;
    if (bytes[4] !== MSG.OKFWUPDATE) return;
    const header = bytes[5];
    if (state.mode === 'firmware') {
      if (!state.configMode) return say('Error not in config mode');
      state.kicked += 1;
      state.mode = 'bootloader';
      return say('SUCCESSFULL FW LOAD REQUEST, REBOOTING...');
    }
    /* bootloader: one packet, one RECEIVED; a final packet also ends a block */
    const len = header === 0xff ? 57 : header;
    state.packets.push(toHex(bytes.subarray(6, 6 + len)));
    say('RECEIVED OKFWUPDATE');
    if (header !== 0xff) {
      state.blocksDone += 1;
      setTimeout(() => say(state.blocksDone < blocks ? 'NEXT BLOCK' : 'SUCCESSFULLY LOADED FW'), 5);
    }
    return undefined;
  });
  return { pipe, state };
}

function start(pipe) {
  const plugins = [hostPlugin, embedded, sessionPlugin, devicePlugin];
  plugins.config = { transport: { pipe } };
  return new Promise((resolve, reject) => {
    const app = Rectify.build(plugins, (err, started) => (err ? reject(err) : resolve(started)));
    app.start();
  });
}

test('requestFirmwareUpdate sends the kick and reports the reboot; outside config mode the refusal is the error', async () => {
  const ok = fakeUpdatableKey({ configMode: true });
  const app = await start(ok.pipe);
  const said = await app.services.device.requestFirmwareUpdate({ timeoutMs: 1000 });
  assert.match(said, /FW LOAD REQUEST/);
  assert.equal(ok.state.kicked, 1);
  assert.equal(ok.state.mode, 'bootloader');

  const no = fakeUpdatableKey({ configMode: false });
  const app2 = await start(no.pipe);
  await assert.rejects(
    () => app2.services.device.requestFirmwareUpdate({ timeoutMs: 1000 }),
    /Error not in config mode/,
  );
  assert.equal(no.state.kicked, 0);
});

test('sendFirmware streams every block, waits for each packet and each block, and ends on SUCCESSFULLY LOADED FW', async () => {
  const b1 = block(70, 1);   // 135 bytes: three packets
  const b2 = block(10, 2);   // 75 bytes: two packets
  const ok = fakeUpdatableKey({ configMode: true, blocks: 2 });
  ok.state.mode = 'bootloader';
  const app = await start(ok.pipe);
  const seen = [];
  const result = await app.services.device.sendFirmware(`${BEGIN}\n${b1}\n${b2}\n${END}`, {
    onProgress: (p) => seen.push(p),
    packetTimeoutMs: 1000,
    blockTimeoutMs: 1000,
  });
  assert.deepEqual(result, { blocks: 2 });
  assert.equal(ok.state.packets.join(''), (b1 + b2).toLowerCase());
  assert.deepEqual(seen.map((p) => [p.block, p.of, p.packet, p.packets]), [
    [1, 2, 1, 3], [1, 2, 2, 3], [1, 2, 3, 3], [2, 2, 1, 2], [2, 2, 2, 2],
  ]);
});

test('sendFirmware stops at the first packet the bootloader does not acknowledge', async () => {
  const b1 = block(10, 1);
  const pipe = fakePipe({ autoStart: true });   // answers nothing at all
  const app = await start(pipe);
  await assert.rejects(
    () => app.services.device.sendFirmware(`${BEGIN}\n${b1}\n${END}`, { packetTimeoutMs: 200, blockTimeoutMs: 200 }),
    /block 1 packet 1 was not acknowledged/,
  );
  assert.equal(pipe.writes.filter((w) => w.iface === IFACE.VENDOR).length, 1);
});
