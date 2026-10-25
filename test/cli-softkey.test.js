/*
 * --soft-key (cli/transport-softkey.js; Brad, 2026-10-25: "--soft-key will boot the same softkey the desktop app does
 * ... interactive to input pin code and send a 1-6 button press ... use stdio"): the desktop app's recorded soft key,
 * its PIN asked on the terminal and pressed, 1-6 + Enter pressing its buttons, the pipe contract of a hard key.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { PassThrough } = require('stream');
const { EventEmitter } = require('events');
const { createSoftKeyPipe, softKeyRecord, waitingFrom } = require('../cli/transport-softkey');

function fakeEmu() {
  const e = new EventEmitter();
  e.presses = [];
  e.writes = [];
  e.started = null;
  e.start = ({ storageDir }) => { e.started = storageDir; };
  e.stop = () => { e.started = null; };
  e.pressQueue = (digits, ticks) => { e.presses.push([digits, ticks]); return digits.length; };
  e.writeHid = (buf, iface) => e.writes.push(['plain', iface, buf.length]);
  e.writeHidTaken = async (buf, iface) => e.writes.push(['taken', iface, buf.length]);
  e.confirmState = () => -1;
  e.rounds = () => 100;
  e.pressPending = () => 0;
  return e;
}
const tick = (ms) => new Promise((r) => setTimeout(r, ms));

test('the recorded soft key is booted, its PIN asked and pressed, 1-6 + Enter press its buttons, reports and writes pass', async () => {
  const emu = fakeEmu();
  const input = new PassThrough();
  const output = new PassThrough();
  let said = '';
  output.on('data', (d) => { said += d; });
  const pipe = createSoftKeyPipe({ net: 'test', input, output, loadEmulator: () => emu, record: { storageDir: '/tmp/okemu/plugins-config.edge-test', emulator: '/x' } });
  const started = pipe.start();
  await tick(20);
  input.write('1234561\n');
  await started;
  assert.equal(emu.started, '/tmp/okemu/plugins-config.edge-test');
  assert.deepEqual(emu.presses[0], ['1234561', 10], 'the PIN pressed in, as taps');
  assert.match(said, /PIN \(digits 1-6/);
  assert.ok(!said.includes('1234561'), 'the PIN is never echoed');
  input.write('1\n');
  await tick(20);
  assert.deepEqual(emu.presses[1], ['1', 10]);
  input.write('9\n');
  await tick(20);
  assert.equal(emu.presses.length, 2, 'only 1-6 press');
  const seen = [];
  pipe.on('stream', (ev) => seen.push(ev));
  emu.emit('stream', { buffer: Buffer.from([1, 2]), iface: 2, dir: 'out' });
  assert.deepEqual(seen.map((e) => [e.iface, e.dir, e.bytes.length]), [[2, 0, 2]], 'dir as the lib numbers it: OUT 0');
  await pipe.write(2, new Uint8Array(64));
  await pipe.write(1, new Uint8Array(64));
  assert.deepEqual(emu.writes, [['taken', 2, 64], ['plain', 1, 64]], 'a vendor write waits until the firmware took it');
  assert.equal(pipe.interfaces()[0].iface, 2);
  await pipe.stop();
  assert.equal(emu.started, null);
});

test('no soft key recorded, or not for this net: says to start it once in the desktop app', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'okjs-softkey-'));
  assert.throws(() => softKeyRecord('live', home), /start the soft key once in the ok-edge desktop app/);
  fs.mkdirSync(path.join(home, '.onlykey-js'));
  fs.writeFileSync(path.join(home, '.onlykey-js', 'softkey.json'), JSON.stringify({ live: { storageDir: '/a', emulator: '/e' } }));
  assert.equal(softKeyRecord('live', home).storageDir, '/a');
  assert.throws(() => softKeyRecord('test', home), /testnet soft key yet/);
});

test('what the firmware waits for: a sign, an Edge approval; WebAuthn and nothing are not asked here', () => {
  const packed = (auth, opcode, mode) => (auth | (opcode << 8) | (mode << 24) | (1 << 27)) >>> 0;
  assert.deepEqual(waitingFrom(packed(1, 0xed, 1)), { what: 'a sign', code: false });
  assert.deepEqual(waitingFrom(packed(1, 0xf8, 0)), { what: 'an Edge approval', code: false });
  assert.equal(waitingFrom(packed(1, 0xf6, 1)), null);
  assert.equal(waitingFrom(-1), null);
});
