/*
 * A HALTED SOFT KEY (Brad, 2026-10-07: "the cli should see what the issue is,
 * so the ai agent can say"). ok-rn's soft key halts on its inactivity lockout
 * (CPU_RESTART) and stays gone until ok-rn restarts. Its Bluetooth bridge then
 * answers every vendor request with one text report (ok-rn vendorBridge.ts
 * KEY_STOPPED). Before, the request went into the dead firmware and the CLI
 * said "no reply on interface 2 within 3000ms" - the A13 that evening.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { main } = require('../cli/index');
const { startDesktop } = require('../cli/desktop');
const { fakePipe } = require('./helpers/fake-pipe');
const { IFACE } = require('../src/transport/contract');
const okmsg = require('../src/protocol/okmsg');

/* ok-rn src/vendorBridge.ts KEY_STOPPED - the same sentence, word for word */
const KEY_STOPPED = 'Error soft key stopped, restart ok-rn on the phone';

/* the bridge in front of a halted soft key: every vendor write is answered with KEY_STOPPED */
function haltedPhone() {
  const pipe = fakePipe({ autoStart: true });
  const write = pipe.write;
  pipe.write = async (iface, bytes) => {
    const n = await write(iface, bytes);
    if (iface === IFACE.VENDOR) setImmediate(() => pipe.deliverText(KEY_STOPPED, { iface: IFACE.VENDOR }));
    return n;
  };
  return pipe;
}

async function run(argv) {
  const out = [];
  const err = [];
  const code = await main(argv, {
    out: (line) => out.push(line),
    err: (line) => err.push(line),
    start: (opts) => startDesktop({ ...opts, pipe: haltedPhone() }),
  });
  return { code, out, err };
}

test('the bridge\'s sentence is a refusal of its own kind: stopped', () => {
  assert.equal(okmsg.errorKind(KEY_STOPPED), 'stopped');
  assert.ok(KEY_STOPPED.length < 64, 'one report');
});

test('a halted soft key: the command stops at connect and says to restart ok-rn', async () => {
  for (const argv of [['getlabels'], ['status']]) {
    const r = await run(argv);
    assert.equal(r.code, 1, argv.join(' '));
    assert.deepEqual(r.out, [], argv.join(' '));
    assert.match(r.err.join('\n'), /soft key on the phone has stopped/, argv.join(' '));
    assert.match(r.err.join('\n'), /Restart ok-rn on the phone and log in/, argv.join(' '));
  }
});
