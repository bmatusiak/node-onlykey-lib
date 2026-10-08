/*
 * Edge against a HALTED soft key (Brad, 2026-10-07): the A13 had logged itself
 * out (ok-rn's inactivity lockout halts the soft key until ok-rn restarts) and
 * `edge budget` said only "no reply on interface 2 within 3000ms", three times.
 * Every Edge connect now checks the key answered and is open, so the agent can
 * tell Brad what to do. The bridge's sentence: ok-rn vendorBridge.ts KEY_STOPPED.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { main } = require('../../cli/index');
const { startDesktop } = require('../../cli/desktop');
const { fakePipe } = require('../../test/helpers/fake-pipe');
const { IFACE } = require('../../src/transport/contract');

const KEY_STOPPED = 'Error soft key stopped, restart ok-rn on the phone';

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

test('edge register against a halted soft key: stops at connect and says to restart ok-rn', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'edge-halted-'));
  const out = [];
  const err = [];
  try {
    const code = await main(['edge', '--edge-home', home, 'register', 'test-agent', '--ssh', 'ssh://claude@test', '--gpg', 'Claude <claude@test>'], {
      out: (l) => out.push(l),
      err: (l) => err.push(l),
      start: (opts) => startDesktop({ ...opts, pipe: haltedPhone() }),
    });
    assert.equal(code, 1);
    assert.match(err.join('\n'), /soft key on the phone has stopped/);
    assert.match(err.join('\n'), /Restart ok-rn on the phone and log in/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
