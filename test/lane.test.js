/*
 * ONE LANE PER KEY (src/transport/lane.js): one conversation with the key at
 * a time, because its replies carry no request id. Measured on the phones
 * (2026-10-03): a background Edge sync and a test's grant swapped answers; Key
 * Chain's slot reads and a sync made slots read "unknown" and the wrong type.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { laneOf, inLane } = require('../src/transport/lane');
const { createPipeTransport } = require('../src/transport/pipeTransport');

const tick = (ms) => new Promise((r) => setTimeout(r, ms));

test('lane: conversations never overlap - the second starts only when the first has settled', async () => {
  const t = {};
  const log = [];
  const talk = (name, ms) => inLane(t, async () => {
    log.push(`${name} start`);
    await tick(ms);
    log.push(`${name} end`);
    return name;
  });
  const results = await Promise.all([talk('a', 30), talk('b', 5), talk('c', 1)]);
  assert.deepEqual(results, ['a', 'b', 'c']);
  assert.deepEqual(log, ['a start', 'a end', 'b start', 'b end', 'c start', 'c end']);
});

test('lane: an idle lane runs the conversation in the same tick; a failed one does not block the next', async () => {
  const t = {};
  let ran = false;
  const p = inLane(t, async () => { ran = true; });
  assert.equal(ran, true, 'an idle lane must not add a tick before the conversation subscribes');
  await p;
  await assert.rejects(inLane(t, async () => { throw new Error('refused'); }), /refused/);
  assert.equal(await inLane(t, async () => 'next'), 'next');
  assert.equal(laneOf(t), laneOf(t), 'one lane per transport');
  assert.notEqual(laneOf(t), laneOf({}), 'and only per transport');
});

/*
 * The swap, end to end on a real pipeTransport: a key whose answer to each
 * request comes some time after it (a press, BLE latency). Two callers ask at
 * once; each must get ITS answer.
 */
test('lane: two callers on one key each get their own answer, even when the first waits on a press', async () => {
  const listeners = new Set();
  const pipe = {
    start() {}, stop() {}, isRunning() { return true; },
    /* the pipe contract: on('stream', cb) carries {iface, dir, bytes} both ways */
    on(event, cb) { listeners.add(cb); return () => listeners.delete(cb); },
    write(iface, bytes) {
      /* the key answers "<request byte> done" - the first one after a 40 ms press */
      const asked = bytes[0];
      const answer = Uint8Array.from([asked, 0xaa]);
      setTimeout(() => listeners.forEach((cb) => cb({ iface, dir: 0, bytes: answer })), asked === 1 ? 40 : 2);
      listeners.forEach((cb) => cb({ iface, dir: 1, bytes }));
      return Promise.resolve();
    },
  };
  const { transport, destroy } = createPipeTransport({ name: 'lane-test', pipe, EventEmitter: require('events') });
  await transport.open();
  /* a conversation the way the plugins write one: listen, write, wait for the answer */
  const conversation = (n) => inLane(transport, () => new Promise((resolve) => {
    const off = transport.on('report', (e) => {
      if (e.iface !== 2) return;
      off();
      resolve(e.data[0]);
    });
    transport.write(2, Uint8Array.from([n]));
  }));
  const [first, second] = await Promise.all([conversation(1), conversation(2)]);
  assert.equal(first, 1, 'the slow request read another caller\'s answer');
  assert.equal(second, 2, 'the fast request read another caller\'s answer');
  /* and request() takes the same lane */
  const viaRequest = await Promise.all([conversation(1), transport.request({ iface: 2, data: Uint8Array.from([2]), timeoutMs: 500 })]);
  assert.equal(viaRequest[0], 1);
  assert.equal(viaRequest[1][0], 2);
  await destroy();
});
