'use strict';
/*
 * BUG 1 (2026-10-05): the Edge plugin wrapped its write in a plain try/catch,
 * but a pipe's write is a promise - a refused Bluetooth write rejected with
 * nobody listening, and Node ended the edge-agent for it. The request must
 * fail on its own, and the process must not see an unhandled rejection.
 */
const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('events');
const setup = require('../plugins/edge');

test('a write the pipe refuses fails ITS request - no unhandled rejection, the service lives on', async () => {
  const unhandled = [];
  const onUnhandled = (e) => unhandled.push(e);
  process.on('unhandledRejection', onUnhandled);
  try {
    const events = new EventEmitter();
    const transport = {
      name: 'fake',
      open: async () => {}, close: async () => {}, isOpen: () => true, request: async () => { throw new Error('unused'); },
      on: (ev, l) => { events.on(ev, l); return () => events.removeListener(ev, l); },
      write: () => Promise.reject(Object.assign(new Error('the phone did not take the write: status: 3'), { code: 'EWRITE' })),
    };
    let edge = null;
    setup({ transport }, (err, s) => { if (err) throw err; edge = s.edge; });
    await assert.rejects(() => edge.head({ timeoutMs: 2000 }), (e) => e.code === 'EWRITE' && /status: 3/.test(e.message));
    /* a second request is still answered the same way: nothing was left wedged */
    await assert.rejects(() => edge.head({ timeoutMs: 2000 }), (e) => e.code === 'EWRITE');
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(unhandled, [], 'a refused write escaped as an unhandled rejection');
  } finally {
    process.removeListener('unhandledRejection', onUnhandled);
  }
});

test('the answer clock starts when the write has gone out - a write that reconnects first is not timed out', async () => {
  const events = new EventEmitter();
  const head = new Uint8Array(64); /* a HEAD reply: seq 0, a zero head */
  const transport = {
    name: 'fake',
    open: async () => {}, close: async () => {}, isOpen: () => true, request: async () => { throw new Error('unused'); },
    on: (ev, l) => { events.on(ev, l); return () => events.removeListener(ev, l); },
    /* 400 ms to go out (a reconnect), then the phone answers at once */
    write: () => new Promise((r) => setTimeout(() => { r(64); setImmediate(() => events.emit('report', { iface: 2, data: head })); }, 400)),
  };
  let edge = null;
  setup({ transport }, (err, s) => { if (err) throw err; edge = s.edge; });
  const h = await edge.head({ timeoutMs: 200 });
  assert.equal(h.seq, 0);
});
