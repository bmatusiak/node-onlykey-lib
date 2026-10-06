'use strict';
/* The wire envelope (Brad, 2026-10-06): every message names its sender and itself; an answer names the request. */
const test = require('node:test');
const assert = require('node:assert');
const wire = require('../src/edge/wire');

function fakeTransport() {
  let listener = null;
  const sent = [];
  return {
    sent,
    on(event, cb) { if (event === 'report') listener = cb; return () => { listener = null; }; },
    async write(_iface, frame) { sent.push(frame); },
    answer(message) { for (const f of wire.encode(wire.KIND.ANSWER, message)) listener && listener({ iface: 2, data: f }); },
    lastRequest() {
      const asm = wire.createAssembler();
      let got = null;
      for (const f of sent) got = asm.push(f) || got;
      return got && got.message;
    },
  };
}
const tick = () => new Promise((r) => setImmediate(r));

test('envelope: the request is stamped; a stale answer is dropped, the right one taken', async () => {
  const t = fakeTransport();
  const logs = [];
  const ch = wire.createWireChannel(t, { timeoutMs: 2000, device: 'pc-1', log: (l) => logs.push(l) });
  const p = ch.send({ type: 'note', x: 1 });
  await tick();
  const req = t.lastRequest();
  assert.strictEqual(req.wire.dev, 'pc-1');
  assert.match(req.wire.id, /^[0-9a-f]{16}$/);
  assert.strictEqual(typeof req.wire.ts, 'number');
  /* a late answer to an earlier request that gave up */
  t.answer({ ok: 'old', wire: { dev: 'phone', id: 'a', ts: 1, re: { dev: 'pc-1', id: '0000000000000000' } } });
  await tick();
  t.answer(wire.answerEnvelope(req, { ok: 'mine' }, { dev: 'phone' }));
  const got = await p;
  assert.strictEqual(got.ok, 'mine');
  assert.deepStrictEqual(got.wire.re, { dev: 'pc-1', id: req.wire.id });
  assert.ok(logs.some((l) => /stale answer/.test(l)));
});

test('envelope: an older app (no envelope in its answer) is still answered as before', async () => {
  const t = fakeTransport();
  const ch = wire.createWireChannel(t, { timeoutMs: 2000 });
  const p = ch.send({ type: 'note' });
  await tick();
  t.answer({ ok: 'legacy' });
  assert.strictEqual((await p).ok, 'legacy');
});

test('answerEnvelope: an older computer (no envelope) gets its answer unchanged', () => {
  assert.deepStrictEqual(wire.answerEnvelope({ type: 'note' }, { ok: 1 }, { dev: 'phone' }), { ok: 1 });
});
