'use strict';
/* The wire envelope (Brad, 2026-10-06): every message names its sender and itself; an answer names the request. */
const test = require('node:test');
const assert = require('node:assert');
const wire = require('../src/wire');

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

/* THE TESTNET (BLOCKS.md §5; Brad, 2026-10-07): live and test never answer each other */
test('net: a request names its chain, and an answer from the other chain becomes a refusal - both ways', async () => {
  for (const [mine, theirs] of [['test', 'live'], ['live', 'test']]) {
    const t = fakeTransport();
    const ch = wire.createWireChannel(t, { timeoutMs: 2000, net: mine });
    const p = ch.send({ type: 'budget' });
    await tick();
    const req = t.lastRequest();
    assert.strictEqual(req.wire.net, mine);
    t.answer(wire.answerEnvelope(req, { ok: true, grantId: 7 }, { dev: 'phone', net: theirs }));
    const got = await p;
    assert.strictEqual(got.ok, false, `${mine} computer, ${theirs} phone`);
    assert.strictEqual(got.refusal, 'net');
    assert.match(got.detail, theirs === 'test' ? /on the testnet - add --test-mode/ : /on the live chain - drop --test-mode/);
  }
});

test('net: the same chain is answered; an older app (no net) counts as live', async () => {
  const t = fakeTransport();
  const ch = wire.createWireChannel(t, { timeoutMs: 2000, net: 'test' });
  const p = ch.send({ type: 'budget' });
  await tick();
  t.answer(wire.answerEnvelope(t.lastRequest(), { ok: true }, { dev: 'phone', net: 'test' }));
  assert.strictEqual((await p).ok, true);
  const t2 = fakeTransport();
  const live = wire.createWireChannel(t2, { timeoutMs: 2000 });
  const p2 = live.send({ type: 'budget' });
  await tick();
  t2.answer(wire.answerEnvelope(t2.lastRequest(), { ok: true }, { dev: 'phone' }));
  assert.strictEqual((await p2).ok, true, 'a live computer and an app that names no net');
});
