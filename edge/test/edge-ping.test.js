'use strict';
/* okedge ping (Brad, 2026-10-06): random bytes to the phone and back, checked by their SHA-256. */
const test = require('node:test');
const assert = require('node:assert');
const { ping, client } = require('../src');

test('ping: the phone echoes id and data; the answer is checked byte for byte', () => {
  const data = Uint8Array.from({ length: 3000 }, (_, i) => (i * 7) & 255);
  const msg = ping.buildPing(data);
  assert.deepStrictEqual(ping.checkPong(msg, ping.answerPing(msg)), { ok: true, bytes: 3000 });
  const pong = ping.answerPing(msg);
  assert.match(ping.checkPong(msg, { ...pong, id: 'f'.repeat(64) }).why, /different id/);
  const flipped = { ...pong, data: Buffer.from(Buffer.from(pong.data, 'base64').map((b, i) => (i === 100 ? b ^ 1 : b))).toString('base64') };
  assert.match(ping.checkPong(msg, flipped).why, /came back changed/);
  assert.strictEqual(ping.answerPing({ type: 'note' }), null, 'only a ping is echoed');
  assert.strictEqual(ping.answerPing({ type: 'ping', id: 'x', data: '' }), null, 'a malformed ping is not');
  assert.throws(() => ping.buildPing(new Uint8Array(ping.PING_MAX + 1)), /at most/);
});

test('client.ping: OK through an echoing phone; a changed byte and silence are reported', async () => {
  const echo = { send: async (m) => ping.answerPing(m) };
  const c = client.createEdgeClient({ edge: {}, channel: echo, signer: null });
  const r = await c.ping({ size: 2048 });
  assert.strictEqual(r.exact, true);
  assert.strictEqual(r.bytes, 2048);
  assert.ok(r.wire > 2048, 'base64 + JSON on the wire');
  const liar = { send: async (m) => ({ ...ping.answerPing(m), data: ping.answerPing(m).data.replace(/^.{4}/, 'AAAA') }) };
  assert.match((await client.createEdgeClient({ edge: {}, channel: liar, signer: null }).ping({ size: 64 })).why, /changed/);
  let waited = null;
  const silent = { send: async (_m, o) => { waited = o && o.timeoutMs; return null; } };
  const s = await client.createEdgeClient({ edge: {}, channel: silent, signer: null }).ping({ size: 64 });
  assert.strictEqual(s.exact, false);
  assert.match(s.why, /no answer/);
  assert.strictEqual(waited, 10000, 'a ping waits seconds, not the sheet\'s minutes');
});
