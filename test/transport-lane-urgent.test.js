'use strict';
/*
 * Rule 8 (Brad, 2026-10-06): a Hold or Revoke the person taps goes to the front
 * of the key's lane - behind the conversation already running, never into it.
 */
const test = require('node:test');
const assert = require('node:assert');
const { laneOf, inLane, urgentWaiting } = require('../src/transport/lane');

test('lane: an urgent conversation goes ahead of everything waiting, never into the one running', async () => {
  const transport = {};
  const lane = laneOf(transport);
  const order = [];
  let release;
  const first = lane(() => new Promise((r) => { order.push('computer start'); release = () => { order.push('computer end'); r(); }; }));
  const a = lane(async () => { order.push('sync a'); });
  const b = lane(async () => { order.push('sync b'); });
  assert.strictEqual(urgentWaiting(transport), false);
  const hold = inLane(transport, async () => { order.push('hold'); }, { urgent: true });
  const revoke = inLane(transport, async () => { order.push('revoke'); }, { urgent: true });
  assert.strictEqual(urgentWaiting(transport), true, 'the bridge can see an urgent conversation waiting');
  release();
  await Promise.all([first, a, b, hold, revoke]);
  assert.deepStrictEqual(order, ['computer start', 'computer end', 'hold', 'revoke', 'sync a', 'sync b']);
  assert.strictEqual(urgentWaiting(transport), false);
});

test('lane: an idle lane still runs at once, in the same tick', () => {
  const lane = laneOf({});
  let ran = false;
  lane(() => { ran = true; return Promise.resolve(); });
  assert.strictEqual(ran, true);
});

test('lane: a conversation that throws does not stop the ones behind it', async () => {
  const lane = laneOf({});
  const order = [];
  const x = lane(async () => { throw new Error('refused'); });
  const y = lane(async () => { order.push('y'); });
  await assert.rejects(x, /refused/);
  await y;
  assert.deepStrictEqual(order, ['y']);
});
