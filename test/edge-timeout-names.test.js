'use strict';
/*
 * A TIMED-OUT REQUEST NAMES WHAT CAME INSTEAD. The A13's slow answers
 * (2026-10-05) could not be told apart from "no answer" alone: nothing at all,
 * another request's answer, or the phone's own traffic. The timeout now lists
 * the vendor reports the request passed over.
 */
const test = require('node:test');
const assert = require('node:assert');
const { IFACE } = require('../src/protocol/msg');
const { edgeOver, report } = require('./helpers/fake-edge-key');

/* a key that answers every write with what `replies` gives, never with a HEAD */
function strayKey(replies) {
  const listeners = new Set();
  return {
    open() {}, close() {}, isOpen: () => true, request() { throw new Error('not used'); },
    on(event, fn) { if (event === 'report') { listeners.add(fn); return () => listeners.delete(fn); } return () => {}; },
    write() {
      for (const r of replies()) setTimeout(() => listeners.forEach((l) => l({ iface: IFACE.VENDOR, data: r })), 1);
    },
  };
}

test('a timeout with nothing on the line says nothing arrived', async () => {
  const edge = edgeOver(strayKey(() => []));
  await assert.rejects(edge.head({ timeoutMs: 150 }), (e) => {
    assert.equal(e.code, 'ETIMEDOUT');
    assert.match(e.message, /nothing arrived/);
    assert.deepEqual(e.passed, []);
    return true;
  });
});

test('a timeout names the broadcast and the report that was not this request\'s', async () => {
  const notHead = report([0xde, 0xad, 0xbe, 0xef]);
  notHead[61] = 2; /* fails the HEAD shape check: an unknown capability bit (bit 0 is R13b) */
  const edge = edgeOver(strayKey(() => [report([...Buffer.from('UNLOCKEDv3.1.0-testc')]), notHead]));
  await assert.rejects(edge.head({ timeoutMs: 150 }), (e) => {
    assert.equal(e.code, 'ETIMEDOUT');
    assert.match(e.message, /meanwhile: broadcast "UNLOCKEDv3\.1\.0-testc", not-ours deadbeef0000/);
    assert.equal(e.passed.length, 2);
    return true;
  });
});
