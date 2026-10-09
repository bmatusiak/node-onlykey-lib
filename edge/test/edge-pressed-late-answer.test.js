'use strict';
/*
 * A LATE ANSWER IS NOT A PRESSED REQUEST'S ANSWER. On the A13 (2026-10-04) an
 * agent registration waited on a slow press, took another report as its
 * answer, and found a link that was not the registration ("invalid") - though
 * the key had written it. A pressed request that writes a link now takes only
 * a seq above the key's seq from before it.
 */
const test = require('node:test');
const assert = require('node:assert');
const { chain, codes } = require('../src');
const { fakeKey, edgeOver, report, u32 } = require('./helpers/fake-edge-key');

/* the fake key, plus `stale` reports sent ahead of the answer to the first request with sub `onSub` */
function lateAnswerKey(onSub) {
  const key = fakeKey();
  const extra = new Set();
  let stale = null;
  return {
    ...key,
    setStale(r) { stale = r; },
    on(ev, fn) {
      const off = key.on(ev, fn);
      if (ev === 'report') extra.add(fn);
      return () => { off(); extra.delete(fn); };
    },
    write(iface, frame) {
      if (stale && frame[5] === onSub) {
        const r = stale;
        stale = null;
        extra.forEach((l) => l({ iface, data: r })); /* before the key's own answer */
      }
      return key.write(iface, frame);
    },
  };
}

/* a pressed LOSS stands in for the retired registration (2026-10-08): the same newLink wait */
test('a stale seq . head during the press wait is passed over; the loss gets its own link', async () => {
  const t = lateAnswerKey(0x34);
  const edge = edgeOver(t);
  const v = await edge.head(); /* what a late RECEIPT / WAIVE answer looks like: the key's current seq . head */
  t.setStale(report([...u32(v.seq), ...v.head]));
  const r = await edge.loss({ from: 0, to: 0, timeoutMs: 2000 });
  assert.equal(r.seq, v.seq + 1);
  const [l] = await edge.pickup(r.seq, 1);
  assert.equal(chain.decodeLink(l.link).op, codes.OP.LOSS);
});

test('a late HEAD answer during the press wait is passed over too', async () => {
  const t = lateAnswerKey(0x34);
  const edge = edgeOver(t);
  const h = await edge.head();
  const late = report([...u32(h.seq), ...h.head]); /* a HEAD with nothing live: zeros past the head */
  t.setStale(late);
  const r = await edge.loss({ from: 0, to: 0, timeoutMs: 2000 });
  assert.equal(r.seq, h.seq + 1);
});

test('a press the key refuses ("Error button press was not accepted") ends the request as a timeout, never as a seq', async () => {
  /* the core closed its 20 s wait; the press after it was refused in a sentence (Pixel, 2026-10-05) */
  const t = lateAnswerKey(0x34);
  const edge = edgeOver(t);
  t.setStale(report([...Buffer.from('Error button press was not accepted')]));
  await assert.rejects(edge.loss({ from: 0, to: 0, timeoutMs: 2000 }), (e) => {
    assert.equal(e.code, 'ETIMEDOUT');
    assert.equal(e.keyText, 'Error button press was not accepted');
    return true;
  });
});

/* was "a registration whose press ..." until 2026-10-08 (Brad: "lets cut it out"): a budget request's press now */
test('a budget request whose press the key refused says so - not "invalid", not "nobody pressed"', async () => {
  const { request, approve } = require('../src');
  const t = lateAnswerKey(0x10);
  const edge = edgeOver(t);
  await edge.receipt(0, 0, new Uint8Array(32)); /* nothing owed: the grant reaches the key */
  t.setStale(report([...Buffer.from('Error button press was not accepted')]));
  const msg = await request.build({ reason: 'late presser', scopes: [{ op: 'sign', slot: 1, cap: 1 }], lifetime: 10 });
  const r = await approve.approveRequest(msg, {
    edge, from: 'pc-nitro16', seen: new Set(), ask: async () => 'approve',
    verifyCopy: async () => ({ ok: true, head: (await edge.head()).head }), timeoutMs: 2000,
  });
  assert.equal(r.refusal, 'timeout');
  assert.match(r.detail || r.reason || JSON.stringify(r), /refused the press .*20 s/);
});
