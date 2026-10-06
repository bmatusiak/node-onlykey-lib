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
const { chain, codes } = require('../src/edge');
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

test('a stale seq . head . tag during the press wait is passed over; the registration gets its own link', async () => {
  const t = lateAnswerKey(0x15);
  const edge = edgeOver(t);
  const v = await edge.vouch(); /* what a late TICKET / WAIVE answer looks like: the key's current seq . head . tag */
  t.setStale(report([...u32(v.seq), ...v.head, ...v.tag]));
  const r = await edge.agentAdd(new Uint8Array(32).fill(7), { timeoutMs: 2000 });
  assert.equal(r.seq, v.seq + 1);
  const [l] = await edge.pickup(r.seq, 1);
  assert.equal(chain.decodeLink(l.link).op, codes.OP.AGENT_ADD);
});

test('a late HEAD answer during the press wait is passed over too', async () => {
  const t = lateAnswerKey(0x15);
  const edge = edgeOver(t);
  const h = await edge.head();
  const late = report([...u32(h.seq), ...h.head]); /* a HEAD with nothing live: zeros past the head */
  t.setStale(late);
  const r = await edge.agentAdd(new Uint8Array(32).fill(9), { timeoutMs: 2000 });
  assert.equal(r.seq, h.seq + 1);
});

test('a press the key refuses ("Error button press was not accepted") ends the request as a timeout, never as a seq', async () => {
  /* the core closed its 20 s wait; the press after it was refused in a sentence (Pixel, 2026-10-05) */
  const t = lateAnswerKey(0x15);
  const edge = edgeOver(t);
  t.setStale(report([...Buffer.from('Error button press was not accepted')]));
  await assert.rejects(edge.agentAdd(new Uint8Array(32).fill(5), { timeoutMs: 2000 }), (e) => {
    assert.equal(e.code, 'ETIMEDOUT');
    assert.equal(e.keyText, 'Error button press was not accepted');
    return true;
  });
});

test('a registration whose press the key refused says so - not "invalid", not "nobody pressed"', async () => {
  const { request, approve } = require('../src/edge');
  const t = lateAnswerKey(0x15);
  const edge = edgeOver(t);
  t.setStale(report([...Buffer.from('Error button press was not accepted')]));
  const signer = request.signerFromSecret(new Uint8Array(32).fill(33));
  const msg = await request.buildRegister({ signer, name: 'late presser' });
  const r = await approve.approveRegister(msg, { edge, seen: new Set(), ask: async () => 'approve', timeoutMs: 2000 });
  assert.equal(r.refusal, 'timeout');
  assert.match(r.detail || r.reason || JSON.stringify(r), /refused the press .*20 s/);
});
