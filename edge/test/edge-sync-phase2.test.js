'use strict';
/*
 * onlykey-js edge sync phase 2 (Brad, 2026-10-05): a place that keeps copies fills the
 * phone's copy; only a place on the key's list; a sheet, Yes, a press, and a
 * `sync` link whose subject is SHA256 of what moved; a fork stops it.
 */
const test = require('node:test');
const assert = require('node:assert');
const { codes, chain, request, approve, sync } = require('../src');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { fakeKey, edgeOver, DEVICE } = require('./helpers/fake-edge-key');

const signer = () => request.peerSignerFromSecret(p256.utils.randomSecretKey());
const hex = (b) => Buffer.from(b).toString('hex');

/* a little chain of n links, the way the key writes them */
function links(n, deviceId = DEVICE) {
  let head = chain.genesis(deviceId);
  const out = [];
  for (let seq = 0; seq < n; seq += 1) {
    const link = chain.encodeLink({ seq, op: codes.OP.SIGN, decision: 1, slot: 2, flags: 1, grantId: 0, subject: new Uint8Array(32).fill(seq + 1) });
    head = chain.weld(head, link);
    out.push({ link, head, reveal: null });
  }
  return out;
}

test('messages: signed by the place\'s key; a changed payload, another key or a replay is dropped', async () => {
  const s = signer();
  const have = await sync.buildHave({ signer: s, deviceId: DEVICE, name: 'NITRO16 copies' });
  assert.deepEqual(sync.verify(have), { ok: true });
  assert.equal(sync.verify({ ...have, payload: { ...have.payload, name: 'someone else' } }).reason, 'bad-signature');
  assert.equal(sync.verify({ ...have, peer: hex(signer().publicKey) }).reason, 'bad-signature');
  assert.equal(sync.verify(have, { seen: new Set([have.nonce]) }).reason, 'replayed');
  const msgs = await sync.buildLinks({ signer: s, deviceId: DEVICE, records: links(90) });
  assert.equal(msgs.length, 3, '90 links go in batches of 40');
  assert.ok(msgs.every((m) => sync.verify(m).ok && m.payload.sid === msgs[0].payload.sid && m.payload.parts === 3));
  assert.deepEqual(msgs.map((m) => m.payload.links.length), [40, 40, 10]);
  const tampered = JSON.parse(JSON.stringify(msgs[1]));
  tampered.payload.links[0][0] = '00'.repeat(64);
  assert.equal(sync.verify(tampered).reason, 'bad-signature', 'a link swapped in transit passed');
  assert.deepEqual(sync.recordsOf(msgs[2]).map((r) => chain.decodeLink(r.link).seq), [80, 81, 82, 83, 84, 85, 86, 87, 88, 89]);
});

test('ranges and what the phone lacks: only the gaps are sent', () => {
  const all = links(12);
  assert.deepEqual(sync.rangesOf([0, 1, 2, 5, 6, 9]), [[0, 2], [5, 6], [9, 9]]);
  const lacks = sync.missing(all, [[0, 2], [5, 6], [9, 9]]);
  assert.deepEqual(lacks.map((r) => chain.decodeLink(r.link).seq), [3, 4, 7, 8, 10, 11]);
});

test('merge: gaps filled in seq order; a link that disagrees with the phone\'s is a fork, never chosen between', () => {
  const all = links(10);
  const phone = [all[0], all[1], all[5], all[6]];
  const m = sync.merge(phone, all);
  assert.deepEqual(m.links.map((r) => chain.decodeLink(r.link).seq), [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.deepEqual(m.added.map((r) => chain.decodeLink(r.link).seq), [2, 3, 4, 7, 8, 9]);
  assert.deepEqual(m.conflicts, []);
  const other = links(10, new Uint8Array(16).fill(7)); /* the same seqs, other bytes */
  const forked = sync.merge(phone, [other[1], all[2]]);
  assert.deepEqual(forked.conflicts, [1]);
});
