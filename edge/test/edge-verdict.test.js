'use strict';

/*
 * The verdict on a copy (edge/src/verdict.js; S4 step 2, 2026-11-02): the app's check, pure, with a state a host can
 * keep. Each path: a full check; the same head and copy skipped; only the new links after it grew; the state through
 * JSON (a restart) still skips; no checkpoint -> unsigned, never kept; a bad checkpoint -> tampered, never kept; a gap
 * under a signed checkpoint is history not here; a changed link is tampered; no head -> not-synced.
 */
const test = require('node:test');
const assert = require('node:assert');
const chain = require('../src/chain');
const { OP, DECISION } = require('../src/codes');
const { verdict, digestOf } = require('../src/verdict');
const K = require('./helpers/hybrid-key').edgeKey(new Uint8Array(32).fill(9));

const b32 = (n) => new Uint8Array(32).fill(n % 256);
const N = 40;
const opOf = (seq) => [OP.GRANT_CREATE, OP.SIGN, OP.RECEIPT][seq % 3];
const links = Array.from({ length: N }, (_, seq) => chain.encodeLink({
  seq, op: opOf(seq), decision: opOf(seq) === OP.SIGN ? DECISION.SELF_PRESS : DECISION.APPROVE, subject: b32(seq + 1), grantId: 1 + Math.floor(seq / 3), version: 1,
}));
const heads = chain.heads(links, chain.genesis(K.deviceId));
const recs = (from, upTo) => links.slice(from, upTo + 1).map((l, i) => ({ link: l, head: heads[from + i] }));
const copyOf = (from, upTo, extra = {}) => ({ deviceId: K.deviceId, links: recs(from, upTo), seals: [], ...extra });
const headAt = (seq) => ({ seq, head: heads[seq], ringFrom: seq + 1 });
const keyAt = (seq) => ({ publicKey: K.publicKey, publicKeyPq: K.publicKeyPq, checkpoint: K.checkpoint({ seq, head: heads[seq] }) });

test('a full check, then the same head and copy skipped, then only the new links', () => {
  const first = verdict(copyOf(0, 30), headAt(30), keyAt(30));
  assert.equal(first.verdict.kind, 'verified');
  assert.equal(first.path, 'full');
  assert.ok(first.state);
  const again = verdict(copyOf(0, 30), headAt(30), keyAt(30), { prev: first.state });
  assert.equal(again.path, 'skipped');
  assert.deepEqual(again.verdict, first.verdict);
  const grown = verdict(copyOf(0, 35), headAt(35), keyAt(35), { prev: first.state });
  assert.equal(grown.path, 'new-links');
  assert.equal(grown.verdict.kind, 'verified');
  assert.equal(grown.verdict.through, 35);
});

test('the state survives JSON - a restart skips as the same session would', () => {
  const first = verdict(copyOf(0, 30), headAt(30), keyAt(30));
  const kept = JSON.parse(JSON.stringify(first.state));
  assert.equal(verdict(copyOf(0, 30), headAt(30), keyAt(30), { prev: kept }).path, 'skipped');
  /* the digest follows the links, not the objects holding them */
  assert.equal(kept.digest, digestOf(copyOf(0, 30).links));
});

test('no checkpoint: unsigned, and nothing kept', () => {
  const r = verdict(copyOf(0, 30), headAt(30), { publicKey: K.publicKey, publicKeyPq: K.publicKeyPq });
  assert.equal(r.verdict.kind, 'unsigned');
  assert.equal(r.state, null);
});

test('a checkpoint that does not verify with both halves: tampered (bad-checkpoint), nothing kept', () => {
  const key = keyAt(30);
  key.checkpoint = { ...key.checkpoint, signaturePq: new Uint8Array(key.checkpoint.signaturePq.length) };
  const r = verdict(copyOf(0, 30), headAt(30), key);
  assert.deepEqual(r.verdict, { kind: 'tampered', seq: 30, reason: 'bad-checkpoint' });
  assert.equal(r.state, null);
});

test('a gap under a signed checkpoint is history not here; a changed link is tampered; no head is not-synced', () => {
  const gappy = { deviceId: K.deviceId, links: [...recs(0, 10), ...recs(20, 30)], seals: [] };
  const g = verdict(gappy, headAt(30), keyAt(30));
  assert.equal(g.verdict.kind, 'verified');
  /* #20 is held but welds to nothing held before it (#19's head is missing): open with the gap, as copy.assess counts it */
  assert.deepEqual(g.verdict.notHere, [{ from: 11, to: 20 }]);

  const bad = copyOf(0, 30);
  bad.links[12] = { ...bad.links[12], head: b32(99) };
  assert.equal(verdict(bad, headAt(30), keyAt(30)).verdict.kind, 'tampered');

  const ns = verdict(copyOf(0, 30), { seq: 30, head: null, ringFrom: 31 }, keyAt(30), { prev: { keep: 'me' } });
  assert.equal(ns.verdict.kind, 'not-synced');
  assert.deepEqual(ns.state, { keep: 'me' }, 'not synced: what was kept stays');
});

test('noFull: null when only the full check would do', () => {
  assert.equal(verdict(copyOf(0, 30), headAt(30), keyAt(30), { noFull: true }), null);
});
