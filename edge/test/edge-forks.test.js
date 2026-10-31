'use strict';
/*
 * EVERY RESTORE IS A FORK (edge/src/forks.js; Brad, 2026-10-31): a restored key's chain begins with a CONTINUE naming
 * the backup point; forks of one point carry one subject, and two of them are the yellow flag (a copy of the backup in
 * someone else's hands, maybe).
 */
const test = require('node:test');
const assert = require('node:assert');
const { chain, forks } = require('../src');
const { OP } = require('../src/codes');

const id = (n) => new Uint8Array(16).fill(n);
const hex = (b) => Buffer.from(b).toString('hex');

/* a chain from `from` (genesis, or a continue's seq) of ordinary pressed signs, each record with its head */
function chainOf(deviceId, { from = 0, count, first = null }) {
  const links = [];
  let head = chain.genesis(deviceId);
  for (let i = 0; i < count; i++) {
    const seq = from + i;
    const link = i === 0 && first ? first : chain.encodeLink({ seq, op: OP.SIGN, decision: 1, slot: 1, subject: new Uint8Array(32).fill(seq), grantId: 0 });
    head = chain.weld(head, link);
    links.push({ link, head });
  }
  return { deviceId, links };
}
/* the continue a key restored from `parent`'s backup at `atSeq` writes first (no debts: the parent's links owe nothing) */
function continueFrom(parent, atSeq) {
  const at = parent.links.find((e) => chain.decodeLink(e.link).seq === atSeq);
  const subject = chain.continueSubject({ oldDeviceId: parent.deviceId, oldSeq: atSeq, oldHead: at.head, owedSeqs: [] });
  return chain.encodeLink({ seq: atSeq + 1, op: OP.CONTINUE, decision: 1, slot: 0, subject, grantId: 0 });
}

test('the original, two restores of one backup (the yellow flag) and one of a later backup - each named by its parent', () => {
  const root = chainOf(id(1), { count: 8 });
  const a = chainOf(id(2), { from: 4, count: 3, first: continueFrom(root, 3) });
  const b = chainOf(id(3), { from: 4, count: 2, first: continueFrom(root, 3) });
  const c = chainOf(id(4), { from: 7, count: 2, first: continueFrom(root, 6) });
  const t = forks.forkTree([a, root, c, b]);
  const of = (d) => t.chains.find((x) => x.deviceId === hex(d));
  assert.equal(of(id(1)).start, 'original');
  assert.deepEqual([of(id(2)).start, of(id(2)).forkSeq, of(id(2)).parent], ['fork', 4, hex(id(1))]);
  assert.equal(of(id(2)).point, of(id(3)).point, 'two restores of one backup carry one subject');
  assert.notEqual(of(id(2)).point, of(id(4)).point);
  assert.deepEqual(t.points.map((p) => [p.seq, p.parent, p.forks.length, p.flag]), [[4, hex(id(1)), 2, true], [7, hex(id(1)), 1, false]]);
});

test('the flag needs no parent: two forks of one point, the parent never held here; a chain held from later is partial', () => {
  const root = chainOf(id(1), { count: 6 });
  const a = chainOf(id(2), { from: 3, count: 2, first: continueFrom(root, 2) });
  const b = chainOf(id(3), { from: 3, count: 1, first: continueFrom(root, 2) });
  const t = forks.forkTree([a, b, { deviceId: root.deviceId, links: root.links.slice(4) }]);
  assert.deepEqual(t.points.map((p) => [p.seq, p.parent, p.flag]), [[3, null, true]], 'the parent is not named from a copy that lacks the backup point');
  assert.equal(t.chains.find((x) => x.deviceId === hex(id(1))).start, 'partial');
});
