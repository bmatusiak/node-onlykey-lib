'use strict';
/*
 * R28 (onlykey-edge SPEC.md, decided 2026-10-04): one chain per physical
 * device. A device moving to its own chain writes a CONTINUE link first - the next
 * seq after the chain it continues, welded onto its NEW genesis - and a host's copy
 * of the new chain starts there. The firmware side is the plugin's kit test.
 */
const test = require('node:test');
const assert = require('node:assert');
const { createHash } = require('node:crypto');
const chain = require('../src/chain');
const { OP, DECISION } = require('../src/codes');

const sha = (...parts) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(typeof p === 'string' ? Buffer.from(p, 'ascii') : Buffer.from(p));
  return new Uint8Array(h.digest());
};
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };

const oldId = new Uint8Array(16).fill(0x11);
const newId = new Uint8Array(16).fill(0x22);
const oldHead = new Uint8Array(32).fill(0x33);

test('R28: continueSubject is SHA256("OKEDGE-CONTINUE-v1" || old id || old seq || old head || debt seqs) - the plugin\'s write_continue', () => {
  const want = sha('OKEDGE-CONTINUE-v1', oldId, u32(263), oldHead, u32(250), u32(261));
  assert.deepStrictEqual(chain.continueSubject({ oldDeviceId: oldId, oldSeq: 263, oldHead, owedSeqs: [250, 261] }), want);
  assert.deepStrictEqual(chain.continueSubject({ oldDeviceId: oldId, oldSeq: 263, oldHead }), sha('OKEDGE-CONTINUE-v1', oldId, u32(263), oldHead));
});

test('R28: a copy whose first link is a continue at #264 verifies from the new genesis at 264, and nothing before it is a gap', () => {
  const subject = chain.continueSubject({ oldDeviceId: oldId, oldSeq: 263, oldHead, owedSeqs: [250] });
  const l264 = chain.encodeLink({ seq: 264, op: OP.CONTINUE, decision: DECISION.APPROVE, subject, grantId: 1 });
  const l265 = chain.encodeLink({ seq: 265, op: OP.SIGN, decision: DECISION.APPROVE, flags: 1, subject: new Uint8Array(32).fill(5) });
  const entries = [{ link: l264 }, { link: l265 }];
  const start = chain.chainStart(entries, newId);
  assert.strictEqual(start.fromSeq, 264);
  assert.deepStrictEqual(start.fromHead, chain.genesis(newId));
  const h264 = chain.weld(chain.genesis(newId), l264);
  const h265 = chain.weld(h264, l265);
  const v = chain.verify(entries, { deviceId: newId, ...start, expectHead: { seq: 265, head: h265 } });
  assert.strictEqual(v.ok, true, JSON.stringify(v.failure));
  assert.strictEqual(v.verifiedThrough, 265);
  assert.deepStrictEqual(v.gaps, []);
  /* the same links read as if the chain began at genesis #0: everything before is missing and the welds fail */
  const wrong = chain.verify(entries, { deviceId: newId, expectHead: { seq: 265, head: h265 } });
  assert.ok(!wrong.ok || wrong.gaps.length > 0);
});

test('R28: a copy without a continue still starts at genesis #0', () => {
  const l0 = chain.encodeLink({ seq: 0, op: OP.SIGN, decision: DECISION.APPROVE, flags: 1, subject: new Uint8Array(32).fill(7) });
  assert.deepStrictEqual(chain.chainStart([{ link: l0 }], newId), { fromSeq: 0, fromHead: chain.genesis(newId) });
  assert.deepStrictEqual(chain.chainStart([], newId), { fromSeq: 0, fromHead: chain.genesis(newId) });
});

test('R28: copy.checkContinue - matches the old copy it continues; a forged head and a late copy are not "ok"', () => {
  const copy = require('../src/copy');
  /* an old chain of two plain signs from genesis */
  const l0 = chain.encodeLink({ seq: 0, op: OP.SIGN, decision: DECISION.APPROVE, flags: 1, subject: new Uint8Array(32).fill(1) });
  const l1 = chain.encodeLink({ seq: 1, op: OP.SIGN, decision: DECISION.APPROVE, flags: 1, subject: new Uint8Array(32).fill(2) });
  const h0 = chain.weld(chain.genesis(oldId), l0);
  const h1 = chain.weld(h0, l1);
  const oldCopy = { deviceId: oldId, links: [{ link: l0, head: h0 }, { link: l1, head: h1 }] };
  const cont = (head) => chain.encodeLink({ seq: 2, op: OP.CONTINUE, decision: DECISION.APPROVE, subject: chain.continueSubject({ oldDeviceId: oldId, oldSeq: 1, oldHead: head }), grantId: 0 });
  assert.deepStrictEqual(copy.checkContinue(cont(h1), oldCopy), { ok: true, oldSeq: 1, debts: [], debtsChecked: true });
  assert.deepStrictEqual(copy.checkContinue(cont(new Uint8Array(32).fill(9)), oldCopy), { ok: false, reason: 'subject-mismatch', oldSeq: 1 });
  /* a copy holding only #1 (it starts late): a match is still a match, but not "debts checked" */
  assert.strictEqual(copy.checkContinue(cont(h1), { deviceId: oldId, links: [{ link: l1, head: h1 }] }).debtsChecked, false);
  assert.strictEqual(copy.checkContinue(cont(new Uint8Array(32).fill(9)), { deviceId: oldId, links: [{ link: l1, head: h1 }] }).reason, 'unverifiable');
  assert.strictEqual(copy.checkContinue(l1, oldCopy).reason, 'not-a-continue');
});
