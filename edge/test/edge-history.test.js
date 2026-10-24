'use strict';

/* edge/src/history.js: a copy described as budget history (no verification - that is the copy check's) */

const test = require('node:test');
const assert = require('node:assert/strict');
const { chain, codes } = require('../src');
const { budgetHistory } = require('../src/history');

const { OP, DECISION, FLAG } = codes;
const z = () => new Uint8Array(32);

function build() {
  const links = [];
  const add = (f) => { links.push({ link: chain.encodeLink({ seq: links.length, ...f }) }); return links.length - 1; };
  const receipt = (ref, code = 0) => add({ op: OP.RECEIPT, decision: code, grantId: ref, subject: z() });
  const pressed = add({ op: OP.SIGN, decision: DECISION.APPROVE, slot: 2, flags: FLAG.PRESS_OBSERVED, subject: z() });
  receipt(pressed);
  const grantId = links.length + 1;
  add({ op: OP.GRANT_CREATE, decision: DECISION.APPROVE, flags: FLAG.PRESS_OBSERVED, grantId, subject: z() });
  const use = add({ op: OP.SIGN, decision: DECISION.SELF_PRESS, slot: 221, flags: FLAG.BUDGET_SPENT, grantId, grantStep: 1, subject: z() });
  receipt(use);
  add({ op: OP.GRANT_END, decision: 1, grantId, subject: z() });
  return { links, grantId, use };
}

test('history: a budget with its opening, a spend with its intent and receipt, how it ended; a pressed use apart', () => {
  const { links, grantId, use } = build();
  const h = budgetHistory({
    links,
    openings: [{ grantId, reason: 'sign 1 commit', scopes: [{ op: 1, slot: 221, cap: 1 }], uses: 1, lifetime: 30, opened: 1000, from: 'this computer' }],
    notes: { reasons: { [use]: 'sign: lib abc1234' }, messages: { [use]: 'pushed' } },
  });
  assert.equal(h.budgets.length, 1);
  const b = h.budgets[0];
  assert.equal(b.grantId, grantId);
  assert.equal(b.reason, 'sign 1 commit');
  assert.deepEqual(b.ended, { seq: links.length - 1, how: 'completed' });
  assert.equal(b.spends.length, 1);
  assert.equal(b.spends[0].intent, 'sign: lib abc1234');
  assert.equal(b.spends[0].receipt.name, 'OK');
  assert.equal(b.spends[0].receipt.message, 'pushed', 'a note filed under the use');
  assert.equal(h.presses.length, 1);
  assert.equal(h.presses[0].receipt.seq, 1);
});

test('history: a spend whose opening is not in the copy (opened behind a loss) is still listed under its budget', () => {
  const { links, grantId } = build();
  const h = budgetHistory({ links: links.filter((_, i) => i !== 2), openings: [] });
  assert.equal(h.budgets[0].grantId, grantId);
  assert.equal(h.budgets[0].seq, null);
  assert.equal(h.budgets[0].spends.length, 1);
});
