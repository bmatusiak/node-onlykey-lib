'use strict';
/*
 * `edge watch` says how each budget ended, from the key's own end link (codes.END; Brad,
 * 2026-10-10: "budgets should auto complete once fufilled"). Completed is the normal end and is
 * said plainly; revoked and settled ended it early and are flagged, as is a loss.
 */
const test = require('node:test');
const assert = require('node:assert');
const { watchLines } = require('../cli/commands');
const { codes } = require('../src');

const end = (seq, decision) => ({ seq, op: codes.OP.GRANT_END, decision, grantId: 54 });
const lines = (links) => watchLines({ links, missed: 0, events: [] }, { time: new Date(2026, 9, 10, 15, 19, 25) });

test('watch: a completed budget is said plainly; revoked and settled are flagged; a loss is flagged', () => {
  assert.deepEqual(lines([end(56, codes.END.COMPLETED)]), ['#56 15:19:25 budget 54 completed']);
  assert.deepEqual(lines([end(57, codes.END.REVOKED)]), ['#57 15:19:25 budget 54 revoked  ⚠']);
  assert.deepEqual(lines([end(58, codes.END.SETTLED)]), ['#58 15:19:25 budget 54 settled - ended early, incomplete  ⚠']);
  assert.match(lines([{ seq: 59, op: codes.OP.LOSS, decision: 1, grantId: 3 }])[0], /⚠$/);
});
