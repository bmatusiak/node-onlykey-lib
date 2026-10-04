'use strict';

/* B7: one classification of a use for the phone's Live view and okedge watch */
const test = require('node:test');
const assert = require('node:assert');
const { codes, live } = require('../src/edge');

const { OP, DECISION, FLAG } = codes;
const use = (decision, flags = 0, op = OP.SIGN) => ({ op, decision, flags });

test('each decision and flag mix gives one kind, and only the two R16 cases are alarms', () => {
  const rows = [
    [use(DECISION.SELF_PRESS, FLAG.BUDGET_SPENT), 'self-press', null],
    [use(DECISION.APPROVE), 'press', null],
    [use(DECISION.APPROVE, FLAG.PRESS_OBSERVED | FLAG.OWES_TICKET), 'press-under-budget', live.ALARM['press-under-budget']],
    [use(DECISION.APPROVE, FLAG.ARMED | FLAG.OWES_TICKET | FLAG.PRESS_OBSERVED), 'mismatched-arm', live.ALARM['mismatched-arm']],
    [use(DECISION.DENY), 'denied', null],
    [use(DECISION.TIMEOUT), 'timed-out', null],
    [use(DECISION.APPROVE, 0, OP.DECRYPT), 'press', null],
  ];
  for (const [f, kind, alarm] of rows) assert.deepEqual(live.classifyUse(f), { kind, alarm });
});

test('links that are not a use have no classification', () => {
  for (const op of [OP.TICKET, OP.GRANT_CREATE, OP.GRANT_END, OP.LOSS, OP.FIDO_AUTH]) assert.equal(live.classifyUse({ op, decision: 1, flags: 0 }), null);
  assert.equal(live.classifyUse(null), null);
});
