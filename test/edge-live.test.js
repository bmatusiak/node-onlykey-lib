'use strict';

/* B7: one classification of a use for the phone's Live view and okedge watch */
const test = require('node:test');
const assert = require('node:assert');
const { codes, live } = require('../src/edge');

const { OP, DECISION, FLAG } = codes;
const use = (decision, flags = 0, op = OP.SIGN) => ({ op, decision, flags });

test('each decision and flag mix gives one kind; only a mismatched TX start (an old link) is an alarm', () => {
  const rows = [
    [use(DECISION.SELF_PRESS, FLAG.BUDGET_SPENT), 'self-press', null],
    [use(DECISION.APPROVE), 'press', null],
    /* an old link: the B7 alarm for it is gone (2026-10-06) */
    [use(DECISION.APPROVE, FLAG.PRESS_OBSERVED | FLAG.OWES_TICKET), 'press-under-budget', null],
    [use(DECISION.APPROVE, FLAG.STARTED | FLAG.OWES_TICKET | FLAG.PRESS_OBSERVED), 'mismatched-tx', live.ALARM['mismatched-tx']],
    /* R13b: the key copies the intent only when the TX start matched - STARTED + intent is the agent's own pressed request */
    [{ ...use(DECISION.APPROVE, FLAG.STARTED | FLAG.OWES_TICKET | FLAG.PRESS_OBSERVED), intent: new Uint8Array(16).fill(7) }, 'started-press', null],
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
