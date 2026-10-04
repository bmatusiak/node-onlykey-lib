'use strict';

/**
 * What a use was, and whether it should stand out - the Live view's one answer
 * (onlykey-edge build/okrn-edge-tab.md B7), shared by the phone's tab and
 * `okedge watch` so the two can never tell the same link two ways.
 *
 * The key writes the decision into the link (firmware.md, 2026-10-02): flag bit 5
 * (ARMED) and bit 4 (OWES_TICKET) tell a direct press, a self-press and a
 * mismatched ARM apart - the chain alone could not rebuild that afterwards.
 */
const { OP, DECISION, FLAG } = require('./codes');

const KIND = Object.freeze({
  SELF_PRESS: 'self-press', // a budget paid: no press
  PRESS: 'press', // a plain press, no budget involved
  PRESS_UNDER_BUDGET: 'press-under-budget', // pressed while a budget was live: owes a ticket (R16)
  MISMATCHED_ARM: 'mismatched-arm', // an agent ARMed, but the request that came was not the one it ARMed for
  DENIED: 'denied',
  TIMED_OUT: 'timed-out',
});

const ALARM = Object.freeze({
  [KIND.MISMATCHED_ARM]: 'an ARM that did not match its request - someone else jumped in?',
  [KIND.PRESS_UNDER_BUDGET]: 'a press asked for under a live budget (it owes a ticket, R16)',
});

/**
 * A sign or decrypt link's decoded fields (chain.decodeLink) -> {kind, alarm}
 * (alarm: a sentence, or null). Anything that is not a sign or decrypt -> null.
 * The ARMED test comes first: a mismatched ARM is pressed and owes a ticket too.
 */
function classifyUse(f) {
  if (!f || (f.op !== OP.SIGN && f.op !== OP.DECRYPT)) return null;
  let kind;
  if (f.decision === DECISION.SELF_PRESS) kind = KIND.SELF_PRESS;
  else if (f.decision === DECISION.DENY) kind = KIND.DENIED;
  else if (f.decision === DECISION.TIMEOUT) kind = KIND.TIMED_OUT;
  else if (f.flags & FLAG.ARMED) kind = KIND.MISMATCHED_ARM;
  else if (f.flags & FLAG.OWES_TICKET) kind = KIND.PRESS_UNDER_BUDGET;
  else kind = KIND.PRESS;
  return { kind, alarm: ALARM[kind] || null };
}

module.exports = { KIND, ALARM, classifyUse };
