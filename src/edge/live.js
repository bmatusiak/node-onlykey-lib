'use strict';

/**
 * What a use was, and whether it should stand out - the Live view's one answer
 * (onlykey-edge build/okrn-edge-tab.md B7), shared by the phone's tab and
 * `okedge watch` so the two can never tell the same link two ways.
 *
 * The key writes the decision into the link (firmware.md, 2026-10-02): flag bit 5
 * (STARTED) and bit 4 (OWES_TICKET) tell a direct press, a self-press and a
 * mismatched TX start apart - the chain alone could not rebuild that afterwards.
 */
const { OP, DECISION, FLAG } = require('./codes');

const KIND = Object.freeze({
  SELF_PRESS: 'self-press', // a budget paid: no press
  PRESS: 'press', // a plain press, no budget involved
  PRESS_UNDER_BUDGET: 'press-under-budget', // pressed while a budget was live: owes a ticket (R16)
  MISMATCHED_TX: 'mismatched-tx', // an agent started, but the request that came was not the one it started for
  STARTED_PRESS: 'started-press', // R13b: the TX start matched, nothing could pay, a person pressed - the intent is in the link
  DENIED: 'denied',
  TIMED_OUT: 'timed-out',
});

/*
 * The B7 'press during a live budget' alarm is gone (spec session, 2026-10-06): an
 * ordinary press is not Edge. New keys write neither kind any more (a mismatched sign
 * is refused, an ordinary press writes no link); these name old links only.
 */
const ALARM = Object.freeze({
  [KIND.MISMATCHED_TX]: 'a TX start that did not match its request - someone else jumped in?',
});

/**
 * A sign or decrypt link's decoded fields (chain.decodeLink) -> {kind, alarm}
 * (alarm: a sentence, or null). Anything that is not a sign or decrypt -> null.
 * The STARTED test comes first: a mismatched TX start is pressed and owes a ticket too.
 *
 * R13b: the key copies the TX start's intent into the link ONLY when the TX start's token
 * matched this very request (okplugin_edge.cpp primed: has_intent is set on a
 * match), so STARTED + an intent = the agent's own request, pressed because no
 * budget paid (`okedge exec --press`, or a budget on hold or used up) - not an
 * alarm. STARTED with no intent is still the mismatch: a v2 TX start that did not
 * match leaves no intent, and a v1 TX start never carries one.
 */
function classifyUse(f) {
  if (!f || (f.op !== OP.SIGN && f.op !== OP.DECRYPT)) return null;
  let kind;
  if (f.decision === DECISION.SELF_PRESS) kind = KIND.SELF_PRESS;
  else if (f.decision === DECISION.DENY) kind = KIND.DENIED;
  else if (f.decision === DECISION.TIMEOUT) kind = KIND.TIMED_OUT;
  else if (f.flags & FLAG.STARTED) kind = f.intent ? KIND.STARTED_PRESS : KIND.MISMATCHED_TX;
  else if (f.flags & FLAG.OWES_TICKET) kind = KIND.PRESS_UNDER_BUDGET;
  else kind = KIND.PRESS;
  return { kind, alarm: ALARM[kind] || null };
}

module.exports = { KIND, ALARM, classifyUse };
