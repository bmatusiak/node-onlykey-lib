export const KIND: Readonly<{
    SELF_PRESS: "self-press";
    PRESS: "press";
    PRESS_UNDER_BUDGET: "press-under-budget";
    MISMATCHED_TX: "mismatched-tx";
    STARTED_PRESS: "started-press";
    DENIED: "denied";
    TIMED_OUT: "timed-out";
}>;
export const ALARM: Readonly<{
    "mismatched-tx": "a TX start that did not match its request - someone else jumped in?";
}>;
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
export function classifyUse(f: any): {
    kind: "press" | "self-press" | "press-under-budget" | "mismatched-tx" | "started-press" | "denied" | "timed-out";
    alarm: any;
} | null;
