export const KIND: Readonly<{
    SELF_PRESS: "self-press";
    PRESS: "press";
    PRESS_UNDER_BUDGET: "press-under-budget";
    MISMATCHED_ARM: "mismatched-arm";
    ARMED_PRESS: "armed-press";
    DENIED: "denied";
    TIMED_OUT: "timed-out";
}>;
export const ALARM: Readonly<{
    "mismatched-arm": "an ARM that did not match its request - someone else jumped in?";
}>;
/**
 * A sign or decrypt link's decoded fields (chain.decodeLink) -> {kind, alarm}
 * (alarm: a sentence, or null). Anything that is not a sign or decrypt -> null.
 * The ARMED test comes first: a mismatched ARM is pressed and owes a ticket too.
 *
 * R13b: the key copies the ARM's intent into the link ONLY when the ARM's token
 * matched this very request (okplugin_edge.cpp primed: has_intent is set on a
 * match), so ARMED + an intent = the agent's own request, pressed because no
 * budget paid (`okedge exec --press`, or a budget on hold or used up) - not an
 * alarm. ARMED with no intent is still the mismatch: a v2 ARM that did not
 * match leaves no intent, and a v1 ARM never carries one.
 */
export function classifyUse(f: any): {
    kind: "press" | "self-press" | "press-under-budget" | "mismatched-arm" | "armed-press" | "denied" | "timed-out";
    alarm: any;
} | null;
