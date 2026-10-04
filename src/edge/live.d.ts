export const KIND: Readonly<{
    SELF_PRESS: "self-press";
    PRESS: "press";
    PRESS_UNDER_BUDGET: "press-under-budget";
    MISMATCHED_ARM: "mismatched-arm";
    DENIED: "denied";
    TIMED_OUT: "timed-out";
}>;
export const ALARM: Readonly<{
    "mismatched-arm": "an ARM that did not match its request - someone else jumped in?";
    "press-under-budget": "a press asked for under a live budget (it owes a ticket, R16)";
}>;
/**
 * A sign or decrypt link's decoded fields (chain.decodeLink) -> {kind, alarm}
 * (alarm: a sentence, or null). Anything that is not a sign or decrypt -> null.
 * The ARMED test comes first: a mismatched ARM is pressed and owes a ticket too.
 */
export function classifyUse(f: any): {
    kind: "press" | "self-press" | "press-under-budget" | "mismatched-arm" | "denied" | "timed-out";
    alarm: any;
} | null;
