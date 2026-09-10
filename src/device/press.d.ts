export namespace PRESS_TICKS {
    let TAP: number;
    let HOLD: number;
    let GESTURE: number;
    let REJECTED: number;
}
/**
 * Idle sense rounds before the firmware calls a press finished.
 *
 * `key_off > 2` (okcore.cpp:2723) - three rounds with no pad held - plus one
 * for the round the hold retired in, which still read as held.
 *
 * This is why counted presses with no idle gap between them MERGE: the firmware
 * never saw the release, so the two durations sum, and two taps of 10 become
 * one hold of 20. Past 72 that is a gesture.
 * See FINDING-counted-presses-merge-without-an-idle-gap.md.
 */
export const RELEASE_ROUNDS: 4;
/**
 * What a hold past the gesture floor actually does, by button.
 *
 * Written out because "it is in the gesture band" is not a useful thing to tell
 * somebody: the consequences are different per button and three of them are
 * irreversible or disruptive.
 *
 * These are the CLASSIC assignments. A DUO takes config mode on button 1 held
 * past 180 instead - see capabilities().configModeGesture, which is the source
 * a caller should use rather than this table.
 */
export const GESTURES: {
    1: string;
    2: string;
    3: string;
    6: string;
};
/** Which band a count falls in: 'tap', 'hold', 'gesture' or 'rejected'. */
export function bandFor(ticks: any): "rejected" | "gesture" | "hold" | "tap";
/** True when a hold this long stops being a slot read. */
export function isGesture(ticks: any): boolean;
/**
 * Refuse a gesture-length hold unless it was asked for by name.
 *
 * There is no such thing as accidentally wanting one: at 72 iterations button 1
 * takes a backup, button 3 locks the key and restarts it, and button 6 enters
 * config mode - which ends only at restart. A slot read never needs to go past
 * 71, so the default makes that range unreachable rather than merely unlikely.
 *
 * Returns the message rather than throwing, so a caller can reject, throw or
 * render it. Null means the hold is fine.
 */
export function gestureRefusal(button: any, ticks: any, { allowGesture }?: {
    allowGesture?: boolean | undefined;
}): string | null;
