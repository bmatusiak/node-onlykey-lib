/**
 * The lane of `transport`: exclusive(fn) runs fn after every conversation
 * queued before it has settled, and returns fn's result.
 *
 * URGENT (rule 8, Brad 2026-10-06): a Hold or Revoke the person taps must not
 * wait behind an agent's conversation. exclusive(fn, {urgent: true}) goes to
 * the FRONT of what is waiting (behind earlier urgent ones) - never into the
 * conversation already running: one conversation at a time still holds. The
 * phone's bridge ends a computer's hold at its next request boundary when one
 * waits (urgentWaiting).
 * @param {object} transport
 * @returns {(fn: () => Promise<any>, opts?: {urgent?: boolean}) => Promise<any>}
 */
export function laneOf(transport: object): (fn: () => Promise<any>, opts?: {
    urgent?: boolean;
}) => Promise<any>;
/**
 * Run fn in `transport`'s lane: its own exclusive() when it has one (the
 * lib's transports), otherwise a lane kept here for it - so a transport
 * written to the older contract (a host's own, a test's fake) still gets
 * one conversation at a time.
 */
export function inLane(transport: any, fn: any, opts: any): any;
/** An urgent conversation (a Hold, a Revoke) is waiting for `transport`'s lane. */
export function urgentWaiting(transport: any): any;
