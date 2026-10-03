/**
 * The lane of `transport`: exclusive(fn) runs fn after every conversation
 * queued before it has settled, and returns fn's result.
 * @param {object} transport
 * @returns {(fn: () => Promise<any>) => Promise<any>}
 */
export function laneOf(transport: object): (fn: () => Promise<any>) => Promise<any>;
/**
 * Run fn in `transport`'s lane: its own exclusive() when it has one (the
 * lib's transports), otherwise a lane kept here for it - so a transport
 * written to the older contract (a host's own, a test's fake) still gets
 * one conversation at a time.
 */
export function inLane(transport: any, fn: any): any;
