import { IFACE } from "../protocol/msg";
export namespace DIR {
    let OUT: number;
    let IN: number;
}
/** One vendor report. Not negotiable - the firmware's buffers are this size. */
export const REPORT_SIZE: 64;
/**
 * The methods a transport must implement.
 *
 * Kept as a list rather than a base class: a transport is often a thin wrapper
 * over something that already exists (a TurboModule, a socket), and forcing it
 * to extend anything just adds a layer.
 */
export const REQUIRED: string[];
/**
 * Check a transport before anything depends on it.
 *
 * Called by the transport plugin at registration, so a missing method is a
 * build-time failure naming the transport, rather than a TypeError thrown
 * from inside a poll loop twenty seconds later.
 */
export function assertTransport(transport: any, name?: string): any;
/**
 * Strip trailing NULs from a device string.
 *
 * hidprint() memsets its buffer and writes only the string, so everything
 * after it is padding and must not reach an assertion. Trailing only: an
 * interior NUL is the device's own byte.
 */
export function stripPadding(bytes: any): any;
/** Pad or truncate to exactly one report. */
export function toReport(bytes: any, size?: number): any;
/**
 * Add the leading report ID some platforms require.
 *
 * hidapi on Linux and chrome.hid both want it; an in-process bus does not.
 * A transport calls this only if its platform needs it - never at a higher
 * layer, or the two disagree.
 */
export function withReportId(bytes: any, reportId?: number): Uint8Array<any>;
export { IFACE };
