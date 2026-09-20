export class DeviceConsole {
    constructor({ limit }?: {
        limit?: number | undefined;
    });
    limit: number;
    buffer: string;
    waiters: Set<any>;
    off: any;
    /**
     * Subscribe to a transport's log events.
     *
     * The transport has already stripped NUL padding and decoded latin1 - see
     * src/transport/contract.js. Nothing here re-does that, because doing it in
     * two places is how the two end up disagreeing.
     */
    attach(transport: any): this;
    detach(): this;
    /** Feed text directly. Exposed for tests and for transports without events. */
    push(text: any): void;
    /**
     * Drop what has been said so far.
     *
     * Called before each step, so a prompt from the PREVIOUS step cannot satisfy
     * this one. The firmware prints the same words at several points in the
     * bracket - "Enter PIN" appears for both the primary and the confirmation -
     * so without this a step can be satisfied by stale text and the sequence
     * runs ahead of the device.
     */
    clear(): this;
    get text(): string;
    /**
     * Wait for a pattern, failing early on any of `reject`.
     *
     * The buffer is checked BEFORE subscribing, and that ordering is the whole
     * point: the device can print between the write that provoked it and the
     * caller's wait, and a wait that only looked at future text would miss a line
     * that had already arrived and then time out against a device that answered
     * correctly. Same hazard as writing before subscribing on the vendor
     * interface, in a different costume.
     *
     * @returns {Promise<string>} the console text at the moment it matched
     */
    waitFor(pattern: any, { reject, timeoutMs }?: {
        reject?: never[] | undefined;
        timeoutMs?: number | undefined;
    }): Promise<string>;
    /**
     * Wait until a pattern has matched `count` times.
     *
     * The firmware prints one acknowledgement per PIN digit, so a first-match
     * wait returns after digit one while the rest of the burst is still being
     * consumed. The next message then lands mid-burst and the device sees a
     * short PIN - which surfaces much later as "PINs don't match" against two
     * PINs that were typed identically.
     */
    waitForCount(pattern: any, count: any, { reject, timeoutMs }?: {
        reject?: never[] | undefined;
        timeoutMs?: number | undefined;
    }): Promise<any>;
    _wait({ test, reject, timeoutMs, describe }: {
        test: any;
        reject: any;
        timeoutMs: any;
        describe: any;
    }): Promise<any>;
}
/**
 * Send a line of button presses.
 *
 * ONE write for the whole PIN, terminated by a newline. The firmware queues
 * the presses and replays them one per loop() iteration, so there is no
 * per-digit delay to tune - and splitting the burst across writes is how a
 * subsequent message lands in the middle of it and the firmware sees a short
 * PIN.
 */
export function pressLine(transport: any, digits: any): any;
/**
 * The console tail, with the PIN taken out of it.
 *
 * A tail in an error message earns its place - "timed out" against a device
 * that printed something unexpected is close to undiagnosable from a phone,
 * which is why these errors carry one. But on a DEBUG firmware the last thing
 * the console said during a PIN bracket is the device acknowledging each digit
 * BY VALUE: "password appended with 4", once per keypress, in order. An Error
 * travels further than a log line - up through every catch, into whatever the
 * caller renders, and off-device if anything crash-reports - so a tail must
 * not carry one.
 *
 * The line survives with its digit removed. That the device was acknowledging
 * presses is the diagnostic fact; WHICH presses is the secret, and no reader of
 * a timeout message needs it.
 *
 * A production firmware never reaches this: it does not enumerate SEREMU, so
 * the buffer is empty and the tail is "". This protects the developer key,
 * which is the one a maintainer actually holds.
 */
export function safeTail(text: any, n?: number): string;
/** Keep the tail of the console; a long session should not grow without end. */
export const DEFAULT_LIMIT: 65536;
