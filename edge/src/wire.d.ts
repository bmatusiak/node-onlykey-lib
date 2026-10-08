export const OKEDGE_REQUEST: 247;
export const KIND: Readonly<{
    REQUEST: 1;
    ANSWER: 2;
}>;
export const PIECE: 55;
/** a whole message -> its 64-byte reports */
export function encode(kind: any, obj: any): Uint8Array<ArrayBuffer>[];
/** is this report an OKEDGE_REQUEST piece (either direction)? */
export function isEdgeRequestFrame(frame: any): any;
/**
 * Pieces in, whole messages out. push(frame) -> {kind, message} when a message
 * is complete, null otherwise. A piece out of order, or JSON that does not
 * parse, drops what was gathered (and push returns {error}).
 */
export function createAssembler(): {
    push(frame: any): {
        error: string;
        kind?: undefined;
        message?: undefined;
    } | {
        kind: number;
        message: any;
        error?: undefined;
    } | null;
};
/**
 * The PC side of the Bluetooth channel: send(EDGE_REQUEST) -> the app's
 * answer, or null when nothing comes back in time (an app DROPS an unsigned,
 * unregistered or replayed request without answering). The person approves
 * in between, so the wait is long. Held as one conversation in the key's lane
 * (transport/lane.js), so no other request from this host lands in it.
 */
export function createWireChannel(transport: any, { timeoutMs, iface, device, log, net }?: {
    timeoutMs?: number | undefined;
    iface?: number | undefined;
    device?: null | undefined;
    log?: (() => void) | undefined;
    net?: string | undefined;
}): {
    send(message: any, opts?: {}): any;
};
/** the phone's answer to `request`, stamped (unchanged when the request had no envelope - an older computer) */
/**
 * @param {any} request
 * @param {any} answer
 * @param {{dev?: string, net?: string, now?: () => number}} [opts]  net: the chain the phone is on (BLOCKS.md §5)
 */
export function answerEnvelope(request: any, answer: any, { dev, net, now }?: {
    dev?: string;
    net?: string;
    now?: () => number;
}): any;
