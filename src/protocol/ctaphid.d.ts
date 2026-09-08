/**
 * The client protocol, bound to a transport.
 *
 * Takes anything satisfying src/transport/contract.js, so the same ceremony
 * runs over the embedded emulator, a USB key, or a socket.
 */
export class CtapHid {
    /**
     * @param {object} transport  must provide on() and write()
     * @param {object} [opts] {iface}
     */
    constructor(transport: object, { iface }?: object);
    transport: object;
    iface: any;
    cid: Uint8Array<ArrayBuffer> | null;
    /** Every KEEPALIVE status seen, so a caller can tell a press was demanded. */
    keepAlives: any[];
    /**
     * Open a reader over one channel's traffic.
     *
     * ONE subscription for a whole exchange, with a QUEUE - not a fresh
     * subscription per message. That distinction is the entire difficulty of this
     * protocol on an in-process bus.
     *
     * A KEEPALIVE burst puts several complete messages on the wire at once, and
     * the firmware answers immediately after them. Subscribing again after
     * handling a keepalive means the answer has already gone past with nobody
     * listening, and the exchange waits out its timeout against a device that
     * replied correctly. onlykey-testing hit the same wall from the other
     * direction and solved it with a cursor over buffered reports; here the
     * subscription simply stays up and completed messages are queued until asked
     * for.
     *
     * @returns {{next: function, close: function}}
     */
    _open(cid: any, { timeoutMs }?: {
        timeoutMs?: number | undefined;
    }): {
        next: Function;
        close: Function;
    };
    /** Write a framed message. The reader must already be open. */
    _write(cid: any, cmd: any, payload: any): Promise<void>;
    /**
     * Allocate a channel. Must happen before anything else.
     *
     * The nonce is echoed back, which is how a reply is recognised as ours on a
     * bus that other clients may share.
     */
    init(opts?: {}): Promise<Uint8Array<ArrayBuffer>>;
    /**
     * One CBOR command, with the KEEPALIVE loop.
     *
     * @param {number} cmd CTAP2_CMD.*
     * @param {Uint8Array} [data] already-encoded CBOR parameters
     * @param {object} [opts] {timeoutMs, onKeepAlive}
     * @returns {Promise<*>} the decoded response, or undefined for an empty one
     */
    send(cmd: number, data?: Uint8Array, opts?: object): Promise<any>;
    /**
     * Read until something that is not a keepalive.
     *
     * The wait AFTER a keepalive is much longer than the ordinary one, and that
     * is not a safety margin - it is what the firmware does.
     * device.cpp:172 sends KEEPALIVE only when the status CHANGES:
     *
     *     if (status != CTAPHID_STATUS_IDLE && __device_status != status)
     *         ctaphid_update_status(status);
     *
     * so a user-presence wait produces exactly ONE keepalive and then silence
     * for up to CTAP2_UP_DELAY_MS - 19 seconds (ctap.h:173) - while the device
     * waits for a finger. The spec suggests a ~100ms cadence and this firmware
     * does not follow it, so a client using its ordinary timeout gives up at ten
     * seconds on a ceremony the user is halfway through confirming.
     */
    _await(reader: any, opts: any): Promise<any>;
    getInfo(opts?: {}): Promise<any>;
    makeCredential(params: any, opts?: {}): Promise<any>;
    getAssertion(params: any, opts?: {}): Promise<any>;
    /** Did the device ask for a finger during the last exchange? */
    get askedForUserPresence(): boolean;
}
export class Ctap2Error extends Error {
    constructor(code: any);
    code: any;
    ctapName: any;
}
/**
 * Split a message into 64-byte CTAPHID packets.
 *
 * Pure, so it can be tested against the reference without a device.
 */
export function frame(cid: any, cmd: any, payload: any): Uint8Array<ArrayBuffer>[];
export namespace CTAPHID {
    let PING: number;
    let MSG: number;
    let LOCK: number;
    let INIT: number;
    let WINK: number;
    let CBOR: number;
    let CANCEL: number;
    let KEEPALIVE: number;
    let ERROR: number;
}
export namespace CTAP2_CMD {
    let MAKE_CREDENTIAL: number;
    let GET_ASSERTION: number;
    let GET_INFO: number;
    let CLIENT_PIN: number;
    let RESET: number;
    let GET_NEXT_ASSERTION: number;
}
export const CTAP2_ERROR: {
    0: string;
    1: string;
    2: string;
    3: string;
    17: string;
    18: string;
    20: string;
    21: string;
    25: string;
    33: string;
    34: string;
    35: string;
    36: string;
    37: string;
    38: string;
    39: string;
    43: string;
    45: string;
    46: string;
    49: string;
    54: string;
    106: string;
};
export namespace KEEPALIVE {
    let PROCESSING: number;
    let UP_NEEDED: number;
}
export const BROADCAST_CID: Uint8Array<ArrayBuffer>;
export const TYPE_INIT: 128;
export const PACKET_SIZE: 64;
export const INIT_PAYLOAD: number;
export const CONT_PAYLOAD: number;
