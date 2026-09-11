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
     * The same exchange, handed back UNDECODED: the status byte followed by
     * whatever CBOR came with it.
     *
     * This exists for BRIDGING. A bridge carries bytes between a host and an
     * authenticator and must not develop opinions about them - it has to forward
     * the device's own error rather than throw its own, because the host is the
     * thing entitled to interpret CTAP2 status codes. send() throwing on a
     * non-zero status is right for a caller acting on the result and wrong for
     * one relaying it: a browser told "the request failed" learns nothing, where
     * CTAP2_ERR_NO_CREDENTIALS tells it to try another authenticator.
     *
     * Decoding and re-encoding the CBOR would be worse still. A round trip is
     * not guaranteed to be byte-identical, and the response is SIGNED - authData
     * and the attestation cover exact bytes, so a re-encoded map that differs by
     * one integer width verifies as a forgery at the relying party.
     *
     * @returns {Promise<Uint8Array>} status byte followed by the CBOR body
     */
    sendRaw(cmd: any, data?: Uint8Array<ArrayBuffer>, opts?: {}): Promise<Uint8Array>;
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
/**
 * Reassembles inbound packets into whole messages.
 *
 * Stateful on purpose: a continuation packet is meaningless without the
 * initialization packet before it, so the buffer has to outlive one callback.
 *
 * ## On an unexpected continuation, the packet is dropped and the message kept
 *
 * ok-rn carried a second copy of this that ABANDONED the whole message when a
 * continuation arrived with the wrong sequence or the wrong channel, on the
 * reasoning that splicing corrupt bytes together is worse. The two copies are
 * now one, and this is the behaviour that survived, for three reasons:
 *
 *   - Neither version splices the bad packet, so the choice is only about the
 *     good bytes already collected. Throwing those away because something
 *     unrelated arrived turns one stray packet into a lost message.
 *   - A stray packet on this bus is usually a LEFTOVER from the previous
 *     exchange, not corruption of this one - the emulator's report queue can
 *     deliver one after the next message has started.
 *   - When a message really is lost, waiting produces a timeout that names how
 *     many of how many bytes arrived. Abandoning produces silence.
 *
 * A fresh initialization packet always resets, so both recover at the same
 * point either way: the next message.
 *
 * The spec's own rule for the case with no state at all - CTAP §11.2.4,
 * "spurious continuation packets will be ignored" - is what both copies already
 * did, and still do.
 */
export class Assembler {
    constructor({ packetSize }?: {
        packetSize?: number | undefined;
    });
    packetSize: number;
    initPayload: number;
    contPayload: number;
    reset(): void;
    cid: Uint8Array<ArrayBuffer> | null | undefined;
    cmd: number | null | undefined;
    total: number | null | undefined;
    chunks: any[] | Uint8Array<ArrayBufferLike>[] | undefined;
    have: number | undefined;
    seq: number | undefined;
    /** How much of a message is outstanding, for a timeout message to quote. */
    get progress(): {
        have: number | undefined;
        total: number | undefined;
    } | null;
    /**
     * @param {Uint8Array} packet
     * @returns {{cid: Uint8Array, cmd: number, payload: Uint8Array}|null}
     */
    push(packet: Uint8Array): {
        cid: Uint8Array;
        cmd: number;
        payload: Uint8Array;
    } | null;
}
/**
 * A channel id as four bytes, from either four bytes or a number.
 *
 * This file is bytes-oriented, but a channel id reads naturally as a number -
 * BROADCAST is "0xffffffff", and that is how it appears in a log line. Both
 * spellings arrive here, so both are accepted and one is stored.
 */
export function cidBytes(cid: any): Uint8Array<ArrayBufferLike>;
/** The same id as a number, for logs and for comparing against BROADCAST. */
export function cidNumber(cid: any): number;
export class Ctap2Error extends Error {
    constructor(code: any);
    code: any;
    ctapName: any;
}
/**
 * Split a message into packets of `packetSize` bytes.
 *
 * Pure, so it can be tested against the reference without a device.
 *
 * `packetSize` is a parameter rather than the constant because a USB endpoint
 * reports its own packet size on connect, and the descriptor is what decides
 * how much fits in a report - not our assumption about it.
 */
export function frame(cid: any, cmd: any, payload: any, packetSize?: number): Uint8Array<ArrayBuffer>[];
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
export namespace CTAP2_STATUS {
    let OK: number;
    let INVALID_COMMAND: number;
    let INVALID_PARAMETER: number;
    let INVALID_LENGTH: number;
    let MISSING_PARAMETER: number;
    let INVALID_CREDENTIAL: number;
    let USER_ACTION_PENDING: number;
    let OPERATION_DENIED: number;
    let NO_CREDENTIALS: number;
    let NOT_ALLOWED: number;
    let UNSUPPORTED_OPTION: number;
}
/**
 * Byte to spec name, for a status a device SENT us.
 *
 * Derived, not retyped: see the note above CTAP2_STATUS. 0x00 keeps the
 * CTAP2 spelling here because this table describes CTAP2 command replies,
 * while ctap.js reads byte 0 of a tunnelled U2F signature, where the same
 * zero means CTAP1_SUCCESS.
 */
export const CTAP2_ERROR: {
    0: string;
    1: string;
    2: string;
    3: string;
    4: string;
    5: string;
    6: string;
    10: string;
    11: string;
    16: string;
    17: string;
    18: string;
    19: string;
    20: string;
    21: string;
    22: string;
    23: string;
    24: string;
    25: string;
    32: string;
    33: string;
    34: string;
    35: string;
    36: string;
    37: string;
    38: string;
    39: string;
    40: string;
    41: string;
    42: string;
    43: string;
    44: string;
    45: string;
    46: string;
    47: string;
    48: string;
    49: string;
    50: string;
    51: string;
    52: string;
    53: string;
    54: string;
    55: string;
    56: string;
    57: string;
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
