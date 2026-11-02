/** The frame command every socket message travels under (cli/ble-link.js, the phone's src/bleRoom.ts). */
export const CMD_SOCKET: 134;
export const KIND: Readonly<{
    OPEN: 1;
    OPENED: 2;
    TEXT: 3;
    PART: 4;
    CLOSE: 5;
    HERE: 6;
    WHERE: 7;
}>;
export const PART_MAX: 2400;
/** HERE: the server's name, for the phone's url and its login proof. */
export function encodeHere({ host }: {
    host: any;
}): Uint8Array<any>;
/** WHERE: the phone asks for HERE again, saying whether it has a socket open. */
export function encodeWhere({ open }?: {
    open?: boolean | undefined;
}): Uint8Array<any>;
/** OPEN: the phone dials its identity's room. */
export function encodeOpen({ room }: {
    room: any;
}): Uint8Array<any>;
/** OPENED: the server's answer - the socket is up. */
export function encodeOpened({ host }: {
    host: any;
}): Uint8Array<any>;
/** TEXT (and PARTs first when it is long): one room message -> the 0x86 payloads to send, in order. */
export function encodeText(text: any): Uint8Array<any>[];
/** CLOSE: either end; a websocket close's code and reason. */
export function encodeClose({ code, reason }?: {
    code?: number | undefined;
    reason?: string | undefined;
}): Uint8Array<any>;
/**
 * The receiving end: 0x86 payloads in, socket events out -
 *   {kind:'here', host} | {kind:'where', open} | {kind:'open', room} | {kind:'opened', host} | {kind:'text', text} |
 *   {kind:'close', code, reason} | null (a PART held, or a payload that is not one of these: dropped, as noise is on any
 *   link).
 */
export function createDecoder(): {
    push(payload: any): {
        kind: string;
        text: string;
        host?: undefined;
        open?: undefined;
        room?: undefined;
        code?: undefined;
        reason?: undefined;
    } | {
        kind: string;
        host: any;
        text?: undefined;
        open?: undefined;
        room?: undefined;
        code?: undefined;
        reason?: undefined;
    } | {
        kind: string;
        open: boolean;
        text?: undefined;
        host?: undefined;
        room?: undefined;
        code?: undefined;
        reason?: undefined;
    } | {
        kind: string;
        room: any;
        text?: undefined;
        host?: undefined;
        open?: undefined;
        code?: undefined;
        reason?: undefined;
    } | {
        kind: string;
        code: number;
        reason: string;
        text?: undefined;
        host?: undefined;
        open?: undefined;
        room?: undefined;
    } | null;
};
/**
 * THE PHONE'S END: a WebSocket-shaped class for room-client's connectRoom ({WebSocket}), over one Bluetooth link's 0x86
 * messages - so the room client runs unchanged over the radio. The holder sends with `sendFrame(payload)` (one 0x86
 * payload) and feeds every 0x86 payload that arrives to `push(payload)`, and `down(reason)` when the link goes.
 *
 *   const s = createSocketLink({ sendFrame });
 *   s.host                       the server's name once HERE came (null before); onHere(fn) tells when
 *   connectRoom({ url: `ble://${s.host}`, WebSocket: s.WebSocket, ... })
 *
 * @param {{sendFrame: (payload: Uint8Array) => any}} o
 */
export function createSocketLink({ sendFrame }: {
    sendFrame: (payload: Uint8Array) => any;
}): {
    WebSocket: {
        new (url: any): {
            url: string;
            readyState: number;
            onopen: any;
            onmessage: any;
            onclose: any;
            onerror: any;
            send(text: any): void;
            close(code?: number, reason?: string): void;
            closed(code: any, reason: any): void;
        };
    };
    readonly host: any;
    /** fn(host) each time the server says its name (HERE) */
    onHere(fn: any): () => boolean;
    /** ask the server for HERE again (and say whether a socket is open on this side) */
    where(): void;
    /** one 0x86 payload from the link */
    push(payload: any): void;
    /** the link went: the socket closes as a dropped websocket does (1006), and the server's name is forgotten */
    down(reason?: string): void;
};
