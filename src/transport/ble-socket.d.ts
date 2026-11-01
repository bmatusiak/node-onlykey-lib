/** The frame command every socket message travels under (cli/ble-link.js, the phone's src/bleSocket.ts). */
export const CMD_SOCKET: 134;
export const KIND: Readonly<{
    OPEN: 1;
    OPENED: 2;
    TEXT: 3;
    PART: 4;
    CLOSE: 5;
}>;
export const PART_MAX: 2400;
/** OPEN: the phone dials its identity's room. */
export function encodeOpen({ room }: {
    room: any;
}): Uint8Array<any>;
/** OPENED: the server's answer - the host its challenge is for. */
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
 *   {kind:'open', room} | {kind:'opened', host} | {kind:'text', text} | {kind:'close', code, reason} | null (a PART
 *   held, or a payload that is not one of these: dropped, as noise is on any link).
 */
export function createDecoder(): {
    push(payload: any): {
        kind: string;
        text: string;
        room?: undefined;
        host?: undefined;
        code?: undefined;
        reason?: undefined;
    } | {
        kind: string;
        room: any;
        text?: undefined;
        host?: undefined;
        code?: undefined;
        reason?: undefined;
    } | {
        kind: string;
        host: any;
        text?: undefined;
        room?: undefined;
        code?: undefined;
        reason?: undefined;
    } | {
        kind: string;
        code: number;
        reason: string;
        text?: undefined;
        room?: undefined;
        host?: undefined;
    } | null;
};
