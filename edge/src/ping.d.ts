export const PING_TYPE: "ping";
export const PONG_TYPE: "pong";
export const RECEIPT_TYPE: "ping-receipt";
export const PING_MAX: 8192;
/** the computer's message for these bytes */
export function buildPing(data: any): {
    type: string;
    id: string;
    data: string;
};
/**
 * The phone's answer: the same id and data, nothing looked at but the shape -
 * or null (not a ping, or not one this phone sends back).
 */
/**
 * @param {any} message
 * @param {{firstAt?: number|null, rxAt?: number|null, now?: () => number}} [times]
 */
export function answerPing(message: any, { firstAt, rxAt, now }?: {
    firstAt?: number | null;
    rxAt?: number | null;
    now?: () => number;
}): {
    type: string;
    id: any;
    data: any;
    firstAt: number | null;
    rxAt: number | null;
    txAt: number;
} | null;
/** -> {ok: true} when the answer is our id and its data hashes to it; else {ok: false, why} */
export function checkPong(sent: any, answer: any): {
    ok: boolean;
    why: string;
    bytes?: undefined;
} | {
    ok: boolean;
    bytes: number;
    why?: undefined;
};
