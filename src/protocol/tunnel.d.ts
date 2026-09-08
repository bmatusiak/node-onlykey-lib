/**
 * Send one vendor command through the tunnel.
 *
 * @param {object} ctap   a CtapHid with a channel already allocated
 * @param {object} req    {cmd, opt1, opt2, opt3, data}
 * @param {object} opts
 * @param {function} opts.randomBytes  required unless clientDataHash is given
 * @param {Uint8Array} [opts.clientDataHash]  32 bytes, for a reproducible test
 * @param {string} [opts.rpId]
 * @param {function} [opts.onKeepAlive]  called while the device waits for a press
 * @param {number} [opts.timeoutMs]
 */
export function send(ctap: object, req: object, opts?: {
    randomBytes: Function;
    clientDataHash?: Uint8Array<ArrayBufferLike> | undefined;
    rpId?: string | undefined;
    onKeepAlive?: Function | undefined;
    timeoutMs?: number | undefined;
}): Promise<{
    status: string;
    code: number;
    data: Uint8Array | null;
    error: string | null;
    count: number | null;
}>;
/**
 * Bind a tunnel to one CtapHid and one source of randomness.
 *
 * The form a plugin wants: everything platform-specific is supplied once, and
 * callers afterwards pass only the request.
 */
export function createTunnel(ctap: any, { randomBytes, rpId }?: {
    rpId?: string | undefined;
}): {
    rpId: string;
    send(req: any, opts?: {}): Promise<{
        status: string;
        code: number;
        data: Uint8Array | null;
        error: string | null;
        count: number | null;
    }>;
};
import { RP_ID } from "./ctap";
export { RP_ID };
