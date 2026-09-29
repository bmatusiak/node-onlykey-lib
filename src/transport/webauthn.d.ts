/**
 * A ctap for tunnel.js, backed by the browser's WebAuthn.
 *
 * @param {object} options
 * @param {{get: function}} options.credentials  navigator.credentials, injected
 * @param {string} [options.rpId]  the rpId to assert. When given it is the ONE
 *   source of truth and a tunnel asking for a different one is refused; when
 *   omitted, the tunnel's own rpId (params key 1) is used.
 * @param {number} [options.timeoutMs]  default ceremony timeout; a per-call
 *   opts.timeoutMs (tunnel.send forwards it) wins
 * @param {function} [options.randomBytes]  (n) => Uint8Array, for the challenge
 * @param {function} [options.now]  () => ms, injectable so a test can pin time
 * @param {function} [options.beforeRequest]  async () => void, awaited before
 *   EVERY credentials.get(). A page's gate: wait for document focus (a
 *   request issued into an unfocused page does not reject - it hangs until
 *   the device gives up), or ask for the user gesture Safari demands. If it
 *   rejects, nothing is sent and the call fails with code NOT_ISSUED.
 */
export function createWebAuthnCtap({ credentials, rpId, timeoutMs, randomBytes, now, beforeRequest, }?: {
    credentials: {
        get: Function;
    };
    rpId?: string | undefined;
    timeoutMs?: number | undefined;
    randomBytes?: Function | undefined;
    now?: Function | undefined;
    beforeRequest?: Function | undefined;
}): {
    rpId: string | null;
    /**
     * One tunnelled round trip.
     *
     * @param {Map} params  from ctap.assertionParams: 1 rpId, 2 clientDataHash,
     *   3 allowList
     * @param {object} [opts]
     * @param {number} [opts.timeoutMs]
     * @param {AbortSignal} [opts.signal]  to cancel the ceremony
     * @returns {Promise<Map>}  2 = authenticatorData, 3 = signature - the shape
     *   ctap.decodeAssertion reads, the same one CtapHid returns
     */
    getAssertion(params: Map<any, any>, opts?: {
        timeoutMs?: number | undefined;
        signal?: any;
    }): Promise<Map<any, any>>;
};
/**
 * An error from the browser's ceremony, with a code a host can branch on.
 *
 * `code` is ours rather than the DOMException's name, because the useful
 * distinction is not always the one the browser made - see TIMEOUT below.
 * The original is kept as `cause`.
 */
export class WebAuthnError extends Error {
    constructor(code: any, message: any, cause: any);
    code: any;
    cause: any;
}
/**
 * How long the browser is asked to wait for the ceremony, by default.
 *
 * The same order as the CTAPHID path: long enough for a person to find the key
 * and touch it. The browser treats it as a hint and clamps it to its own
 * range, so this is the upper bound a page asks for, not a guarantee.
 */
export const DEFAULT_TIMEOUT_MS: 60000;
/**
 * WebAuthn's floor for a challenge is 16 bytes. 32 matches the size of the
 * clientDataHash it stands in for.
 */
export const CHALLENGE_BYTES: 32;
