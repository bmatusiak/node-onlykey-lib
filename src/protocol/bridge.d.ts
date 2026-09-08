/**
 * @param {object} ctapOrTransport a CtapHid, or a transport to build one from
 * @param {object} [opts]
 * @param {function} [opts.onKeepAlive] called with the keepalive status byte
 *   while the device waits. A BLE host needs these RELAYED - the firmware sends
 *   one and then goes quiet for up to nineteen seconds waiting for a finger,
 *   and a browser hearing nothing for that long gives up on a ceremony the user
 *   is midway through confirming.
 * @param {function} [opts.log] (level, message)
 * @param {number} [opts.timeoutMs]
 * @param {number} [opts.presenceTimeoutMs]
 */
export function createCtapBridge(ctapOrTransport: object, opts?: {
    onKeepAlive?: Function | undefined;
    log?: Function | undefined;
    timeoutMs?: number | undefined;
    presenceTimeoutMs?: number | undefined;
}): {
    handle: (request: Uint8Array, perCall?: object) => Promise<Uint8Array>;
    /** The CTAPHID channel in use, or null before the first request. */
    readonly channel: any;
    /** Forget the channel, so the next request opens a new one. */
    reset(): void;
};
export namespace BRIDGE_STATUS {
    let TIMEOUT: number;
    let OTHER: number;
    let INVALID_LENGTH: number;
}
