/**
 * A ctap for okcrypto over the vendor interface of `transport` (a USB or embedded transport: on(report), write).
 * @param {object} transport
 * @param {{timeoutMs?: number}} [o] - how long one request may wait for its answer (a press, a CTAP operation pending)
 */
export function createVendorBridgeCtap(transport: object, { timeoutMs }?: {
    timeoutMs?: number;
}): {
    vendorBridge: boolean;
    /** End every request still waiting, with ECANCELED: the key is gone, so none waits out its timeout. */
    cancel(why?: string): void;
    getAssertion(params: any, opts?: {}): Promise<Map<number, any>>;
};
export const OKVENDORBRIDGE: 253;
