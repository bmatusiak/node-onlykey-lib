/**
 * @param {{url: string, me: {id: string, identityPublicKey: Uint8Array, bucketKey: object, certificate: Uint8Array},
 *   device: {id: string, name: string, kind: string}, WebSocket: any, randomBytes: (n: number) => Uint8Array,
 *   timeoutMs?: number}} o
 */
export function connectRoom({ url, me, device, WebSocket: WS, randomBytes, timeoutMs }: {
    url: string;
    me: {
        id: string;
        identityPublicKey: Uint8Array;
        bucketKey: object;
        certificate: Uint8Array;
    };
    device: {
        id: string;
        name: string;
        kind: string;
    };
    WebSocket: any;
    randomBytes: (n: number) => Uint8Array;
    timeoutMs?: number;
}): Promise<any>;
