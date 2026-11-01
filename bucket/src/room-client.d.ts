/**
 * @param {{url: string, me: {id: string, identityPublicKey: Uint8Array, bucketKey: object, certificate: Uint8Array},
 *   device: {id: string, name: string, kind: string}, WebSocket: any, randomBytes: (n: number) => Uint8Array,
 *   timeoutMs?: number, login?: ((asked: {host: string, nonce: Uint8Array}) => Promise<Uint8Array>) | null}} o
 */
export function connectRoom({ url, me, device, WebSocket: WS, randomBytes, timeoutMs, login }: {
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
    login?: ((asked: {
        host: string;
        nonce: Uint8Array;
    }) => Promise<Uint8Array>) | null;
}): Promise<any>;
