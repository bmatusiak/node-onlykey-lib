export const NONCE: 32;
export const KINDS: Set<string>;
/**
 * The server's challenge for one connection.
 * @param {(n: number) => Uint8Array} randomBytes
 */
export function challenge(randomBytes: (n: number) => Uint8Array): {
    nonce: Uint8Array<ArrayBuffer>;
    message: {
        t: string;
        nonce: string;
    };
};
/**
 * A device's join, answering a server's challenge.
 * @param {{identityPublicKey: Uint8Array, bucketKey: {secretKey: Uint8Array, publicKey: Uint8Array}, certificate: Uint8Array}} me
 * @param {{nonce: string, host: string}} asked the challenge's nonce (hex) and the server's host as the device reached it
 * @param {{id: string, name: string, kind: string}} device how this device shows in the room
 */
export function join(me: {
    identityPublicKey: Uint8Array;
    bucketKey: {
        secretKey: Uint8Array;
        publicKey: Uint8Array;
    };
    certificate: Uint8Array;
}, asked: {
    nonce: string;
    host: string;
}, device: {
    id: string;
    name: string;
    kind: string;
}): {
    t: string;
    identityPublicKey: string;
    bucketPublicKey: string;
    certificate: string;
    signature: string;
    device: {
        id: string;
        name: string;
        kind: string;
    };
};
/**
 * The server checks a join. Never throws.
 * @param {string} room the identity id the connection asked for
 * @param {object} msg the device's join
 * @param {{nonce: Uint8Array, host: string}} asked this connection's challenge and the server's own host
 * @returns {{ok: true, identity: string, device: {id: string, name: string, kind: string}} | {ok: false}}
 */
export function checkJoin(room: string, msg: object, asked: {
    nonce: Uint8Array;
    host: string;
}): {
    ok: true;
    identity: string;
    device: {
        id: string;
        name: string;
        kind: string;
    };
} | {
    ok: false;
};
/** A device as a room shows it: id 16-64 hex, a name up to 64 characters, one of KINDS - or null. */
export function deviceOf(d: any): {
    id: any;
    name: any;
    kind: any;
} | null;
