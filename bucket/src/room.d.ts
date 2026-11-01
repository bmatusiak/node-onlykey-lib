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
    signature: string;
    device: {
        id: string;
        name: string;
        kind: string;
    };
    login?: {
        host: string;
        nonce: string;
    } | undefined;
    t: string;
    identityPublicKey: string;
    bucketPublicKey: string;
    certificate: string;
};
/**
 * The server checks a join. Never throws.
 * @param {string} room the identity id the connection asked for
 * @param {object} msg the device's join
 * @param {{nonce: Uint8Array, host: string}} asked this connection's challenge and the server's own host
 * @param {{requireLogin?: boolean, open?: boolean}} [opts] requireLogin: only a login proof for THIS challenge enters -
 *   the key was present at this join (a kept certificate does not). open: NO PROOF AT ALL - the desktop's own local MCP
 *   (Brad, 2026-11-01: "the local mcp has no auth, but it still will communicate with the desktop app for the planner and
 *   budget calls"): a well-formed join for this room's identity, from a well-formed device, enters; nothing is verified.
 *   Only for a server no one else reaches (127.0.0.1, its own app).
 * @returns {{ok: true, identity: string, device: {id: string, name: string, kind: string}, login: boolean} | {ok: false}}
 */
export function checkJoin(room: string, msg: object, asked: {
    nonce: Uint8Array;
    host: string;
}, { requireLogin, open }?: {
    requireLogin?: boolean;
    open?: boolean;
}): {
    ok: true;
    identity: string;
    device: {
        id: string;
        name: string;
        kind: string;
    };
    login: boolean;
} | {
    ok: false;
};
/** A device as a room shows it: id 16-64 hex, a name up to 64 characters, one of KINDS - or null. */
export function deviceOf(d: any): {
    id: any;
    name: any;
    kind: any;
} | null;
/** The frame key of a room: the bucket key's secret, through HKDF, bound to the room. */
export function frameKey(bucketKey: any, roomId: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/**
 * Seal one frame body for the server to pass on.
 * @param {Uint8Array} key frameKey()
 * @param {{room: string, from: string, to: string}} who
 * @param {object} payload anything JSON
 * @param {(n: number) => Uint8Array} randomBytes
 * @returns {string} hex of nonce | ciphertext
 */
export function sealFrame(key: Uint8Array, who: {
    room: string;
    from: string;
    to: string;
}, payload: object, randomBytes: (n: number) => Uint8Array): string;
/** Open a frame body, or null when it is not one sealed for this room, from that sender, to this receiver. */
export function openFrame(key: any, who: any, body: any): any;
