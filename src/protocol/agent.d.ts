export namespace KEY_TYPE {
    let ED25519: number;
    let P256R1: number;
    let P256K1: number;
    let CURVE25519: number;
}
export const VERSIONS: {
    1: {
        publicKey: number;
        base: number;
    };
    2: {
        publicKey: number;
        base: number;
    };
};
export const SIGN_TYPES: number[];
export const ECDH_TYPES: number[];
/** The public-key code (132 or 232). */
export function publicKeyCode(version: any, keyType: any): any;
/** The OKSIGN slot code (201-203 or 221-223). */
export function signCode(version: any, keyType: any): any;
/** The OKDECRYPT slot code for ECDH (202-204 or 222-224). */
export function ecdhCode(version: any, keyType: any): any;
/**
 * The 32 bytes a derivation is keyed by.
 *
 * @param {Uint8Array|{ssh: {user?: string, host: string}}|{gpg: string}} identity
 *   a ready hash (32 bytes), or what lib-agent hashes
 */
export function identityHash(identity: Uint8Array | {
    ssh: {
        user?: string;
        host: string;
    };
} | {
    gpg: string;
}): Uint8Array<ArrayBufferLike>;
/** How many bytes of the 64-byte report are the public key. */
export function publicKeyLength(keyType: any): 64 | 32;
/** How many bytes of the 64-byte report are the ECDH result. */
export function sharedSecretLength(keyType: any): 64 | 32;
