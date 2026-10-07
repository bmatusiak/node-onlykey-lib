export const RSA_BITS: readonly number[];
/**
 * Make a key on this host.
 *
 * @param {'ed25519'|'x25519'|'p256'|'secp256k1'|'rsa'} type
 * @param {{bits?: number, subtle?: any}} [opts] bits for RSA; subtle defaults to globalThis.crypto.subtle
 * @returns {Promise<{type: string, publicKey: Uint8Array, keyType: number,
 *   secret?: Uint8Array, p?: Uint8Array, q?: Uint8Array, e?: number, bits?: number,
 *   material: object}>} `material` is what keys.prepareKey / device.loadKey take
 */
export function hostKey(type: "ed25519" | "x25519" | "p256" | "secp256k1" | "rsa", { bits, subtle }?: {
    bits?: number;
    subtle?: any;
}): Promise<{
    type: string;
    publicKey: Uint8Array;
    keyType: number;
    secret?: Uint8Array;
    p?: Uint8Array;
    q?: Uint8Array;
    e?: number;
    bits?: number;
    material: object;
}>;
/** Zero every byte array a hostKey() result holds. Call it once the key is loaded or exported. */
export function wipe(key: any): void;
