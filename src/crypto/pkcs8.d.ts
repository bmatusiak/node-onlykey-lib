export const DEFAULT_ITERATIONS: 600000;
/**
 * The unencrypted PrivateKeyInfo for one key. Never written out by itself -
 * encryptedPem() wraps it - but exported for tests and for a caller that has
 * its own envelope.
 *
 * @param {{type: 'rsa', p: Uint8Array, q: Uint8Array, e?: number}
 *   | {type: 'ed25519'|'x25519'|'p256'|'secp256k1', secret: Uint8Array}} key
 * @returns {Uint8Array}
 */
export function privateKeyInfo(key: {
    type: "rsa";
    p: Uint8Array;
    q: Uint8Array;
    e?: number;
} | {
    type: "ed25519" | "x25519" | "p256" | "secp256k1";
    secret: Uint8Array;
}): Uint8Array;
/**
 * The encrypted PEM. The passphrase is asked for twice by the caller and
 * passed as `confirm`, so the same check refuses a mismatch here too.
 *
 * @param {Parameters<typeof privateKeyInfo>[0]} key
 * @param {string} passphrase at least 25 characters (the backup passphrase's rule)
 * @param {{confirm?: string, iterations?: number, salt?: Uint8Array, iv?: Uint8Array}} [opts]
 *   salt/iv are for frozen test vectors only
 * @returns {Promise<string>}
 */
export function encryptedPem(key: Parameters<typeof privateKeyInfo>[0], passphrase: string, { confirm, iterations, salt, iv }?: {
    confirm?: string;
    iterations?: number;
    salt?: Uint8Array;
    iv?: Uint8Array;
}): Promise<string>;
