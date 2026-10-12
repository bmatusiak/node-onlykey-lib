/**
 * @param {{type: string, publicKey?: Uint8Array, comment?: string, pgp?: string}} key
 *   type: ed25519 | x25519 | p256 | secp256k1 | rsa | mlkem768 | xwing | composite
 * @returns {{hex?: string, base64?: string, ssh?: string, age?: string, pgp?: string}}
 */
export function forKey({ type, publicKey, comment, pgp }: {
    type: string;
    publicKey?: Uint8Array;
    comment?: string;
    pgp?: string;
}): {
    hex?: string;
    base64?: string;
    ssh?: string;
    age?: string;
    pgp?: string;
};
