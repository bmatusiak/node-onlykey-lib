/**
 * @param {{type: string, publicKey: Uint8Array, comment?: string}} key
 *   type: ed25519 | x25519 | p256 | secp256k1 | rsa | mlkem768 | xwing
 * @returns {{hex: string, base64: string, ssh?: string, age?: string}}
 */
export function forKey({ type, publicKey, comment }: {
    type: string;
    publicKey: Uint8Array;
    comment?: string;
}): {
    hex: string;
    base64: string;
    ssh?: string;
    age?: string;
};
