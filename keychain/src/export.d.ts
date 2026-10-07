/**
 * @param {import('../vendor/openpgp/openpgp').PrivateKey} privateKey a DECRYPTED openpgp key
 * @param {string} passphrase
 * @param {{confirm?: string|null, openpgp: any}} opts the openpgp module (src/crypto/pgp),
 *   passed in so a caller that never exports PGP never loads it (1.2 MB)
 * @returns {Promise<string>} armored
 */
export function encryptedPgp(privateKey: any, passphrase: string, { confirm, openpgp }?: {
    confirm?: string | null;
    openpgp: any;
}): Promise<string>;
import pkcs8 = require("../../src/crypto/pkcs8");
export declare let encryptedPem: typeof pkcs8.encryptedPem;
