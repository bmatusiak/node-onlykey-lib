export const VERSION: 2;
export const LABEL: "okrn-contact:v1";
export const ID_LEN: 16;
export const TOKEN_LEN: 16;
export const LINK_LEN: 8;
/** The id of a contact identity: SHA-256("okrn-contact/id/v1" || X-Wing public key), first 16 bytes. */
export function idOf(publicKey: any): Uint8Array<ArrayBuffer>;
/**
 * A new invite for this phone's contact identity.
 * @param {{publicKey: Uint8Array, randomBytes: (n: number) => Uint8Array}} p
 * @returns {{id: Uint8Array, token: Uint8Array, link: Uint8Array, url: string}}
 */
export function makeInvite({ publicKey, randomBytes }: {
    publicKey: Uint8Array;
    randomBytes: (n: number) => Uint8Array;
}): {
    id: Uint8Array;
    token: Uint8Array;
    link: Uint8Array;
    url: string;
};
/**
 * Read an invite from what a QR scan or a link gave. Throws naming what is wrong.
 * @param {string} text
 * @returns {{id: Uint8Array, token: Uint8Array, link: Uint8Array}}
 */
export function readInvite(text: string): {
    id: Uint8Array;
    token: Uint8Array;
    link: Uint8Array;
};
import { toHex } from "../../src/bytes";
export { toHex };
