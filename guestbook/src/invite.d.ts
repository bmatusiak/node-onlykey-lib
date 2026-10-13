export const VERSION: 2;
export const LABEL: "okrn-contact:v1";
export const ID_LEN: 16;
export const TOKEN_LEN: 16;
export const LINK_LEN: 8;
export const PERIOD_MS: number;
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
 * A rotating invite for this phone's contact identity: a seed instead of a fixed token.
 * @returns {{id: Uint8Array, link: Uint8Array, seed: Uint8Array}}
 */
export function makeRotatingInvite({ publicKey, randomBytes }: {
    publicKey: any;
    randomBytes: any;
}): {
    id: Uint8Array;
    link: Uint8Array;
    seed: Uint8Array;
};
/** The QR's text right now, and when it next changes. */
export function inviteUrlAt(invite: any, now: any): {
    url: string;
    nextAt: number;
};
/** The tokens the showing phone accepts now: this window's and the previous one's (or a fixed one). */
export function tokensAt(invite: any, now: any): any[];
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
