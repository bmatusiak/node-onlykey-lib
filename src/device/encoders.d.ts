export const BASE32_ALPHABET: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export const MODHEX_ALPHABET: "cbdefghijklnrtuv";
export namespace YUBI {
    let PUBLIC_ID_HEX: number;
    let PRIVATE_ID_HEX: number;
    let SECRET_HEX: number;
}
export namespace TFA_TYPE {
    let GOOGLE_AUTH: string;
    let YUBIKEY: string;
}
/**
 * Decode a base32 TOTP secret to bytes.
 *
 * Two defects fixed relative to OnlyKeyWizard.js:1529-1544.
 *
 * PADDING. The original does not strip '=', so indexOf returns -1, and
 * (-1).toString(2) is the string "-1", which its zero-pad turns into "000-1".
 * That corrupts the entire bit string from that point on - and '=' is present
 * on most real secrets, so this is not an edge case.
 *
 * TRUNCATION. The original emits hex nibbles and the caller does
 * .match(/.{2}/g), which silently drops a trailing odd nibble. A 26-character
 * secret is 130 bits, which is exactly where that bites.
 *
 * Whitespace is stripped because authenticator apps present secrets in groups
 * of four and people paste them that way.
 */
export function base32ToBytes(secret: any): Uint8Array<ArrayBuffer>;
/** The device wants the TOTP secret as bytes; this is the hex spelling of them. */
export function base32ToHex(secret: any): string;
/**
 * modhex to hex.
 *
 * Yubico encodes its public id in modhex - an alphabet chosen so the string
 * survives any keyboard layout. The original helper is named hexToModhex but
 * both call sites pass reverse=true, which makes it convert the other way; the
 * name is simply wrong. Named for what it does here.
 */
export function modhexToHex(modhex: any): string;
export function hexToModhex(hex: any): string;
/**
 * Encode a Yubico OTP credential for the YUBIAUTH field.
 *
 * @param {object} spec
 * @param {string} spec.publicId   modhex, as Yubico presents it
 * @param {string} spec.privateId  hex, 6 bytes
 * @param {string} spec.secretKey  hex, 16 bytes
 * @returns {Uint8Array}
 */
export function yubiCredential({ publicId, privateId, secretKey }: {
    publicId: string;
    privateId: string;
    secretKey: string;
}): Uint8Array;
