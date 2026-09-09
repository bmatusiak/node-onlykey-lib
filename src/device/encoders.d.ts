/**
 * The two-factor mode, sent as a LITERAL ASCII STRING.
 *
 * Not a numeric code. The device compares the text, and the values come
 * straight from the radio buttons in the original UI. Turning these into an
 * enum on the wire would be a silent protocol change.
 */
/**
 * Check a Yubico credential and report EVERY problem, without throwing.
 *
 * The builders above throw on the first thing wrong, which is right for a
 * caller assembling bytes and wrong for a form. The desktop app shows what
 * happens otherwise: `submitYubiAuthForm()` converts the public id inline, the
 * conversion throws on a hex digit where modhex was wanted, the throw escapes
 * into event dispatch, and the button appears to do nothing at all - no error,
 * no message, the fields still full, and not one byte sent to the device. See
 * onlykey-testing/FINDING-app-yubico-silent-discard.md.
 *
 * The trap is the form's own shape rather than a missing label. Three adjacent
 * fields, and the FIRST takes a different alphabet from the other two:
 *
 *   Public Identity    6 bytes MODHEX
 *   Private Identity   6 bytes hex
 *   Secret Key        16 bytes hex
 *
 * Anyone filling all three from one hex dump gets silence. So this names the
 * field, says which alphabet it wanted, and returns rather than throws.
 *
 * @param {object} spec {publicId, privateId, secretKey}
 * @param {object} [opts]
 * @param {boolean} [opts.global=false] the device-global slot-0 credential,
 *   whose public id is HEX and exactly 6 bytes - not modhex, because
 *   setYubiAuth concatenates it unchanged.
 * @returns {{ok: boolean, errors: Array<{field: string, message: string}>}}
 */
export function validateYubiCredential({ publicId, privateId, secretKey }?: object, { global }?: {
    global?: boolean | undefined;
}): {
    ok: boolean;
    errors: Array<{
        field: string;
        message: string;
    }>;
};
export const BASE32_ALPHABET: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export const MODHEX_ALPHABET: "cbdefghijklnrtuv";
export namespace YUBI {
    let PUBLIC_ID_MIN_HEX: number;
    let PUBLIC_ID_MAX_HEX: number;
    let PUBLIC_ID_GLOBAL_HEX: number;
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
 * Encode a Yubico OTP credential for a SLOT (1-24).
 *
 * The public id arrives as modhex, the way a Yubikey prints it, and is
 * converted here. Length is variable: the firmware recovers it by trimming
 * trailing zeros, so anything from 2 to 16 bytes round-trips.
 *
 * @param {object} spec
 * @param {string} spec.publicId   modhex, 2-16 bytes
 * @param {string} spec.privateId  hex, 6 bytes
 * @param {string} spec.secretKey  hex, 16 bytes
 * @returns {Uint8Array}
 */
export function yubiCredential({ publicId, privateId, secretKey }: {
    publicId: string;
    privateId: string;
    secretKey: string;
}): Uint8Array;
/**
 * Encode the device-global Yubico credential, for slot 0.
 *
 * Different in three ways from the per-slot form, none of them cosmetic: the
 * public id must be EXACTLY 6 bytes because the firmware memcpys that many, it
 * is supplied as hex rather than modhex because setYubiAuth concatenates it
 * unchanged, and it lands on the device-global pseudo-slot.
 *
 * @param {object} spec
 * @param {string} spec.publicId   hex, exactly 6 bytes
 * @param {string} spec.privateId  hex, 6 bytes
 * @param {string} spec.secretKey  hex, 16 bytes
 * @returns {Uint8Array}
 */
export function yubiGlobalCredential({ publicId, privateId, secretKey }: {
    publicId: string;
    privateId: string;
    secretKey: string;
}): Uint8Array;
