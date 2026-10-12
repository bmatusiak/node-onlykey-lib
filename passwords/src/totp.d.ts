export namespace ALGOS {
    export { sha1 as SHA1 };
    export { sha256 as SHA256 };
    export { sha512 as SHA512 };
}
/** One HOTP code. key: the secret's bytes. */
export function hotp(key: any, counter: any, { digits, algo, encoder }?: {
    digits?: number | undefined;
    algo?: string | undefined;
    encoder?: null | undefined;
}): string;
/** The code for an entry's totp field at `nowMs`. -> {code, remaining (s, TOTP only), counter} */
export function codeOf(t: any, nowMs?: number): {
    code: string;
    remaining: null;
    counter: any;
} | {
    code: string;
    remaining: number;
    counter: number;
};
/** A totp field as stored, checked. Unknown fields are dropped. */
export function shapeTotp(t: any): {
    type: string;
    secret: string;
    digits: any;
    algo: string;
};
/**
 * An otpauth:// link (the QR code's text), -> {totp, account, issuer}. Steam's links say
 * issuer=Steam (or encoder=steam); they get Steam's codes.
 */
export function parseOtpauth(uri: any): {
    totp: {
        type: string;
        secret: string;
        digits: any;
        algo: string;
    };
    account: string;
    issuer: any;
};
/**
 * Steam's secret as people have it: the `shared_secret` of a Steam Desktop Authenticator .maFile
 * (or an Aegis/andOTP export) is BASE64 of 20 bytes - 28 characters ending in one '='. Steam never
 * shows a setup QR, so this is how a Steam account gets in (spec "Steam Guard"). That form becomes
 * the base32 every entry keeps; anything else is read as base32, as the other codes are. Checked
 * before shapeTotp upper-cases the text, which would garble base64.
 */
export function steamSecret(text: any): string;
import { sha1 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { sha512 } from "@noble/hashes/sha2.js";
