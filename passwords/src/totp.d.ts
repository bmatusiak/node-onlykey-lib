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
import { sha1 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { sha512 } from "@noble/hashes/sha2.js";
