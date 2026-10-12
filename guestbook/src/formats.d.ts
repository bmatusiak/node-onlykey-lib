export const FORMATS: string[];
export const RAW_LENGTHS: {
    'raw-ed25519': number[];
    'raw-x25519': number[];
    'raw-p256': number[];
    'raw-secp256k1': number[];
    'raw-mlkem768': number[];
    'raw-xwing': number[];
};
export const MAX_TEXT: number;
export class PrivateKeyError extends Error {
    constructor();
}
/** Throws PrivateKeyError when the text carries private key material. */
export function refusePublicOnly(text: any): void;
/**
 * One authorized_keys line ([options] type base64 [comment]) -> the key, or null when the line is
 * not an SSH public key. The blob's own type string must match the line's (a mislabelled blob is
 * refused, not trusted).
 */
export function readSshLine(line: any): {
    format: string;
    text: string;
    fingerprint: string;
    label: string;
    info: {
        type: string;
        comment: string;
    };
} | null;
/** age1... (X25519) or age1onlykey... (X-Wing, 1216 bytes) -> the key, or null. */
export function readAgeRecipient(word: any): {
    format: string;
    text: string;
    fingerprint: string;
    label: string;
    info: {
        kind: string;
    };
} | null;
/** One armored public block -> the key. openpgp is passed in (the vendored fork, lazy on Hermes). */
export function readPgpBlock(openpgp: any, armored: any): Promise<{
    format: string;
    text: any;
    fingerprint: any;
    label: any;
    info: {
        users: any;
        algorithm: any;
        curve: any;
        created: any;
        expires: string;
        revoked: boolean;
    };
}>;
/** The raw formats whose public keys come in this length (the person picks one). */
export function rawCandidates(length: any): string[];
/** A raw key with its curve chosen -> the key. */
export function readRaw(text: any, format: any): {
    format: any;
    text: string;
    fingerprint: string;
    label: any;
    info: {
        bytes: number;
    };
};
/**
 * Every public key in the text (a paste, a QR, a fetched page), each format's detector in turn.
 * Private material anywhere in it refuses the whole text. A bare run of hex/base64 that could only
 * be a raw key comes back as {needsCurve: [formats]} - the person picks the curve, then readRaw.
 * @param {string} text
 * @param {{openpgp?: any}} [opts]
 * @returns {Promise<{found: object[], needsCurve: string[] | null, errors: string[]}>}
 */
export function detectAll(text: string, { openpgp }?: {
    openpgp?: any;
}): Promise<{
    found: object[];
    needsCurve: string[] | null;
    errors: string[];
}>;
