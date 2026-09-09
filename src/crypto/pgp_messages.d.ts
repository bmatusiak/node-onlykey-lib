/**
 * An armoured key, or an openpgp Key object already in hand.
 */
export type KeyLike = string | object;
/**
 * One signature's verdict.
 *
 * `valid` is false rather than absent when verification failed, and `error`
 * says why - openpgp's own result rejects a promise instead, which surfaces as
 * an unhandled rejection somewhere unrelated.
 */
export type SignatureResult = {
    keyID: string;
    valid: boolean;
    error: string | null;
};
/**
 * Encrypt text to one or more recipients.
 *
 * @param {object} openpgp the vendored fork
 * @param {{
 *   text: string,
 *   recipients: KeyLike|KeyLike[],
 *   signWith?: KeyLike|KeyLike[]|null,
 *   passphrase?: string|null,
 *   armor?: boolean,
 * }} opts
 * @returns {Promise<string|Uint8Array>} armoured text, or bytes when armor is false
 */
export function encryptText(openpgp: object, { text, recipients, signWith, passphrase, armor, }?: {
    text: string;
    recipients: KeyLike | KeyLike[];
    signWith?: KeyLike | KeyLike[] | null;
    passphrase?: string | null;
    armor?: boolean;
}): Promise<string | Uint8Array>;
/**
 * Encrypt a file's bytes.
 *
 * `filename` travels inside the message. openpgp defaults it to 'msg.txt',
 * which is wrong for a file and is what the receiving client will offer to save
 * it as, so it is passed explicitly.
 *
 * @param {object} openpgp
 * @param {{
 *   data: Uint8Array,
 *   filename?: string,
 *   recipients: KeyLike|KeyLike[],
 *   signWith?: KeyLike|KeyLike[]|null,
 *   passphrase?: string|null,
 *   armor?: boolean,
 * }} opts
 * @returns {Promise<string|Uint8Array>}
 */
export function encryptFile(openpgp: object, { data, filename, recipients, signWith, passphrase, armor, }?: {
    data: Uint8Array;
    filename?: string;
    recipients: KeyLike | KeyLike[];
    signWith?: KeyLike | KeyLike[] | null;
    passphrase?: string | null;
    armor?: boolean;
}): Promise<string | Uint8Array>;
/**
 * Read a message back.
 *
 * ## Verification failures do not throw here
 *
 * openpgp's signature results are promises that REJECT when a signature is bad,
 * and a caller that does not await them individually gets an unhandled
 * rejection rather than an answer. Worse, `expectSigned` would make a bad
 * signature indistinguishable from a bad key at the call site.
 *
 * So each signature is awaited and reported: `signatures` is a list of
 * `{ keyID, valid, error }`. A caller decides what to do about an invalid one -
 * which is the only place that decision can sensibly be made, since "encrypted
 * to me but signed by someone I do not know" is a different problem in a chat
 * client than in a backup tool.
 *
 * @param {object} openpgp
 * @param {{
 *   armored?: string|null,
 *   binary?: Uint8Array|null,
 *   decryptWith: KeyLike|KeyLike[],
 *   passphrase?: string|null,
 *   verifyWith?: KeyLike|KeyLike[]|null,
 *   format?: 'utf8'|'binary',
 * }} opts
 * @returns {Promise<{data: string|Uint8Array, filename: string, signatures: SignatureResult[]}>}
 */
export function decryptMessage(openpgp: object, { armored, binary, decryptWith, passphrase, verifyWith, format, }?: {
    armored?: string | null;
    binary?: Uint8Array | null;
    decryptWith: KeyLike | KeyLike[];
    passphrase?: string | null;
    verifyWith?: KeyLike | KeyLike[] | null;
    format?: "utf8" | "binary";
}): Promise<{
    data: string | Uint8Array;
    filename: string;
    signatures: SignatureResult[];
}>;
/**
 * Sign text without encrypting it.
 *
 * `detached` produces a signature that travels separately from the text;
 * otherwise the result is a cleartext-signed message, which is the form a
 * person can still read without a PGP client.
 *
 * @param {object} openpgp
 * @param {{
 *   text: string,
 *   signWith: KeyLike|KeyLike[],
 *   passphrase?: string|null,
 *   detached?: boolean,
 *   armor?: boolean,
 * }} opts
 * @returns {Promise<string|Uint8Array>}
 */
export function signText(openpgp: object, { text, signWith, passphrase, detached, armor, }?: {
    text: string;
    signWith: KeyLike | KeyLike[];
    passphrase?: string | null;
    detached?: boolean;
    armor?: boolean;
}): Promise<string | Uint8Array>;
/**
 * Check a signature.
 *
 * Handles both shapes: a cleartext-signed message carrying its own text, and a
 * detached signature over text supplied separately. Which one it is is decided
 * by whether `text` was given, not by inspecting the armour - a caller that
 * holds the text knows which it meant.
 *
 * @param {object} openpgp
 * @param {{
 *   armored: string,
 *   text?: string|null,
 *   verifyWith: KeyLike|KeyLike[],
 * }} opts
 * @returns {Promise<{data: string|Uint8Array, signatures: SignatureResult[], valid: boolean}>}
 */
export function verifyText(openpgp: object, { armored, text, verifyWith, }?: {
    armored: string;
    text?: string | null;
    verifyWith: KeyLike | KeyLike[];
}): Promise<{
    data: string | Uint8Array;
    signatures: SignatureResult[];
    valid: boolean;
}>;
/**
 * An armoured key, or an openpgp Key object already in hand.
 *
 * @typedef {string|object} KeyLike
 */
/**
 * One signature's verdict.
 *
 * `valid` is false rather than absent when verification failed, and `error`
 * says why - openpgp's own result rejects a promise instead, which surfaces as
 * an unhandled rejection somewhere unrelated.
 *
 * @typedef {{keyID: string, valid: boolean, error: string|null}} SignatureResult
 */
/**
 * Read one or more public keys from armour.
 *
 * Takes a single armoured block or an array of them, and always returns an
 * array - because "encrypt to one recipient" and "encrypt to three" should not
 * be different call shapes at the caller.
 */
export function readPublicKeys(openpgp: any, armored: any): Promise<any[]>;
/** The same, for private keys, unlocking with a passphrase when one is given. */
export function readPrivateKeys(openpgp: any, armored: any, passphrase: any): Promise<any[]>;
/** Is this text a PGP message, a signed message, or neither? */
export function classifyArmor(text: any): "unknown" | "public-key" | "signature" | "message" | "signed" | "private-key";
/**
 * Turn openpgp's signature promises into plain results.
 *
 * Each `verified` is a promise that REJECTS on a bad signature. Leaving them
 * unawaited produces an unhandled rejection somewhere else entirely, which is
 * the kind of failure that gets blamed on the wrong subsystem.
 *
 * @param {object[]} signatures
 * @returns {Promise<SignatureResult[]>}
 */
export function describeSignatures(signatures: object[]): Promise<SignatureResult[]>;
import { utf8ToBytes } from "../bytes";
export { utf8ToBytes };
