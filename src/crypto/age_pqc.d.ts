export function mlkemKeypairFromSeed(mlkemSeed: any): {
    secretKey: import("@noble/post-quantum/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array>;
    publicKey: import("@noble/post-quantum/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array>;
};
export function buildRecipient(pkX: any, mlkemSeed: any): Uint8Array<any>;
export function xwingCombiner(ssM: any, ssX: any, ctX: any, pkX: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function splitDecapsulate(ssX: any, ciphertext: any, pkX: any, mlkemSeed: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function ctXOf(ciphertext: any): any;
export function xwingEncapsHost(pk: any): {
    sharedSecret: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
    ciphertext: Uint8Array<any>;
};
export function deriveLabelTag(label: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function encodeRecipient(pubkey: any): string;
export function decodeRecipient(recipient: any): Uint8Array<ArrayBuffer>;
export function encodeIdentity(label: any): string;
/**
 * @param {number} slot        101..116
 * @param {Uint8Array} [pubkey] the slot's X-Wing public key. Without it the
 *                              one-byte form is written, which is what the
 *                              Python plugin emits - offered so a caller that
 *                              genuinely has no public key to hand can still
 *                              produce something both clients read.
 */
export function encodeSlotIdentity(slot: number, pubkey?: Uint8Array): string;
/**
 * Read either kind of identity.
 *
 * @returns {{derived: true, label: string}
 *          |{derived: false, slot: number, fingerprint: Uint8Array|null,
 *            legacy: boolean}
 *          |null}
 */
export function decodeIdentity(s: any): {
    derived: true;
    label: string;
} | {
    derived: false;
    slot: number;
    fingerprint: Uint8Array | null;
    legacy: boolean;
} | null;
/**
 * Does this identity still name the key it was made for?
 *
 * @returns true when it cannot tell - a one-byte identity carries no
 *          fingerprint, and refusing what the Python plugin writes would make
 *          the two clients unable to share a file.
 */
export function identityMatchesKey(identity: any, pubkey: any): boolean;
/** SHA-256(pubkey)[0..8] - cli.py's recipient_fingerprint. */
export function recipientFingerprint(pubkey: any): Uint8Array<ArrayBufferLike>;
export const IDENTITY_VERSION: 1;
export const IDENTITY_FINGERPRINT_LEN: 8;
export const XWING_LABEL: Uint8Array<ArrayBuffer>;
export const MLKEM_PK: 1184;
export const MLKEM_CT: 1088;
export const XWING_PK: 1216;
export const XWING_CT: 1120;
export const SEED: 32;
