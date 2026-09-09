/** OnlyKey's vendor command for the connect/derive exchange. */
export const OKCONNECT: 228;
export namespace KEYTYPE {
    let NACL: number;
    let P256R1: number;
    let P256K1: number;
    let CURVE25519: number;
    let XWING: number;
}
export namespace KEYACTION {
    let DERIVE_PUBLIC_KEY: number;
    let DERIVE_SHARED_SECRET: number;
    let DERIVE_PUBLIC_KEY_REQ_PRESS: number;
    let DERIVE_SHARED_SECRET_REQ_PRESS: number;
}
/** AES-GCM's IV here, fixed. See the note at the top of this file. */
export const IV: Uint8Array<ArrayBuffer>;
/**
 * The derivation label, as bytes.
 *
 * `Uint8Array.from()` IS NOT A STRING ENCODER. Given a string it treats it as
 * an iterable of characters and coerces each with Number(), which is NaN for
 * any letter and stores as 0 - so every passphrase collapsed to a run of zero
 * bytes whose only distinguishing feature was its LENGTH, and two different
 * labels of equal length derived the SAME key. That bug is documented in the
 * reference at onlykey-3rd-party.js:54-66, confirmed three ways, and is the
 * reason this is a named function rather than an inline cast.
 */
export function derivationInputBytes(label: any): Uint8Array<ArrayBuffer>;
/**
 * The 32-byte hash the device derives from.
 *
 * An ABSENT label is not the same as an empty one: the reference hashes 32
 * ZERO BYTES when no label is given, not the empty string. Those are different
 * keys, and treating them as one would silently move every unlabelled
 * derivation.
 */
export function derivationHash(label: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/**
 * The current time, as the four bytes the firmware expects.
 *
 * The reference formats the epoch as hex and splits it into byte pairs, which
 * is big-endian and four bytes wide until the year 2106. Written as shifts
 * here because a hex round trip through `Number` is not clearer for being
 * closer to the original.
 */
export function epochBytes(seconds?: number): Uint8Array<ArrayBuffer>;
/**
 * Build an OKCONNECT message.
 *
 *   [header(4) | OKCONNECT | epoch(4) | transit pubkey(32) | env(2) | hash(32)]
 *
 * @param {Uint8Array} transitPublicKey  this host's ephemeral NaCl box pubkey
 * @param {string} label                 what to derive from; '' means none
 * @param {string} browser  one character, echoed by the device untouched
 * @param {string} os       one character
 * @param {Uint8Array} [publicKey]  a peer public key, appended for
 *   DERIVE_SHARED_SECRET. Its absence is what makes the same frame a
 *   DERIVE_PUBLIC_KEY request - the key action in opt1 says which, and the
 *   trailing key is simply not read for the first.
 */
export function buildMessage({ transitPublicKey, label, browser, os, epochSeconds, publicKey, }?: Uint8Array): Uint8Array<ArrayBuffer>;
/** A fresh ephemeral box keypair for one exchange. */
export function newTransitKeypair(): nacl.BoxKeyPair;
/**
 * The AES key for this exchange.
 *
 * `nacl.box.before` is X25519 followed by HSalsa20, not a bare scalar
 * multiplication - using raw X25519 here produces a different key and decrypts
 * to noise. Then the hash, which happens inside the reference's aesgcm_decrypt
 * rather than at its call site.
 */
export function transitKey(devicePublicKey: any, appSecretKey: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/**
 * Undo the device's AES-GCM-without-a-tag.
 *
 * GCM is CTR mode over blocks starting at J0 + 1, and for a 12-byte IV
 * J0 is `IV || 00000001` - so the first keystream block is `IV || 00000002`.
 * With no tag to verify, decryption is exactly that CTR stream.
 */
export function decryptBody(key: any, body: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/**
 * Split a decrypted response into the device's status line and its payload.
 *
 *   [ status string, NUL-terminated ("UNLOCKEDvX.Y.Z-xxxx\0") | payload ]
 *
 * The NUL is LOCATED rather than an offset assumed, because the status string
 * grows and shrinks with the firmware version string - a fixed offset works
 * until the version number gains a digit.
 */
export function splitStatus(plaintext: any): {
    status: string;
    payload: any;
};
/**
 * A whole response: transit pubkey, then everything else encrypted.
 *
 *   [ device transit pubkey(32) | AES-GCM( status NUL payload ) ]
 *
 * Confirmed live rather than read off the firmware
 * (onlykey-3rd-party.js:498-506): with the encrypt-response flag set,
 * EVERYTHING after the transit public key is one encrypted blob -
 * ok_extension.cpp forces any truthy opt3 to that mode.
 *
 * @returns {{devicePublicKey: Uint8Array, status: string, payload: Uint8Array}}
 */
export function openResponse(response: any, appSecretKey: any, { encrypted }?: {
    encrypted?: boolean | undefined;
}): {
    devicePublicKey: Uint8Array;
    status: string;
    payload: Uint8Array;
};
/** How wide a public key is, per key type. */
export function publicKeyWidth(keytype: any): 64 | 32 | 65;
/**
 * The derived public key out of a DERIVE_PUBLIC_KEY payload.
 *
 * P-256 comes back uncompressed at 65 bytes; the 32-byte curves come back
 * bare. Taken from the END of the payload, as the reference does - the device
 * appends it after whatever else the status blob carried.
 */
export function publicKeyFrom(payload: any, keytype: any): any;
/**
 * A DERIVE_SHARED_SECRET payload, which is TWO values and not one.
 *
 * It ends with the public key AND THEN the secret:
 *
 *   [ ... | sharedPub(65 for P-256, 32 for the 25519 curves) | secret(32) ]
 *
 * so the secret is the LAST 32 BYTES and the public key sits in front of it
 * (onlykey-3rd-party.js:441-448). Reading this payload with publicKeyFrom -
 * which takes the last `width` bytes, correct for a public-key derive - hands
 * back 33 bytes of public key with the secret glued to the end of it. That is
 * not a truncated secret, it is a DIFFERENT VALUE that happens to contain the
 * right one: it looks like a plausible hex blob, it is stable per label, and
 * it does not match what any other OnlyKey client derives for that label.
 *
 * The private half is 32 bytes for every supported EC key type, so this width
 * does not vary the way the public one does.
 */
export function sharedSecretFrom(payload: any, keytype: any): {
    secret: any;
    publicKey: any;
};
/** An ECC private/shared value is 32 bytes for every supported key type. */
export const SECRET_BYTES: 32;
import nacl = require("tweetnacl");
