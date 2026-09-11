/** The only protocol this firmware accepts (ctap.cpp:2217). */
export const PIN_PROTOCOL: 1;
export namespace PARAM {
    let PIN_PROTOCOL: number;
    let SUB_COMMAND: number;
    let KEY_AGREEMENT: number;
    let PIN_AUTH: number;
    let NEW_PIN_ENC: number;
    let PIN_HASH_ENC: number;
    let GET_KEY_AGREEMENT: number;
    let GET_RETRIES: number;
}
export namespace SUB {
    let GET_RETRIES_1: number;
    export { GET_RETRIES_1 as GET_RETRIES };
    let GET_KEY_AGREEMENT_1: number;
    export { GET_KEY_AGREEMENT_1 as GET_KEY_AGREEMENT };
    export let SET_PIN: number;
    export let CHANGE_PIN: number;
    export let GET_PIN_TOKEN: number;
}
export namespace RESP {
    let KEY_AGREEMENT_1: number;
    export { KEY_AGREEMENT_1 as KEY_AGREEMENT };
    export let PIN_TOKEN: number;
    export let RETRIES: number;
}
/**
 * The padded plaintext is exactly this long, always.
 *
 * The firmware recovers the PIN LENGTH by counting zero bytes backwards from
 * index 63 (`trailing_zeros(pinEnc, NEW_PIN_ENC_MIN_SIZE - 1)`,
 * ctap.cpp:2082), so the padding is not decoration - it is the length field.
 * Sending 32 bytes of ciphertext would make the firmware read whatever lies
 * at offsets 32..63 of its own buffer as part of the PIN.
 */
export const PIN_BLOCK: 64;
/** ctap.h:156-157, read through the `ret < MIN || ret >= MAX` test. */
export const PIN_MIN_BYTES: 4;
export const PIN_MAX_BYTES: 63;
/** ctap.h:436. Sixteen, not thirty-two: one AES block. */
export const PIN_TOKEN_SIZE: 16;
/**
 * A fresh platform key pair for one exchange.
 *
 * Fresh per exchange because it is free and because reusing one gives an
 * observer of the bus a long-lived handle to correlate; the authenticator
 * treats its own side as ephemeral too.
 */
export function newPlatformKey(): {
    secretKey: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
    publicKey: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
    coseKey: Map<number, any>;
};
/**
 * SHA-256 of the ECDH x coordinate - the whole key derivation for protocol 1.
 *
 * @param {Uint8Array} secretKey            the platform private key
 * @param {Map|Uint8Array} authenticatorKey the decoded COSE_Key from
 *                                          getKeyAgreement, or a raw 65-byte
 *                                          uncompressed point
 *
 * noble returns the shared point COMPRESSED - 33 bytes, a sign prefix and
 * then x - so the prefix is dropped. Hashing all 33 would produce a secret
 * that differs from the device's for half of all key pairs at random, which
 * is the kind of bug that looks like flaky hardware.
 */
export function sharedSecret(secretKey: Uint8Array, authenticatorKey: Map<any, any> | Uint8Array): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/** The PIN as the firmware wants it: UTF-8, zero-padded to 64 bytes. */
export function padPin(pin: any): Uint8Array<ArrayBuffer>;
/** AES(sharedSecret, PIN padded to 64). */
export function newPinEnc(secret: any, pin: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/** AES(sharedSecret, SHA-256(PIN) truncated to 16) - one block. */
export function pinHashEnc(secret: any, pin: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/** HMAC-SHA-256 under the shared secret, truncated to 16 bytes. */
export function pinAuth(secret: any, ...parts: any[]): Uint8Array<ArrayBufferLike>;
/**
 * The same truncated HMAC, but keyed by the PIN TOKEN rather than the shared
 * secret: this is what makeCredential, getAssertion and credential management
 * put in their own pinAuth field.
 */
export function pinTokenAuth(pinToken: any, message: any): Uint8Array<ArrayBufferLike>;
/** Ask how many attempts are left. Costs nothing and takes no PIN. */
export function retriesParams(): Map<number, number>;
/**
 * Ask for the authenticator's key agreement key.
 *
 * ONCE PER ATTEMPT. The device regenerates this pair on every PIN failure
 * (ctap.cpp:2120), so a cached copy is worth exactly one more wasted retry.
 */
export function keyAgreementParams(): Map<number, number>;
/**
 * Set a PIN on a key that has none.
 *
 * The firmware answers CTAP2_ERR_NOT_ALLOWED if one is already set
 * (ctap.cpp:2255), so a caller decides between this and `changePinParams`
 * from getInfo's `clientPin` option rather than by trying one and catching.
 */
export function setPinParams({ secret, platformKey, newPin }: {
    secret: any;
    platformKey: any;
    newPin: any;
}): Map<number, any>;
/**
 * Change a PIN, proving the current one.
 *
 * pinAuth covers newPinEnc FOLLOWED BY pinHashEnc, in that order and with
 * nothing between them (ctap.cpp:2050-2056). Swapping them produces a valid
 * HMAC of the wrong message, which the firmware reports as
 * CTAP2_ERR_PIN_AUTH_INVALID - and unlike a wrong PIN that one does NOT cost
 * an attempt, because the check happens before the counter can move.
 */
export function changePinParams({ secret, platformKey, currentPin, newPin }: {
    secret: any;
    platformKey: any;
    currentPin: any;
    newPin: any;
}): Map<number, any>;
/** Exchange the PIN for a token. No pinAuth: the hash is the proof. */
export function pinTokenParams({ secret, platformKey, pin }: {
    secret: any;
    platformKey: any;
    pin: any;
}): Map<number, any>;
/** The authenticator's key agreement key, decoded. */
export function readKeyAgreement(response: any): {
    x: Uint8Array;
    y: Uint8Array;
    uncompressed: Uint8Array;
    kty: number;
    alg: number | undefined;
    crv: number;
};
/** Attempts left before FIDO2 locks for good. */
export function readRetries(response: any): number;
/**
 * The pinToken, decrypted.
 *
 * Sixteen bytes in and sixteen out: PIN_TOKEN_SIZE is one AES block, so
 * there is exactly one block to decrypt and no padding to strip.
 */
export function readPinToken(response: any, secret: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
