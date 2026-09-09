/** @param {string} text */
export function utf8ToBytes(text: string): Uint8Array<ArrayBuffer>;
/** @param {Uint8Array} bytes */
export function bytesToUtf8(bytes: Uint8Array): string;
/**
 * base64, implemented rather than taken from the platform.
 *
 * Node has Buffer, browsers have btoa, and React Native has neither reliably -
 * atob/btoa only landed in recent versions and Hermes has no Buffer at all.
 * Twenty lines is cheaper than a polyfill dependency or a runtime branch.
 */
export function toBase64(bytes: any): string;
export function fromBase64(text: any): Uint8Array<ArrayBuffer>;
/**
 * base64url, unpadded - which is what a JWK `k` member is.
 *
 * This is not a formatting preference. The web app turns a derived secret into
 * a password by importing the raw bytes as an AES-GCM key and exporting the
 * JWK, then taking `k` (build_AESGCM, onlykey-3rd-party.js:95):
 *
 *     crypto.subtle.importKey('raw', secret, {name:'AES-GCM'}, true, ...)
 *     crypto.subtle.exportKey('jwk', key).then(({k}) => k)
 *
 * RFC 7517 says a JWK octet key is base64url with the padding removed, so `k`
 * is exactly this function's output over the same 32 bytes. Rendering the
 * secret as hex instead gives a different password for the same site, which is
 * a silent incompatibility rather than an error - the user simply cannot log
 * in with the one this app shows.
 *
 * It matters twice over: the vault feeds the UTF-8 of this string into HKDF as
 * its key material, so getting the encoding wrong changes the vault key too.
 */
export function toBase64Url(bytes: any): string;
/** The inverse, tolerant of missing padding. */
export function fromBase64Url(text: any): Uint8Array<ArrayBuffer>;
/** @param {Uint8Array|number[]} bytes */
export function toHex(bytes: Uint8Array | number[]): string;
/**
 * Accepts separators, because hex that a human typed or a log printed is worth
 * being able to paste straight back in.
 * @param {string} hex
 */
export function fromHex(hex: string): Uint8Array<ArrayBuffer>;
/** `01 ff 00 aa` - for logs and assertion messages. */
export function formatHex(bytes: any): string;
/**
 * latin1, not UTF-8.
 *
 * The firmware's strings are single bytes and its binary payloads must survive
 * a round trip unchanged; UTF-8 would mangle anything above 0x7f. This matches
 * okmsg.text()'s `toString('latin1')` upstream.
 * @param {Uint8Array} bytes
 */
export function toLatin1(bytes: Uint8Array): string;
/** @param {string} text */
export function fromLatin1(text: string): Uint8Array<ArrayBuffer>;
/**
 * Printable ASCII only, for showing a report that may be text or may be
 * binary. Unlike toLatin1 this drops what it cannot show rather than emitting
 * control characters into a log.
 * @param {Uint8Array} bytes
 */
export function toPrintable(bytes: Uint8Array): string;
/** @param {Array<Uint8Array>} chunks */
export function concat(chunks: Array<Uint8Array>): Uint8Array<ArrayBuffer>;
/**
 * Constant-time comparison.
 *
 * Present because this library compares MACs and derived keys, and the
 * obvious `===` on a hex string leaks through early exit. Length is not
 * secret, so returning early on it is fine.
 */
export function equalConstantTime(a: any, b: any): boolean;
