/** Little-endian encodings, bit 255 clear. See the note above for each. */
export const LOW_ORDER_U: Uint8Array<ArrayBuffer>[];
/**
 * Whether a 32-byte X25519 u-coordinate is one of the low-order encodings.
 *
 * Bit 255 is masked first, as RFC 7748 section 5 says a receiver MUST, so 0x80 in
 * the last byte cannot smuggle a listed point past the comparison. Every entry
 * is compared in full, whatever matched first - the answer is about a PUBLIC
 * key, but there is no reason to make the time depend on which one.
 *
 * @param {Uint8Array} u
 * @returns {boolean}
 */
export function isLowOrderU(u: Uint8Array): boolean;
/**
 * Refuse an X25519 peer point of low order, before it is used or sent.
 *
 * @param {Uint8Array} u      the peer's 32-byte u-coordinate
 * @param {string} [what]     named in the error: whose point it was
 */
export function assertPeerNotLowOrder(u: Uint8Array, what?: string): void;
/**
 * Refuse an all-zero shared secret - RFC 7748 section 6.1's own check.
 *
 * Applied to every secret a device RETURNS, not only X25519 ones: an all-zero
 * ECDH result is what a low-order peer produces on the 25519 curves, and on
 * P-256 or secp256k1 it is not a value real ECDH produces at all, so it can
 * only mean a zero-filled buffer or a peer chosen to produce it.
 *
 * @param {Uint8Array} secret
 * @param {string} [what]
 */
export function assertNonZeroSecret(secret: Uint8Array, what?: string): void;
