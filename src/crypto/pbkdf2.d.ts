/**
 * PBKDF2-HMAC-SHA256, native where the platform has it.
 * @param {Uint8Array} password
 * @param {Uint8Array} salt
 * @param {number} iterations
 * @param {number} dkLen bytes
 * @param {{onProgress?: ((fraction: number) => void) | null}} [opts]
 * @returns {Promise<Uint8Array>}
 */
export function pbkdf2Sha256(password: Uint8Array, salt: Uint8Array, iterations: number, dkLen: number, { onProgress }?: {
    onProgress?: ((fraction: number) => void) | null;
}): Promise<Uint8Array>;
/**
 * The plain loop, with progress. Kept separate so the shim can use it and the
 * tests can drive it directly.
 * @param {Uint8Array} password
 * @param {Uint8Array} salt
 * @param {number} iterations
 * @param {number} dkLen bytes
 * @param {{onProgress?: ((fraction: number) => void) | null}} [opts]
 * @returns {Promise<Uint8Array>}
 */
export function pbkdf2Loop(password: Uint8Array, salt: Uint8Array, iterations: number, dkLen: number, { onProgress }?: {
    onProgress?: ((fraction: number) => void) | null;
}): Promise<Uint8Array>;
