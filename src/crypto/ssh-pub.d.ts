export namespace CURVES {
    namespace ed25519 {
        let curve: string;
        let sshName: string;
        let keyType: number;
    }
    namespace nist256p1 {
        let curve_1: string;
        export { curve_1 as curve };
        let sshName_1: string;
        export { sshName_1 as sshName };
        let keyType_1: number;
        export { keyType_1 as keyType };
        export let sshCurve: string;
    }
}
export const RSA_NAME: "ssh-rsa";
/** RFC 4251 uint32: four bytes, big-endian. */
export function uint32(n: any): Uint8Array<ArrayBuffer>;
/** RFC 4251 string: a uint32 length, then the bytes (a JS string is UTF-8). */
export function string(v: any): Uint8Array<ArrayBuffer>;
/**
 * RFC 4251 mpint, from an UNSIGNED big-endian magnitude.
 *
 * The rules that make this more than `string()`: two's complement, so a
 * positive number whose top bit is set gets a 0x00 in front, or it would read
 * as negative - every RSA modulus, whose top bit is set by construction,
 * gets one; and no UNNECESSARY leading bytes - "0x00 or 0xff are not
 * allowed" beyond that one - with zero as the empty string.
 *
 * lib-agent does not follow the second rule. formats.py ecdsa_verifier()
 * frames `b'\x00' + r` and `b'\x00' + s` unconditionally, so half its
 * signatures carry a redundant zero and any r below 2^248 keeps its own
 * leading zero bytes too. OpenSSH's sshbuf_get_bignum2_bytes_direct() strips
 * leading zeros and so accepts both; a stricter verifier (RFC 4251 says the
 * encoding is canonical) need not. This one emits the canonical form.
 */
export function mpint(magnitude: any): Uint8Array<ArrayBuffer>;
export function curveInfo(curve: any): any;
/**
 * The SSH public-key blob for a key the OnlyKey returned.
 *
 *   ssh-ed25519          string "ssh-ed25519", string key(32)      RFC 8709
 *   ecdsa-sha2-nistp256  string name, string "nistp256",
 *                        string 0x04 || X || Y                     RFC 5656 3.1
 *
 * The device's P-256 reply is X||Y with no prefix (src/protocol/agent.js), so
 * the uncompressed-point 0x04 is added here.
 *
 * @param {'ed25519'|'nist256p1'} curve
 * @param {Uint8Array} raw
 * @returns {Uint8Array}
 */
export function publicKeyBlob(curve: "ed25519" | "nist256p1", raw: Uint8Array): Uint8Array;
/**
 * An authorized_keys line for a derived Ed25519 or P-256 key.
 *
 * @param {'ed25519'|'nist256p1'} curve
 * @param {Uint8Array} raw  the device's public key (32 bytes, or X||Y)
 * @param {string} [comment]
 * @returns {string}
 */
export function publicKeyLine(curve: "ed25519" | "nist256p1", raw: Uint8Array, comment?: string): string;
/**
 * The ssh-rsa public-key blob (RFC 4253 6.6):
 *
 *   string "ssh-rsa", mpint e, mpint n
 *
 * e BEFORE n - the reverse of PKCS#1's order, and the classic way to build a
 * blob that parses and names the wrong key. Both are mpints, so the modulus,
 * whose top bit is always set, carries the 0x00 sign byte (mpint above).
 *
 * @param {Uint8Array} modulus  n, unsigned big-endian (a slot's public key)
 * @param {{exponent?: number|Uint8Array}} [opts]  e, 65537 by default - what
 *   the OnlyKey and every mainstream generator use
 * @returns {Uint8Array}
 */
export function rsaPublicKeyBlob(modulus: Uint8Array, { exponent }?: {
    exponent?: number | Uint8Array;
}): Uint8Array;
/**
 * An authorized_keys line for an RSA key.
 *
 * @param {Uint8Array} modulus
 * @param {string} [comment]
 * @param {{exponent?: number|Uint8Array}} [opts]
 * @returns {string}
 */
export function rsaPublicKeyLine(modulus: Uint8Array, comment?: string, opts?: {
    exponent?: number | Uint8Array;
}): string;
