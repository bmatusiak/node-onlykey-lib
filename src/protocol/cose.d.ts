export namespace LABEL {
    let KTY: number;
    let ALG: number;
    let CRV: number;
    let X: number;
    let Y: number;
}
export const KTY_EC2: 2;
export const CRV_P256: 1;
/**
 * ECDH-ES + HKDF-256, which is what the authenticator says its key agreement
 * key is for (ctap.cpp:2247 passes COSE_ALG_ECDH_ES_HKDF_256). The name is
 * misleading here: PIN protocol 1 does NOT run HKDF. The shared secret is a
 * bare SHA-256 of the ECDH x coordinate - see clientpin.js.
 */
export const ALG_ECDH_ES_HKDF_256: -25;
/** ES256, for reading a credential public key out of an attestation. */
export const ALG_ES256: -7;
/**
 * A P-256 public key as a COSE_Key map, ready to hand to cbor.encode.
 *
 * @param {Uint8Array} publicKey  65-byte uncompressed (0x04 || x || y) or the
 *                                bare 64-byte x || y
 * @param {number} [alg]          defaults to ECDH-ES+HKDF-256, the only one
 *                                a clientPin key agreement ever uses
 * @returns {Map<number, *>}
 */
export function encodeP256(publicKey: Uint8Array, alg?: number): Map<number, any>;
/**
 * Read a P-256 COSE_Key back.
 *
 * @param {Map<number, *>} map  a decoded CBOR map
 * @returns {{x: Uint8Array, y: Uint8Array, uncompressed: Uint8Array,
 *            kty: number, alg: number|undefined, crv: number}}
 *
 * `uncompressed` is the 0x04-prefixed 65-byte form, because that is what
 * every ECDH implementation on this side takes as input.
 *
 * kty and crv ARE checked here, unlike on the firmware side. A key that says
 * it is P-384 and carries 32-byte coordinates is not a key we can do anything
 * useful with, and silently treating it as P-256 would produce a shared
 * secret that simply differs from the peer's with no error anywhere.
 */
export function decodeP256(map: Map<number, any>): {
    x: Uint8Array;
    y: Uint8Array;
    uncompressed: Uint8Array;
    kty: number;
    alg: number | undefined;
    crv: number;
};
