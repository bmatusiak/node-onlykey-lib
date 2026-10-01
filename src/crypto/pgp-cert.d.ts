export namespace ALGO {
    let ECDH: number;
    let ECDSA: number;
    let EDDSA_LEGACY: number;
}
export namespace OID {
    let ed25519: Uint8Array<ArrayBuffer>;
    let cv25519: Uint8Array<ArrayBuffer>;
    let p256: Uint8Array<ArrayBuffer>;
}
export namespace CURVES {
    export namespace ed25519_1 {
        namespace sign {
            import algo = ALGO.EDDSA_LEGACY;
            export { algo };
            import oid = OID.ed25519;
            export { oid };
            export let keyType: number;
            export let grip: string;
        }
        namespace ecdh {
            import algo_1 = ALGO.ECDH;
            export { algo_1 as algo };
            import oid_1 = OID.cv25519;
            export { oid_1 as oid };
            let keyType_1: number;
            export { keyType_1 as keyType };
            let grip_1: string;
            export { grip_1 as grip };
        }
    }
    export { ed25519_1 as ed25519 };
    export namespace nist256p1 {
        export namespace sign_1 {
            import algo_2 = ALGO.ECDSA;
            export { algo_2 as algo };
            import oid_2 = OID.p256;
            export { oid_2 as oid };
            let keyType_2: number;
            export { keyType_2 as keyType };
            let grip_2: string;
            export { grip_2 as grip };
        }
        export { sign_1 as sign };
        export namespace ecdh_1 {
            import algo_3 = ALGO.ECDH;
            export { algo_3 as algo };
            import oid_3 = OID.p256;
            export { oid_3 as oid };
            let keyType_3: number;
            export { keyType_3 as keyType };
            let grip_3: string;
            export { grip_3 as grip };
        }
        export { ecdh_1 as ecdh };
    }
}
export function openpgpPoint(raw: any): Uint8Array<ArrayBuffer>;
/**
 * A v4 ECC public-key packet body (RFC 4880 5.5.2, RFC 6637 9) - the one
 * hand-encoded piece, see the top of the file.
 *
 * @param {{algo: number, oid: Uint8Array}} kind  CURVES[..].sign or .ecdh
 * @param {Uint8Array} raw  the device's public key, 32 or 64 bytes
 * @param {number} created  seconds since the epoch
 * @returns {Uint8Array}
 */
export function keyPacketBody(kind: {
    algo: number;
    oid: Uint8Array;
}, raw: Uint8Array, created: number): Uint8Array;
/**
 * The 20-byte keygrip, as upper-case hex (how gpg sends it).
 *
 * @param {'ed25519'|'cv25519'|'p256'} grip
 * @param {Uint8Array} raw  the device's public key, 32 or 64 bytes
 * @returns {string}
 */
export function keygrip(grip: "ed25519" | "cv25519" | "p256", raw: Uint8Array): string;
/**
 * Does a device signature over an OpenPGP digest verify?
 *
 * Ed25519 (legacy EdDSA in OpenPGP) signs the digest bytes AS THE MESSAGE.
 * ECDSA signs the digest as the hash, truncated to the curve's 256 bits -
 * which is what the device is given (lib-agent client.py sign() cuts it to
 * 32 bytes) and what gpg verifies against. lowS is off: ECDSA has no low-S
 * rule and the device does not normalise S.
 *
 * @param {number} keyType  1 Ed25519, 2 P-256
 * @returns {boolean}
 */
export function verifyDigest(keyType: number, raw: any, digest: any, sig: any): boolean;
export function kindOf(algo: any, oidBytes: any): any;
/**
 * The public certificate: primary signing key, then per user id the user id
 * and the device's positive certification (0x13), then the ECDH subkey and
 * the device's subkey binding (0x18) - lib-agent's create_primary +
 * create_subkey, one device signature per user id plus one, in that order.
 *
 * @param {object} openpgp  the vendored fork (`node-onlykey-lib/crypto/pgp`)
 * @param {object} opts
 * @param {string} [opts.userId]  one user id, or:
 * @param {string[]} [opts.userIds]  several; the first is the primary. At
 *   least one is required. The device keys are derived from ONE of them -
 *   the first, by lib-agent's rule - and that derivation is the caller's.
 * @param {'ed25519'|'nist256p1'} opts.curve
 * @param {number|Date} [opts.created=0]  key AND signature time, seconds
 *   since the epoch (or a Date). 0 is lib-agent's default, see the top.
 * @param {number|Date} [opts.expires]  absent: the key never expires, and no
 *   Key Expiration Time subpacket is written (lib-agent's certificate). A
 *   number is seconds after `created` (the subpacket's own unit); a Date is
 *   the moment it expires. Written into every self-signature, so the primary
 *   and the subkey expire together.
 * @param {Uint8Array} opts.signPublic  the device's signing public key
 * @param {Uint8Array} opts.ecdhPublic  the device's ECDH public key
 * @param {(digest: Uint8Array, what: string) => Promise<Uint8Array>} opts.sign
 *   the device's 64-byte r||s over `digest` with the signing key
 * @returns {Promise<{armored: string, bytes: Uint8Array, fingerprint: string,
 *   subkeyFingerprint: string, keygrips: {sign: string, ecdh: string}}>}
 */
export function buildCertificate(openpgp: object, { userId, userIds, curve, created, expires, signPublic, ecdhPublic, sign, }?: {
    userId?: string | undefined;
    userIds?: string[] | undefined;
    curve: "ed25519" | "nist256p1";
    created?: number | Date | undefined;
    expires?: number | Date | undefined;
    signPublic: Uint8Array;
    ecdhPublic: Uint8Array;
    sign: (digest: Uint8Array, what: string) => Promise<Uint8Array>;
}): Promise<{
    armored: string;
    bytes: Uint8Array;
    fingerprint: string;
    subkeyFingerprint: string;
    keygrips: {
        sign: string;
        ecdh: string;
    };
}>;
