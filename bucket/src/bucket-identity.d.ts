export function bucketLabel(identityPublicKey: any): string;
export const IDENTITY_LABEL: "";
/** Is this a bucket identity id (32 lowercase hex)? */
export function isBucketIdentityId(s: any): boolean;
/** The id a bucket identity's public key goes by: 32 hex characters (the bucket's owner, its file name). */
export function identityIdOf(identityPublicKey: any): string;
/**
 * Read the key's bucket identity - no press.
 * @param {{agent: {publicKey: Function}}} okcrypto
 * @returns {Promise<{publicKey: Uint8Array, id: string}>}
 */
export function readIdentity(okcrypto: {
    agent: {
        publicKey: Function;
    };
}, opts?: {}): Promise<{
    publicKey: Uint8Array;
    id: string;
}>;
/**
 * Make the bucket key: the key's derive under its own site, turned into an Ed25519 key pair on the host.
 * @param {{deriveSecret: Function}} okcrypto
 * @param {Uint8Array} identityPublicKey the bucket identity (readIdentity) - it names whose bucket key this is
 * @param {string} site the key's ctap_bridge site (okcrypto.keySite) - required: no site, no bucket key
 * @param {object} [opts] passed to the key (confirm, onKeepAlive)
 * @returns {Promise<{secretKey: Uint8Array, publicKey: Uint8Array, version: number}>}
 */
export function deriveBucketKeyAt(okcrypto: {
    deriveSecret: Function;
}, identityPublicKey: Uint8Array, site: string, opts?: object): Promise<{
    secretKey: Uint8Array;
    publicKey: Uint8Array;
    version: number;
}>;
export const BUCKET_KEY_VERSION: 2;
export function bucketKeyLabel(identityPublicKey: any): string;
/**
 * The bucket identity signs the bucket key's public key, on the key (a press on production).
 * @returns {Promise<Uint8Array>} the 64-byte certificate signature
 */
export function certify(okcrypto: any, identityPublicKey: any, bucketPublicKey: any, opts?: {}): Promise<Uint8Array>;
/** Is this bucket key certified by this bucket identity? Never throws: false on anything malformed. */
export function verifyCertificate({ identityPublicKey, bucketPublicKey, certificate }: {
    identityPublicKey: any;
    bucketPublicKey: any;
    certificate: any;
}): boolean;
/** Sign with the bucket key, host-side, no press. */
export function sign(bucketKey: any, purpose: any, bytes: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/**
 * Is this signed by a bucket key of this bucket identity? The certificate and the signature both, or false.
 * @param {{identityPublicKey: Uint8Array, bucketPublicKey: Uint8Array, certificate: Uint8Array, purpose: string, bytes: Uint8Array, signature: Uint8Array}} o
 */
export function verify({ identityPublicKey, bucketPublicKey, certificate, purpose, bytes, signature }: {
    identityPublicKey: Uint8Array;
    bucketPublicKey: Uint8Array;
    certificate: Uint8Array;
    purpose: string;
    bytes: Uint8Array;
    signature: Uint8Array;
}): boolean;
