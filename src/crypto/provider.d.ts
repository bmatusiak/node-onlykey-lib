export function sha256(bytes: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/** SHA-256 applied `times` times (a budget's hash chain: up to 1,024 a reveal) */
export function sha256Repeat(bytes: any, times: any): any;
export function hmacSha256(key: any, msg: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/** P-256 over a message (hashed with SHA-256 first, as noble's prehash) */
export function p256Verify(sig: any, msg: any, publicKey: any, opts: any): boolean;
/**
 * P-256 over a 32-byte digest: sig = r||s (64 bytes), publicKey = SEC1 (65 bytes,
 * 0x04||x||y). Never throws: anything malformed is false.
 */
export function p256VerifyDigest(sig: any, digest: any, publicKey: any, { lowS }?: {
    lowS?: boolean | undefined;
}): boolean;
/** Ed25519, strict. Never throws: anything malformed is false. */
export function ed25519Verify(sig: any, msg: any, publicKey: any): boolean;
/**
 * Plug in a faster implementation (any subset of the functions above); null puts
 * the JS back. name is for the log and the tests.
 */
export function setCryptoProvider(provider: any, name?: string): void;
export function cryptoProviderName(): string;
export namespace js {
    function sha256(bytes: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
    function sha256Repeat(bytes: any, times: any): any;
    function hmacSha256(key: any, msg: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
    function p256VerifyDigest(sig: any, digest: any, publicKey: any): boolean;
    function ed25519Verify(sig: any, msg: any, publicKey: any): boolean;
}
