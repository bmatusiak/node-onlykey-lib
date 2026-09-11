/** The OKCONNECT payload is exactly this long, before any data follows it. */
export const PREFIX: 43;
/**
 * Bytes 0..4 of the OKCONNECT payload: the vendor frame header and the message
 * id. The firmware reads the epoch at [5..8] and ignores these, and
 * onlykey-testing zero-fills them and still works on hardware - but every
 * shipped client emits them, so emit them. Costs nothing, and survives a
 * firmware revision that decides to check.
 */
export const CONNECT_HEADER: number[];
export namespace VECTORS {
    let aliceSecret: string;
    let bobPublic: string;
    let beforenm: string;
    let boxZero: string;
}
/** A fresh X25519 pair. Both halves are raw 32 bytes. */
export function keypair(): {
    secretKey: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
    publicKey: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
};
/**
 * NaCl's crypto_box_beforenm.
 *
 * NOT the raw X25519 output - that is only the first half. NaCl runs the shared
 * point through HSalsa20 with a 16-byte zero input, and the device does the
 * same, so skipping it yields a plausible-looking 32 bytes and a device that
 * answers noise. selfTest() below exists to catch exactly that mistake.
 */
export function beforenm(theirPublic: any, ourSecret: any): Uint8Array<ArrayBuffer>;
/**
 * The session key: SHA-256 over the RAW beforenm bytes.
 *
 * Raw in, raw out - no hex round trip at any point. The browser client reaches
 * the same 32 bytes via nacl.box.before() plus its own sha256, which is why
 * the two interoperate.
 */
export function transitKey(devicePublic: any, ourSecret: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/**
 * Seal or open - the same call, because the operation is its own inverse.
 *
 * GCM with a 12-byte IV is CTR over J0 = IV||00000001 with the payload
 * starting at counter block 2, so this is byte-identical to
 * gcm(key, zeroIV).encrypt(x) truncated to x.length, and it never allocates a
 * tag. That also sidesteps a practical problem: a GCM *decipher* refuses to
 * run without a tag, and there is no tag on this wire, so the open direction
 * has to be the encrypt call anyway.
 *
 * See the header for why the IV is zero and why that cannot be fixed here.
 */
export function box(key: any, data: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/**
 * The 43-byte OKCONNECT payload. Sent UNENCRYPTED - it is the key exchange.
 *
 *   [0..4]   FF FF FF FF E4   frame header + OKCONNECT
 *   [5..8]   epoch seconds, big-endian uint32
 *   [9..40]  our raw X25519 public key
 *   [41]     browser byte, display only
 *   [42]     OS byte, display only
 */
export function connectPayload(publicKey: any, opts?: {}): Uint8Array<ArrayBuffer>;
/**
 * Split an OKCONNECT reply into the device key and its status string.
 *
 * [0..31] is the device's raw X25519 public key, in the clear. [32..] is the
 * model/version string, boxed with the transit key on current firmware and
 * plaintext on some builds - so try opening it and fall back.
 *
 * The shipped client gets this wrong twice (onlykey-api.js:181-183): it reads
 * FWversion out of response.slice(40,52), which is still ciphertext, and then
 * indexes response[51] on the already-decrypted buffer, double-counting the
 * 32-byte offset. Read the version from the opened tail.
 */
export function parseConnectReply(reply: any, key: any): {
    kind: string;
    devicePublic: null;
    status: string;
    sealed: boolean;
    layout?: undefined;
} | {
    kind: string;
    layout: string;
    devicePublic: any;
    status: string;
    sealed: boolean;
};
