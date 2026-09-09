/**
 * The HKDF info string, byte for byte from the web app.
 *
 * It is domain separation, so it is not a label anyone may tidy: change it and
 * every vault entry ever written becomes unreadable, with no error beyond a
 * failed tag check.
 */
export const HKDF_INFO: Uint8Array<ArrayBuffer>;
/**
 * A 32-byte ZERO salt, which is what the web app passes.
 *
 * Not an oversight to fix. HKDF with an empty or zero salt is well defined and
 * the input keying material here is already a high-entropy ECDH secret, so the
 * salt is doing nothing either way - but it is part of the derivation, and
 * substituting a random salt would produce different keys for the same secret
 * and silently orphan every stored credential.
 */
export const HKDF_SALT: Uint8Array<ArrayBuffer>;
/** AES-GCM nonce length, in bytes. */
export const NONCE_BYTES: 12;
/** AES-GCM tag length, in bytes. */
export const TAG_BYTES: 16;
export const DEFAULT_POLICY: "session:30m";
/**
 * The device's ECDH secret to a 256-bit AES key.
 *
 * @param {Uint8Array} sharedSecret  from derive_shared_secret
 * @returns {Uint8Array} 32 bytes
 */
export function deriveVaultKey(sharedSecret: Uint8Array): Uint8Array;
/**
 * Encrypt one credential.
 *
 * The blob is `nonce || ciphertext || tag`, base64, exactly as the web app
 * writes it - a fresh 12-byte nonce prepended to what AES-GCM produced.
 *
 * @param {Uint8Array} key        from deriveVaultKey
 * @param {string} plaintext
 * @param {function} randomBytes  (n) => Uint8Array
 */
export function seal(key: Uint8Array, plaintext: string, randomBytes: Function): string;
/**
 * Decrypt one credential.
 *
 * A tag failure throws, and that is the only signal there is: AES-GCM does not
 * distinguish "wrong key" from "tampered blob", and neither should this.
 */
export function open(key: any, blob: any): string;
/**
 * How long a derived key may be kept, from a policy string.
 *
 * The vocabulary is the web app's:
 *
 *   'always'       never cache - touch the device every single time
 *   'startup'      keep until the process ends
 *   'session:30m'  keep for 30 minutes
 *   'session:2h'   keep for 2 hours
 *
 * Anything unrecognised means 'always', which is the fail-closed direction: a
 * typo in a policy costs an extra touch rather than caching a key forever.
 *
 * SLIDING IS DECIDED BY LENGTH, not stated. A window of an hour or less slides
 * - each use restarts it - and anything longer is absolute. That is the web
 * app's rule (`sliding: ttlMs <= 3600000`) and it is preserved rather than
 * tidied, because the two disagree about when a key expires and a user who set
 * 2h on one client should not get a different answer on another.
 */
export function parsePolicy(policy: any): {
    ttlMs: number;
    sliding: boolean;
    noCache: boolean;
};
/**
 * A TTL cache of derived keys, one per service.
 *
 * `now` is injectable so the expiry rules can be tested without waiting for
 * them, and there is no timer in here at all. The web app runs a reaper every
 * 30 seconds; a library that installed its own interval would keep a host
 * process alive and would have to be torn down. `reap()` is exposed instead
 * and the host decides whether to call it on a schedule, on resume, or never -
 * `get()` already refuses an expired entry, so a reaper only controls how long
 * dead key material sits in memory.
 */
export function createSessionCache({ now, defaultPolicy }?: {
    now?: (() => number) | undefined;
    defaultPolicy?: string | undefined;
}): {
    getPolicy(serviceId: any): any;
    setPolicy(serviceId: any, policy: any): void;
    get(serviceId: any): any;
    put(serviceId: any, key: any): boolean;
    evict(serviceId: any): boolean;
    clear(): void;
    /** Drop everything expired. Returns the service ids that went. */
    reap(): any[];
    /** What is cached and for how much longer, for a sessions panel. */
    status(): {
        serviceId: any;
        policy: any;
        sliding: any;
        remainingMs: number;
        remaining: string;
    }[];
    readonly size: number;
};
