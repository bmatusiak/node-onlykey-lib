export const ROUNDS: 600000;
/**
 * The derive label of an entry's own key (deviceVault adds `vault:`). `ref` is the entry's own
 * random reference, kept in `inner.ref` - not the record id, so a new entry is sealed before the
 * store has given it one, and the label never changes.
 */
export function entryLabel(ref: any): string;
/** a new key-sealed entry's ref: 16 random bytes, hex */
export function newRef(randomBytes: any): string;
/**
 * A passphrase entry's key: PBKDF2 (600k) of the passphrase, combined with the manager key by HKDF.
 * `pbkdf2(password, salt, rounds, dkLen)`: the host's own, when it has one - ok-rn passes OkSSL's
 * (NativeKdf), so the 600k rounds run in OpenSSL, not through WebCrypto or JS. Without it, the
 * lib's pbkdf2Sha256.
 *
 * @param {{passphrase: string, salt: Uint8Array, managerKey: Uint8Array,
 *   onProgress?: ((done: number) => void) | null,
 *   pbkdf2?: ((password: Uint8Array, salt: Uint8Array, rounds: number, dkLen: number) => Promise<Uint8Array>) | null}} o
 */
export function passphraseKey({ passphrase, salt, managerKey, onProgress, pbkdf2 }: {
    passphrase: string;
    salt: Uint8Array;
    managerKey: Uint8Array;
    onProgress?: ((done: number) => void) | null;
    pbkdf2?: ((password: Uint8Array, salt: Uint8Array, rounds: number, dkLen: number) => Promise<Uint8Array>) | null;
}): Promise<Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>>;
/**
 * The entry with its secret fields moved into `inner`, sealed under `innerKey`.
 * @param {object} entry
 * @param {Uint8Array} innerKey
 * @param {(n: number) => Uint8Array} randomBytes
 * @param {{seal: string, salt?: Uint8Array | null, ref?: string | null}} opts
 */
export function sealInner(entry: object, innerKey: Uint8Array, randomBytes: (n: number) => Uint8Array, { seal, salt, ref }: {
    seal: string;
    salt?: Uint8Array | null;
    ref?: string | null;
}): {};
/** The entry with its secret fields back, opened with `innerKey`; throws when the key is wrong. */
export function openInner(entry: any, innerKey: any): any;
/** the salt a passphrase entry was sealed with */
export function saltOf(entry: any): Uint8Array<ArrayBuffer> | null;
