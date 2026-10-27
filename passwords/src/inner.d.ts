export const SEAL: "entry-touch";
export const SECRET_FIELDS: string[];
/**
 * The derive label of an entry's key. `scope`: the store's owner (the bucket identity), so two
 * identities on one key never share an entry key; `ref`: the entry's id.
 */
export function entryLabel(scope: any, ref: any): string;
/**
 * The entry's key from the OnlyKey: its touch derived secret - always a press.
 * @param {{deriveSecret: (label: string, opts: object) => Promise<Uint8Array>}} okcrypto
 * @param {string} scope
 * @param {string} ref
 * @param {object} [opts] passed to deriveSecret (confirm, timeoutMs); `touch` is always true
 */
export function entryKey(okcrypto: {
    deriveSecret: (label: string, opts: object) => Promise<Uint8Array>;
}, scope: string, ref: string, opts?: object): Promise<Uint8Array<ArrayBufferLike>>;
/** Does this entry carry any secret field outside a seal? */
export function hasPlainSecret(entry: any): boolean;
/** a new entry's ref (and id): 16 random bytes, hex */
export function newRef(randomBytes: any): string;
/**
 * The entry with its secret fields moved into `inner`, sealed under `innerKey` (entryKey of `ref`).
 * @param {object} entry
 * @param {Uint8Array} innerKey
 * @param {(n: number) => Uint8Array} randomBytes
 * @param {{ref: string}} opts
 */
export function sealInner(entry: object, innerKey: Uint8Array, randomBytes: (n: number) => Uint8Array, { ref }: {
    ref: string;
}): {};
/**
 * The entry with its secret fields back, opened with `innerKey`. Throws when the key is wrong, and
 * when the seal is not this entry's (its ref, inside and out, must be the entry's id).
 */
export function openInner(entry: any, innerKey: any): any;
