/**
 * the entry kinds this release writes. A mnemonic or a derived entry is a RECIPE (mnemonic.js,
 * derived.js): the phrase or the password itself is never stored.
 */
export const KINDS: string[];
/**
 * The store key's derive label (touchless): one per identity. Not an entry's (an entry's ends in
 * its 32-hex id), so the store key never opens a secret.
 */
export function storeLabel(scope: any): string;
/** A key/value store (getItem/setItem/removeItem) with every key under `prefix`. */
export function prefixedStore(store: any, prefix: any): {
    getItem: (k: any) => any;
    setItem: (k: any, v: any) => any;
    removeItem: (k: any) => any;
};
/** The entry's fields as stored, checked; unknown fields are dropped. A secret outside its seal is refused. */
export function shapeEntry(e: any): {
    v: number;
    kind: any;
    title: string;
};
/**
 * Open one store under its store key. -> list / get / put / remove / exportJSON / importJSON / lock.
 * `store`: getItem/setItem/removeItem (already prefixed with prefixedStore); `key`: the 32-byte
 * store key (the touchless derive of storeLabel); `randomBytes(n)`: the host's CSPRNG.
 *
 * Every record is opened here once; a record that does not open under this key, or whose entry
 * names another record, is NOT listed and is reported in `refused` - never shown as an entry.
 */
export function openStore({ store, key, randomBytes, now }: {
    store: any;
    key: any;
    randomBytes: any;
    now?: (() => Date) | undefined;
}): Promise<{
    /** entries, title order: labels, and each one's seal - the secrets need its press */
    list(): any[];
    get(id: any): any;
    /**
     * New (no id) or an update. A sealed entry's id is its seal's ref (inner.newRef, chosen before
     * sealing): a new sealed entry brings it, as `inner.ref`; an entry without a seal gets a random one.
     */
    put(input: any): Promise<any>;
    remove(id: any): Promise<void>;
    /**
     * A copy to keep or move: the whole list sealed under the store key, each entry's secrets still
     * in their own seal inside it - it opens only with this key (or one restored from its backup).
     */
    exportJSON(): string;
    /** A copy from exportJSON, opened with this store's key: new entries added, the ones here kept. */
    importJSON(json: any): Promise<{
        imported: number;
        skipped: number;
        unreadable: number;
    }>;
    /** records that did not open under this key (another key, moved onto another record, damaged) */
    refused: () => any[];
    readonly size: number;
    readonly locked: boolean;
    /** forget the entries and wipe this copy of the store key */
    lock(): void;
}>;
