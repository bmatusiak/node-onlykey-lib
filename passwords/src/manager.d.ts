/** the derive label the manager key comes from (deviceVault adds `vault:`) */
export const LABEL: "ok-rn-manager";
/** the entry kinds this release writes; later ones (totp, mnemonic, derived) are refused until built */
export const KINDS: string[];
/** The store id: SHA-256 of the manager label's derive public key, hex. Public by design. */
export function storeIdOf(publicKey: any): string;
/** A key/value store (getItem/setItem/removeItem) with every key under `prefix`. */
export function prefixedStore(store: any, prefix: any): {
    getItem: (k: any) => any;
    setItem: (k: any, v: any) => any;
    removeItem: (k: any) => any;
};
/** The entry's fields as stored, checked; unknown fields are dropped. */
export function shapeEntry(e: any): {
    v: number;
    kind: any;
    title: string;
};
/**
 * Open one store under its manager key. -> the manager: list / get / put / remove / exportJSON /
 * importJSON / lock. `store`: getItem/setItem/removeItem (already prefixed with prefixedStore);
 * `key`: the 32-byte manager key; `randomBytes(n)`: the host's CSPRNG.
 *
 * Every record is opened here once; a record that does not open under this key, or whose entry
 * names another record, is NOT listed and is reported in `refused` - never shown as an entry.
 */
export function openManager({ store, key, randomBytes, now }: {
    store: any;
    key: any;
    randomBytes: any;
    now?: (() => Date) | undefined;
}): Promise<{
    /** entries, title order; with their secrets - the caller decides what is drawn */
    list(): any[];
    get(id: any): any;
    /** new (no id) or an update; a changed password goes to the history (last 5) */
    put(input: any): Promise<any>;
    remove(id: any): Promise<void>;
    /** the sealed envelope (src/crypto/vault_store v1): every entry still sealed, ids random */
    exportJSON: () => Promise<string>;
    /** a sealed envelope from this key; an entry that does not open under it is skipped and counted */
    importJSON(json: any, { force }?: {
        force?: boolean | undefined;
    }): Promise<{
        unreadable: number;
        imported: number;
        skipped: number;
        total: any;
    }>;
    /** records that did not open under this key (wrong key, swapped, damaged) */
    refused: () => any[];
    readonly size: number;
    readonly locked: boolean;
    /** forget the entries and wipe this copy of the key (the caller locks its session cache) */
    lock(): void;
}>;
