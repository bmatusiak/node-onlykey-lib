/**
 * A vault store over a host-supplied key/value store.
 *
 * @param {object} opts
 * @param {{getItem: function, setItem: function, removeItem: function}} opts.store
 * @param {function} [opts.now] injectable clock, so a test can pin timestamps
 */
export function createVaultStore({ store, now }?: {
    store: {
        getItem: Function;
        setItem: Function;
        removeItem: Function;
    };
    now?: Function | undefined;
}): {
    /**
     * Save one credential.
     *
     * `createdAt` survives an update and `updatedAt` does not, which is what
     * makes "when did I first store this" answerable after an edit.
     */
    put(entry: any): Promise<any>;
    /** One credential, or null. */
    get(serviceId: any): Promise<any>;
    /** Forget one. The blob is unreadable without the device either way. */
    remove(serviceId: any): Promise<void>;
    /**
     * Every credential, oldest first.
     *
     * Self-healing: an index entry whose record has gone is dropped and the
     * index rewritten, so a half-finished delete does not leave a name in the
     * list forever.
     */
    list(): Promise<any[]>;
    /** Just the names, for a list screen that does not need the blobs. */
    serviceIds(): Promise<any[]>;
    /**
     * Everything, as the web app's export envelope.
     *
     * Safe to hand to anyone in the sense that matters - every `encrypted`
     * field is still sealed, and the key is on a device. It is NOT safe in the
     * sense of privacy: the service ids are in the clear, so an export says
     * which sites someone has accounts on.
     */
    exportJSON(): Promise<string>;
    /**
     * Import an export.
     *
     * Existing ids are SKIPPED unless `force`, so importing a backup over a
     * live vault cannot quietly replace a newer credential with an older one.
     * The count of skipped entries is returned rather than hidden, because
     * "imported 0 of 12" is the answer a caller needs to see.
     */
    importJSON(json: any, { force }?: {
        force?: boolean | undefined;
    }): Promise<{
        imported: number;
        skipped: number;
        total: any;
    }>;
    /**
     * Remove every credential this store knows about.
     *
     * Only what the INDEX names, so a host storing other things under other
     * keys keeps them. That also means a record orphaned by a corrupt index
     * survives a clear - which is the safer failure, since the alternative is
     * deleting keys this store did not write.
     */
    clear(): Promise<number>;
};
/**
 * A store backed by a Map, for tests and for a host with nothing better.
 *
 * NOT persistence. It is here so the library's own tests do not need a
 * platform, and so a host can exercise a flow before wiring real storage.
 */
export function memoryStore(): {
    getItem(key: any): Promise<any>;
    setItem(key: any, value: any): Promise<void>;
    removeItem(key: any): Promise<void>;
    /** For assertions; not part of the contract. */
    _map: Map<any, any>;
};
/** Namespaced so a host storing other things cannot collide. */
export const PREFIX: "onlyagent-vault";
export const INDEX_KEY: "onlyagent-vault/index";
export const RECORD_PREFIX: "onlyagent-vault/credentials/";
/** The export envelope's version. Matches the web app's. */
export const EXPORT_VERSION: 1;
