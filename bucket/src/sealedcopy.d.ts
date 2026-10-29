/**
 * The table key and the unit key, from the bucket key - the same on every device of the identity.
 * @param {{secretKey: Uint8Array}} bucketKey bucket-identity.deriveBucketKeyAt's
 */
export function keysOf(bucketKey: {
    secretKey: Uint8Array;
}): {
    tableKey: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
    unitKey: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
};
/** The id of the heads row (each Edge log's newest link on the server). */
export function headsId(keys: any): string;
/**
 * This bucket as the server's table would hold it.
 * @returns {{rows: Object<string, string>, where: Object<string, [string, string]>}} rows: id -> tag; where: id -> [store, unit key]
 */
export function table(bucket: any, keys: any, { rules }?: {
    rules?: {} | undefined;
}): {
    rows: {
        [x: string]: string;
    };
    where: {
        [x: string]: [string, string];
    };
};
/**
 * What to move: get the rows the server holds that this device lacks or holds differently (first - the stores' rules
 * merge them), then put the rows this device holds that the server lacks or holds differently (after the gets, from the
 * table made again). The heads row is never a unit.
 * @param {Object<string, string>} mine this device's table rows
 * @param {Object<string, string>} theirs the server's table rows
 */
export function plan(mine: {
    [x: string]: string;
}, theirs: {
    [x: string]: string;
}, keys: any): {
    get: string[];
    put: string[];
};
/**
 * The rows to put, sealed: each unit as a trade's GIVE carries it.
 * @param {string[]} ids from plan().put, against this bucket's table (made now)
 * @returns {Object<string, {tag: string, blob: string}>}
 */
export function sealRows(bucket: any, keys: any, ids: string[], { rules, randomBytes }: {
    rules?: {} | undefined;
    randomBytes: any;
}): {
    [x: string]: {
        tag: string;
        blob: string;
    };
};
/**
 * Rows from the server back into a GIVE for replicate.take. A blob that does not open, or names another row's id, is
 * refused - never taken.
 * @param {Object<string, string>} rows id -> blob
 * @returns {{given: Object, refused: string[]}}
 */
export function openRows(rows: {
    [x: string]: string;
}, keys: any): {
    given: Object;
    refused: string[];
};
/**
 * The heads row: each Edge log's newest link the server's copy holds ({<dev>: seq}), sealed.
 * @returns {{id: string, tag: string, blob: string}}
 */
export function sealHeads(heads: any, keys: any, randomBytes: any): {
    id: string;
    tag: string;
    blob: string;
};
/** The heads row opened ({<dev>: seq}), or {} when it is missing or not this bucket's. */
export function openHeads(blob: any, keys: any): any;
/**
 * ONE SYNC WITH A ROW STORE (Brad, 2026-10-29: "we load the key on a fresh session empty, and it then needs to compare
 * the remote and session, and decide"; "the webapp can have an encrypted backup for caching"). A row store is anything
 * that keeps these rows - the server's room, or the web app's own encrypted cache in the browser - so a fresh session
 * compares its cache and the server the same way, and moves only what differs:
 *   store.table()      -> {id: tag}                 ids and tags only
 *   store.get(ids)     -> {id: blob}
 *   store.put(rows)    rows: {id: {tag, blob}}
 * heads: this bucket's Edge logs' newest links ({<dev>: seq}, from logblocks.newestSeqs) - the heads row is put again
 * whenever it changed.
 * @param {{stores: Object, clock?: string|null}} bucket changed in place by what is taken
 * @param {{tableKey: Uint8Array, unitKey: Uint8Array}} keys keysOf(bucket key)
 * @param {{table: () => Promise<Object<string, string>>, get: (ids: string[]) => Promise<Object<string, string>>, put: (rows: Object<string, {tag: string, blob: string}>) => Promise<void>}} store
 * @param {{rules?: Object, randomBytes: (n: number) => Uint8Array, heads?: Object<string, number>|null}} opts
 * @returns {Promise<{got: number, put: number, taken: Object<string, number>, conflicts: Array, refused: string[]}>}
 */
export function syncWith(bucket: {
    stores: Object;
    clock?: string | null;
}, keys: {
    tableKey: Uint8Array;
    unitKey: Uint8Array;
}, store: {
    table: () => Promise<{
        [x: string]: string;
    }>;
    get: (ids: string[]) => Promise<{
        [x: string]: string;
    }>;
    put: (rows: {
        [x: string]: {
            tag: string;
            blob: string;
        };
    }) => Promise<void>;
}, { rules, randomBytes, heads }?: {
    rules?: Object;
    randomBytes: (n: number) => Uint8Array;
    heads?: {
        [x: string]: number;
    } | null;
}): Promise<{
    got: number;
    put: number;
    taken: {
        [x: string]: number;
    };
    conflicts: any[];
    refused: string[];
}>;
export function ownerId(keys: any): string;
export function sealOwner(owner: any, keys: any, randomBytes: any): {
    id: string;
    tag: string;
    blob: string;
};
/**
 * Rows kept on this device back into its bucket: every row must open and the owner row must name `owner` - else null.
 * @param {Object<string, string>} rows id -> blob (all of them, the heads row and the owner row included)
 * @returns {{stores: Object, owner: string}|null}
 */
export function bucketFromRows(rows: {
    [x: string]: string;
}, keys: any, { owner, rules }: {
    owner: any;
    rules?: {} | undefined;
}): {
    stores: Object;
    owner: string;
} | null;
