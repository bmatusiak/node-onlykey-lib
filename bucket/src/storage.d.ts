/**
 * The bucket as sealed rows. rows(identity) -> this identity's RowStore on this host (the adapter decides the net).
 * Every write puts only the units that changed, each sealed under keys from the key's secret, and the owner row once -
 * a write of one record is one row, and needs no key and no press.
 * @param {{rows: (identity: string) => any, rules?: object, randomBytes: (n: number) => Uint8Array}} o
 */
export function rowsStorage({ rows, rules, randomBytes }: {
    rows: (identity: string) => any;
    rules?: object;
    randomBytes: (n: number) => Uint8Array;
}): {
    needsKey: boolean;
    state(identity: any): Promise<"none" | "sealed">;
    open(identity: any, key: any, prove: any): Promise<{
        bucket: any;
        write(): Promise<void>;
        refresh: () => Promise<number>;
    } | null>;
    create(identity: any, key: any): Promise<{
        bucket: any;
        write(): Promise<void>;
        refresh: () => Promise<number>;
    }>;
};
/**
 * The bucket kept opened in a file another program shares (the CLI). One bucket in memory, as on every host: read once,
 * written by handing the whole bucket to be MERGED into the file inside its lock (the store rules, newer wins - a write
 * the other program made meanwhile is never lost), and refreshed by the same merge the other way. net() -> 'live'|'test'.
 * @param {{side: {has: Function, read: Function, keep: Function, mergeIn: Function}, net: () => string, rules?: object}} o
 */
export function sharedFileStorage({ side, net, rules }: {
    side: {
        has: Function;
        read: Function;
        keep: Function;
        mergeIn: Function;
    };
    net: () => string;
    rules?: object;
}): {
    needsKey: boolean;
    state(identity: any): Promise<"none" | "kept">;
    open(identity: any): Promise<{
        bucket: any;
        write(): Promise<void>;
        refresh(): Promise<number>;
    } | null>;
    create(identity: any): Promise<{
        bucket: any;
        write(): Promise<void>;
        refresh(): Promise<number>;
    }>;
};
/** A row store in memory - the contract every row adapter (AsyncStorage, IndexedDB) keeps. */
export function memoryRows(): {
    table(): Promise<any>;
    all(): Promise<any>;
    get(ids: any): Promise<{
        [k: string]: any;
    }>;
    put(rows: any): Promise<void>;
    clear(): Promise<void>;
};
