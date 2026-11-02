/**
 * THE APPROVING HOST'S BUDGET BOOK (the structure track S4 step 7, 2026-11-02): what a host keeps of each budget it
 * approved on a key - the request (reason, scopes, uses), the opening's genesis and the checkpoint signature its press
 * answered with (R27: grants.verifyBudgetOpening), when it was opened and for how long, and the host's own marks on it
 * (endedAt, dismissed, continued, which computer asked). Also your other devices' checked openings (edgeDevices).
 *
 * It was the ok-edge app's alone, read and written as raw storage keys in fifteen places; here it is one book over the
 * host's store - the app's AsyncStorage, later the CLI's home (its local host) - with the SAME keys, so nothing moves:
 *
 *   <prefix><deviceIdHex>.<grantId>  ->  the record as JSON
 *
 *   createBudgetBook({kv, prefix})   kv: {getItem, setItem, getAllKeys?, getMany?} (sync or async; strings);
 *                                    prefix: () => string - the net's own (the app's edgeKey('budgets.'))
 *     get(dev, grantId) -> record | null
 *     put(dev, grantId, record)
 *     patch(dev, grantId, fields) -> the record after, or null when there was none (nothing written)
 *     list(dev, {keys?}) -> [{grantId, record}] by grantId - keys: the store's keys read once already (a refresh
 *                           reads them once for all its lists)
 *     key(dev, grantId) -> the store key
 *
 * Pure: no I/O of its own. Records are plain JSON; a record that does not parse reads as none.
 */
/**
 * @param {{kv: {getItem: (k: string) => any, setItem: (k: string, v: string) => any, getAllKeys?: () => any, getMany?: (keys: string[]) => any}, prefix: () => string}} o
 * @returns {{key: (dev: string, grantId: number) => string, get: (dev: string, grantId: number) => Promise<any>, put: (dev: string, grantId: number, record: any) => Promise<void>,
 *   patch: (dev: string, grantId: number, fields: any) => Promise<any>, list: (dev: string, opts?: {keys?: readonly string[] | string[] | null}) => Promise<Array<{grantId: number, record: any}>>}}
 */
export function createBudgetBook({ kv, prefix }: {
    kv: {
        getItem: (k: string) => any;
        setItem: (k: string, v: string) => any;
        getAllKeys?: () => any;
        getMany?: (keys: string[]) => any;
    };
    prefix: () => string;
}): {
    key: (dev: string, grantId: number) => string;
    get: (dev: string, grantId: number) => Promise<any>;
    put: (dev: string, grantId: number, record: any) => Promise<void>;
    patch: (dev: string, grantId: number, fields: any) => Promise<any>;
    list: (dev: string, opts?: {
        keys?: readonly string[] | string[] | null;
    }) => Promise<Array<{
        grantId: number;
        record: any;
    }>>;
};
