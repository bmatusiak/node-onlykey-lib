export const FORMAT: "onlykey-bucket";
export const SEALED_FORMAT: "onlykey-bucket-sealed";
export const VERSION: 1;
/**
 * A new, empty bucket.
 * @param {{owner?: string|null}} [opts] owner: who the bucket belongs to, as the host names it
 *   (the key's id) - two buckets merge only when it is the same
 * @returns {{format: string, v: number, owner: string|null, stores: Object<string, Object<string, {v: string|null, at: string}>>}}
 */
export function create({ owner }?: {
    owner?: string | null;
}): {
    format: string;
    v: number;
    owner: string | null;
    stores: {
        [x: string]: {
            [x: string]: {
                v: string | null;
                at: string;
            };
        };
    };
};
/**
 * The storage seam for one store, over its part of the bucket.
 * @param {ReturnType<typeof create>} bucket
 * @param {string} name the store's name ('keychain', 'guestbook', 'settings', ...)
 * @param {{now?: () => string}} [opts]
 * @returns {{getItem: (key: string) => string|null, setItem: (key: string, value: string) => void, removeItem: (key: string) => void, keys: () => string[]}}
 */
export function kv(bucket: ReturnType<typeof create>, name: string, { now }?: {
    now?: () => string;
}): {
    getItem: (key: string) => string | null;
    setItem: (key: string, value: string) => void;
    removeItem: (key: string) => void;
    keys: () => string[];
};
/**
 * The bucket as text (unsealed).
 * @param {ReturnType<typeof create>} bucket
 * @returns {string}
 */
export function serialize(bucket: ReturnType<typeof create>): string;
/**
 * Read an unsealed bucket's text, checking its shape.
 * @param {string} text
 * @returns {ReturnType<typeof create>}
 */
export function parse(text: string): ReturnType<typeof create>;
/**
 * The bucket sealed under the key's bucket key - the file that travels.
 * @param {ReturnType<typeof create>} bucket
 * @param {Uint8Array} key 32 bytes, from okcrypto.deviceVault.key('bucket')
 * @param {(n: number) => Uint8Array} randomBytes
 * @returns {string}
 */
export function seal(bucket: ReturnType<typeof create>, key: Uint8Array, randomBytes: (n: number) => Uint8Array): string;
/**
 * Open a bucket file, sealed or not.
 *
 * Sealed: opened with the key; one that does not open was sealed by another key (or is damaged) -
 * it is never read some other way. Unsealed: only where the host allows it (development builds).
 * @param {string} text
 * @param {{key?: Uint8Array|null, allowUnsealed?: boolean}} [opts]
 * @returns {{bucket: ReturnType<typeof create>, sealed: boolean}}
 */
export function open(text: string, { key, allowUnsealed }?: {
    key?: Uint8Array | null;
    allowUnsealed?: boolean;
}): {
    bucket: ReturnType<typeof create>;
    sealed: boolean;
};
/**
 * The generic merge for one store: key by key. A key only one side has is taken; the same value is
 * kept; two different values (a removal counts as a value) are a CONFLICT - both kept in the report
 * with their dates, `into`'s value stays until the person picks (resolve()).
 * @param {Object<string, {v: string|null, at: string}>} into
 * @param {Object<string, {v: string|null, at: string}>} from
 * @returns {{store: Object<string, {v: string|null, at: string}>, taken: number, conflicts: Array<{key: string, into: {v: string|null, at: string}, from: {v: string|null, at: string}}>}}
 */
export function mergeKeys(into?: {
    [x: string]: {
        v: string | null;
        at: string;
    };
}, from?: {
    [x: string]: {
        v: string | null;
        at: string;
    };
}): {
    store: {
        [x: string]: {
            v: string | null;
            at: string;
        };
    };
    taken: number;
    conflicts: Array<{
        key: string;
        into: {
            v: string | null;
            at: string;
        };
        from: {
            v: string | null;
            at: string;
        };
    }>;
};
/**
 * Import one bucket into another. Each store merges by its own rule (rules[name]), or key by key;
 * nothing is dropped - what could not be merged comes back in the report, for the person to pick.
 * Buckets of different owners do not merge.
 * @param {ReturnType<typeof create>} into
 * @param {ReturnType<typeof create>} from
 * @param {{rules?: Object<string, typeof mergeKeys>}} [opts]
 * @returns {{bucket: ReturnType<typeof create>, report: {taken: Object<string, number>, conflicts: Array<{store: string, key: string, into: {v: string|null, at: string}, from: {v: string|null, at: string}}>}}}
 */
export function merge(into: ReturnType<typeof create>, from: ReturnType<typeof create>, { rules }?: {
    rules?: {
        [x: string]: typeof mergeKeys;
    };
}): {
    bucket: ReturnType<typeof create>;
    report: {
        taken: {
            [x: string]: number;
        };
        conflicts: Array<{
            store: string;
            key: string;
            into: {
                v: string | null;
                at: string;
            };
            from: {
                v: string | null;
                at: string;
            };
        }>;
    };
};
/**
 * The person's pick for one conflict: 'into' keeps what is there, 'from' takes the other copy's
 * value and date.
 * @param {ReturnType<typeof create>} bucket
 * @param {{store: string, key: string, into: {v: string|null, at: string}, from: {v: string|null, at: string}}} conflict
 * @param {'into'|'from'} side
 */
export function resolve(bucket: ReturnType<typeof create>, conflict: {
    store: string;
    key: string;
    into: {
        v: string | null;
        at: string;
    };
    from: {
        v: string | null;
        at: string;
    };
}, side: "into" | "from"): void;
