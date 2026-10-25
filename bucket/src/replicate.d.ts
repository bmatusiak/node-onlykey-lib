/**
 * What this side has: per store, per key, its date and value hash.
 * @param {{stores: Object<string, Object<string, {v: string|null, at: string}>>}} bucket
 * @returns {Object<string, Object<string, {at: string, h: string}>>}
 */
export function summarize(bucket: {
    stores: {
        [x: string]: {
            [x: string]: {
                v: string | null;
                at: string;
            };
        };
    };
}): {
    [x: string]: {
        [x: string]: {
            at: string;
            h: string;
        };
    };
};
/**
 * The values to send: every key this side changed (alone, or with the other) that the other does not hold alike.
 * @param {{stores: Object}} bucket
 * @param {ReturnType<typeof summarize>} mine this side's HAVE, as sent
 * @param {ReturnType<typeof summarize>} theirs the other's HAVE
 * @param {Object<string, Object<string, string>>} [base] what both last agreed on (hash per key)
 * @returns {Object<string, Object<string, {v: string|null, at: string}>>}
 */
export function give(bucket: {
    stores: Object;
}, mine: ReturnType<typeof summarize>, theirs: ReturnType<typeof summarize>, base?: {
    [x: string]: {
        [x: string]: string;
    };
}): {
    [x: string]: {
        [x: string]: {
            v: string | null;
            at: string;
        };
    };
};
/**
 * Take what the other side gave. Changes `bucket` in place.
 * @param {{stores: Object}} bucket
 * @param {ReturnType<typeof give>} given the other's GIVE
 * @param {ReturnType<typeof summarize>} mine this side's HAVE, as sent (before this take)
 * @param {ReturnType<typeof summarize>} theirs the other's HAVE
 * @param {Object<string, Object<string, string>>} [base] what both last agreed on
 * @param {{rules?: Object<string, typeof mergeKeys>}} [opts] the stores' merge rules, as bucket.merge takes them
 * @returns {{base: Object<string, Object<string, string>>, taken: Object<string, number>, conflicts: Array<{store: string, key: string, into: object, from: object}>}}
 *   base: the new base to keep for this peer (the other side computes the same); taken: per store, how many keys
 *   changed here; conflicts: for the person - this side keeps its own value until they pick
 */
export function take(bucket: {
    stores: Object;
}, given: ReturnType<typeof give>, mine: ReturnType<typeof summarize>, theirs: ReturnType<typeof summarize>, base?: {
    [x: string]: {
        [x: string]: string;
    };
}, { rules }?: {
    rules?: {
        [x: string]: typeof mergeKeys;
    };
}): {
    base: {
        [x: string]: {
            [x: string]: string;
        };
    };
    taken: {
        [x: string]: number;
    };
    conflicts: Array<{
        store: string;
        key: string;
        into: object;
        from: object;
    }>;
};
export function hashOf(rec: any): string;
export const REMOVED: "removed";
import { mergeKeys } from "./bucket";
