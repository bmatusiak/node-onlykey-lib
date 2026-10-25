/**
 * What this side has: per store, per key, its date and record hash.
 * @param {{stores: Object<string, Object<string, {v: string|null, at: string, archived?: true}>>}} bucket
 * @returns {Object<string, Object<string, {at: string, h: string}>>}
 */
export function summarize(bucket: {
    stores: {
        [x: string]: {
            [x: string]: {
                v: string | null;
                at: string;
                archived?: true;
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
 * The records to send: every one the other side does not hold alike (its hash differs, or it has none). Whether it
 * wins is the receiving store's rule - the same on both sides (bucket.newer, a list's join).
 * @param {{stores: Object}} bucket
 * @param {ReturnType<typeof summarize>} mine this side's HAVE, as sent
 * @param {ReturnType<typeof summarize>} theirs the other's HAVE
 * @returns {Object<string, Object<string, {v: string|null, at: string, archived?: true}>>}
 */
export function give(bucket: {
    stores: Object;
}, mine: ReturnType<typeof summarize>, theirs: ReturnType<typeof summarize>): {
    [x: string]: {
        [x: string]: {
            v: string | null;
            at: string;
            archived?: true;
        };
    };
};
/**
 * Import what the other side gave into this side's bucket (in place), each store by its own rule - the newer wins.
 * @param {{stores: Object, clock?: string|null}} bucket
 * @param {ReturnType<typeof give>} given the other's GIVE
 * @param {{rules?: Object<string, typeof mergeKeys>}} [opts] the stores' merge rules, as bucket.merge takes them
 * @returns {{taken: Object<string, number>, conflicts: Array}} taken: per store, how many changed here; conflicts:
 *   what a store's own rule can never decide (an Edge copy's fork) - the generic rule reports none
 */
export function take(bucket: {
    stores: Object;
    clock?: string | null;
}, given: ReturnType<typeof give>, { rules }?: {
    rules?: {
        [x: string]: typeof mergeKeys;
    };
}): {
    taken: {
        [x: string]: number;
    };
    conflicts: any[];
};
export function hashOf(rec: any): string;
import { mergeKeys } from "./bucket";
