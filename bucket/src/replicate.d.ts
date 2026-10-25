/**
 * What this side has: per store, per unit, its date and hash - no values.
 * @param {{stores: Object<string, Object<string, {v: string|null, at: string, archived?: true}>>}} bucket
 * @param {{rules?: Object}} [opts]
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
}, { rules }?: {
    rules?: Object;
}): {
    [x: string]: {
        [x: string]: {
            at: string;
            h: string;
        };
    };
};
/**
 * The units to send: every one the other side does not hold alike (its hash differs, or it has none). Whether it wins
 * is the receiving store's rule - the same on both sides (bucket.newer, a list's join).
 * @param {{stores: Object}} bucket
 * @param {ReturnType<typeof summarize>} mine this side's HAVE, as sent
 * @param {ReturnType<typeof summarize>} theirs the other's HAVE
 * @param {{rules?: Object}} [opts]
 * @returns {Object<string, Object<string, {v: string|null, at: string, archived?: true, part?: true}>>}
 */
export function give(bucket: {
    stores: Object;
}, mine: ReturnType<typeof summarize>, theirs: ReturnType<typeof summarize>, { rules }?: {
    rules?: Object;
}): {
    [x: string]: {
        [x: string]: {
            v: string | null;
            at: string;
            archived?: true;
            part?: true;
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
/**
 * A BUCKET'S STATE: one hash over every unit - its store, key, value hash and date - and the time of its last change
 * (Brad, 2026-10-25: "ping hashes and timestamps so each device can compare its state before it updates, trading until
 * all hashes are the same"; "the phone tells the desktop a hash and timestamp"). Two devices with the same state hold
 * the same bucket: no trade is needed, and a trade is complete only when the states match. Per store too, so a store
 * that never settles is named. An empty store counts as none. A split value is hashed by its parts in id order, so the
 * order its items were written in does not count.
 * @param {{stores: Object, clock?: string|null}} bucket
 * @param {{rules?: Object}} [opts] the stores' rules (their parts)
 * @returns {{hash: string, at: string|null, stores: Object<string, string>}}
 */
export function stateOf(bucket: {
    stores: Object;
    clock?: string | null;
}, { rules }?: {
    rules?: Object;
}): {
    hash: string;
    at: string | null;
    stores: {
        [x: string]: string;
    };
};
/** The stores whose state differs between two states (bucket names only). */
export function differs(a: any, b: any): string[];
import { mergeKeys } from "./bucket";
