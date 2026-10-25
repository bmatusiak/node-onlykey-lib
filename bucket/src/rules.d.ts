/** Settings: key by key, the newer value wins (bucket.mergeKeys). */
export const settings: typeof mergeKeys;
/**
 * The Key Chain list: one key holding the list (the phone's export format); the list's own merge
 * (keychain/src/list.js merge) - entries by id, twins joined, nothing either side knew dropped.
 * It has no conflicts: two records of one key combine.
 * @param {{parse: (text: string) => object[], serialize: (entries: object[]) => string, merge: (a: object[], b: object[]) => {entries: object[], added: number, paired: number}}} list
 * @param {{key?: string}} [opts]
 */
export function keychain(list: {
    parse: (text: string) => object[];
    serialize: (entries: object[]) => string;
    merge: (a: object[], b: object[]) => {
        entries: object[];
        added: number;
        paired: number;
    };
}, { key }?: {
    key?: string;
}): (into?: {}, from?: {}) => {
    store: any;
    taken: any;
    conflicts: any[];
};
/**
 * Password entries (passwords/ over src/crypto/vault_store.js): each credential is its own key and
 * merges key by key - the same entry changed on both sides is a conflict, never overwritten. The
 * index is not a value to choose between: it is the set of credentials, so it is rebuilt as the
 * union. Works for every vault in the store (each is a prefix: `<storeId>/onlyagent-vault/...`).
 */
export function passwords(): (into?: {}, from?: {}) => {
    store: {
        [x: string]: {
            v: string | null;
            at: string;
            archived?: true;
        };
    };
    taken: number;
    conflicts: any[];
};
/**
 * The Guest Book (guestbook/src/store.js, one blob {v, contacts}): per contact, by id. One only the other
 * copy has is added; the same contact, different on the two sides, is taken from the copy where it changed
 * LATER - its newest key's updatedAt, else the blob's date; the same time decided the same way on every
 * device. Nothing is asked. (A fetched key's update is guestbook/src/merge.js classify, at fetch time.)
 * @param {{key?: string}} [opts] key: the blob's name ('guestbook:v1')
 */
export function guestbook({ key }?: {
    key?: string;
}): (into?: {}, from?: {}) => {
    store: any;
    taken: any;
    conflicts: any[];
};
/**
 * The Edge copies (edge/src/copyfile.js): one key per device, its copy's JSON. Two copies of one
 * device merge by the copy's own rules; a FORK - the copies disagree at a seq both hold, or name
 * different keys - is reported and never repaired: this copy stays, nothing of the other is taken,
 * and the conflict cannot be picked away.
 * @param {{fromJSON: Function, toJSON: Function, merge: Function}} copyfile edge's copyfile module
 */
export function edgeCopies(copyfile: {
    fromJSON: Function;
    toJSON: Function;
    merge: Function;
}): (into?: {}, from?: {}) => {
    store: {};
    taken: number;
    conflicts: {
        key: string;
        reason: any;
        into: any;
        from: any;
        apply(): never;
    }[];
};
/**
 * THE AUDIT DUMP (Brad, 2026-10-21: "the bucket may contain passwords, so the dump is just for the
 * Edge blockchain so it can be externally verified using pubkeys"): every Edge copy in the bucket
 * as JSON blocks, each checked against the keys kept with its copy. Public by nature - nothing
 * else in the bucket ever leaves it unsealed.
 * @param {{stores: Object}} bucket an opened bucket
 * @param {{fromJSON: Function, blocks: Function}} copyfile edge's copyfile module
 * @param {{net: string, store?: string}} opts
 */
export function edgeBlocks(bucket: {
    stores: Object;
}, copyfile: {
    fromJSON: Function;
    blocks: Function;
}, { net, store }: {
    net: string;
    store?: string;
}): any[];
/**
 * The Cryptobox (cryptobox/src/store.js): one key holding `{v, messages}`. Messages join by id from both sides - a
 * message written on one device is never lost to a message written on the other - and a message removed on either side
 * stays removed (removal is an archived flag, never a drop). The joined list is in one order (when written, then id),
 * so both devices end with the same value byte for byte and their bucket states match (replicate.js stateOf). Not
 * made from the Cryptobox module: the blob's shape is all it reads.
 * @param {{key?: string}} [opts]
 */
export function cryptobox({ key }?: {
    key?: string;
}): (into?: {}, from?: {}) => {
    store: any;
    taken: any;
    conflicts: any[];
};
import { mergeKeys } from "./bucket";
