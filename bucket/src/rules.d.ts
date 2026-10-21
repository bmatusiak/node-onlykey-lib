/**
 * Settings: key by key - a setting both copies changed is asked, both values shown with their
 * dates (Brad, 2026-10-21: "ask to show changes, with the dates displayed to give user the best
 * option to decide").
 */
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
    store: {};
    taken: number;
    conflicts: never[];
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
        };
    };
    taken: number;
    conflicts: {
        key: string;
        into: {
            v: string | null;
            at: string;
        };
        from: {
            v: string | null;
            at: string;
        };
    }[];
};
/**
 * The Guest Book (guestbook/src/store.js, one blob {v, contacts}): contacts by id. One only the other
 * copy has is added; the same contact, different on the two sides, is a conflict - the person
 * picks, the copy here stays until then. (A fetched key's update is guestbook/src/merge.js
 * classify, at fetch time; two people's edits to one contact are theirs to choose between.)
 * @param {{key?: string}} [opts] key: the blob's name ('guestbook:v1')
 */
export function guestbook({ key }?: {
    key?: string;
}): (into?: {}, from?: {}) => {
    store: {};
    taken: any;
    conflicts: never[];
} | {
    store: {};
    taken: number;
    conflicts: {
        key: string;
        into: {
            v: string;
            at: any;
        };
        from: {
            v: string;
            at: any;
        };
    }[];
};
import { mergeKeys } from "./bucket";
