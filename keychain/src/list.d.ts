export const FORMAT: "onlykey-keychain";
export const VERSION: 1;
export const KINDS: string[];
export const TYPES: string[];
/**
 * Validate and normalise one entry. publicKey may be bytes or hex.
 * @param {object} fields
 * @returns {object}
 */
export function createEntry(fields: object): object;
/** The file. */
export function serialize(entries: any): string;
/** Read a file back; every entry is checked again - a file is not trusted for being ours. */
export function parse(text: any): any;
/**
 * Add `incoming` to `existing`. An entry with an id already present gets the
 * fields only the incoming copy has (`joined`) - nothing either side knew is
 * dropped. Keeping the existing copy as it was lost the computer's PGP
 * certificate on every onlykey-js edge sync, and the next agent start put it back, so
 * every sync "moved" it again and asked for a press (the A13, 2026-10-05).
 * A twin (the same derived key under a hash and a name) becomes one entry.
 * @returns {{entries: object[], added: number, paired: number, joined: number, kept: number}}
 */
export function merge(existing: any, incoming: any): {
    entries: object[];
    added: number;
    paired: number;
    joined: number;
    kept: number;
};
/** The entry in `entries` holding the same derived key as `e` (type + public key), or null. */
export function findTwin(entries: any, e: any): any;
/** Two entries of one key -> one: the name over the hash, first seen earliest, last seen latest, everything each one knew. */
export function combine(a: any, b: any): object;
/** A short fingerprint to show beside an entry. */
export function fingerprint(publicKey: any): string;
