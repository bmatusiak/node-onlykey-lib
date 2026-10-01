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
 * Add `incoming` to `existing`: an entry with an id already present is kept as
 * it was (the same key from the same place), everything else is added.
 * @returns {{entries: object[], added: number, kept: number}}
 */
export function merge(existing: any, incoming: any): {
    entries: object[];
    added: number;
    kept: number;
};
/** A short fingerprint to show beside an entry. */
export function fingerprint(publicKey: any): string;
