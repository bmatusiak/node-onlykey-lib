export const BLOCK: 64;
/**
 * A copy (copyfile.toJSON's shape) as the store's keys -> values (JSON text).
 * @param {object} j the copy as JSON
 * @returns {Object<string, string>}
 */
export function split(j: object): {
    [x: string]: string;
};
/**
 * One device's keys back into its copy (copyfile.toJSON's shape), or null when the store holds no meta for it.
 * @param {Object<string, string>} entries the store's live keys -> values (only this device's are read)
 * @param {string} deviceIdHex
 */
export function join(entries: {
    [x: string]: string;
}, deviceIdHex: string): {
    v: any;
    deviceId: any;
    links: never[];
} | null;
/** The devices whose log the store holds (by their meta). */
export function devices(keys: any): any;
/** The key's kind and device: {dev, kind, n} or null for a key that is not a log's. */
export function parseKey(key: any): {
    dev: string;
    kind: string;
    n: number | null;
} | null;
export function mergeEntry(key: any, haveText: any, lo: any, hi: any): {
    v: any;
    taken: number;
    fork: null;
} | {
    v: any;
    taken: number;
    fork: string;
};
export function devOf(deviceIdHex: any): string;
export function fileInto(have: any, j: any): {
    changed: {};
    forks: string[];
};
export function newestSeqs(entries: any): {};
