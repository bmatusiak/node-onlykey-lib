/**
 * text -> {version, input, preferences, advanced, unset}
 * `unset`: the names a "; <name> unset" comment says the key has no value for.
 * Throws on anything that is not this file's INI (a line outside a section,
 * an unknown section) - an import must never guess.
 */
export function parse(text: any): {
    version: null;
    input: {};
    preferences: {};
    advanced: {};
    unset: never[];
};
/**
 * What an import would write, from a parsed file: [{name, value}] in the
 * file's order, plus what it leaves alone and why.
 *   oneWay: also write [advanced] (they cannot be undone)
 * -> {writes, skipped: [{name, why}], unknown: [names]}
 */
export function plan(ini: any, { oneWay }?: {
    oneWay?: boolean | undefined;
}): {
    writes: {
        name: string;
        value: number;
        oneWay: boolean;
        requires: any;
    }[];
    skipped: {
        name: string;
        why: string;
    }[];
    unknown: string[];
};
export const SECTIONS: string[];
export const INPUT_KEYS: string[];
export const INPUT_WORDS: string[];
