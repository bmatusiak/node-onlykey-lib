export const PREFIX: "mnemonic:";
/** the phrase lengths a recipe may ask for, by entropy bytes */
export const OUTS: {
    'bip39-12': number;
    'bip39-24': number;
};
/** The derive label of a phrase name. A name is what the person types: trimmed, printable, short. */
export function labelOf(name: any): string;
/** 16 or 32 bytes of entropy from the derive's secret. */
export function entropyFrom(secret: any, out: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/** The recipe's check: the first 4 bytes of SHA-256 of the entropy, hex. */
export function checkOf(entropy: any): string;
/** The words of an entropy, BIP39 English (checksum included). */
export function wordsOf(entropy: any): string[];
/** Whether a phrase is valid BIP39 English (words + checksum). */
export function isValidPhrase(words: any): boolean;
/**
 * Derive a phrase from the key. -> {words, recipe}
 * okcrypto: a backend's okcrypto (deriveSharedSecretFor); press: the derive's press flag, recorded.
 */
export function deriveMnemonic({ okcrypto, name, out, press, onKeepAlive }: {
    okcrypto: any;
    name: any;
    out?: string | undefined;
    press: any;
    onKeepAlive?: undefined;
}): Promise<{
    words: string[];
    recipe: {
        label: string;
        out: string;
        press: boolean;
        check: string;
    };
}>;
/** The saved phrase again, from its recipe - checked; a mismatch throws PhraseDriftError. */
export function openRecipe({ okcrypto, recipe, onKeepAlive }: {
    okcrypto: any;
    recipe: any;
    onKeepAlive?: undefined;
}): Promise<string[]>;
/** A recipe as stored, checked: {label, out, press, check}. */
export function shapeRecipe(r: any): {
    label: any;
    out: any;
    press: any;
    check: any;
};
/** The name a recipe was made from. */
export function nameOf(recipe: any): string;
/** Thrown when the key's phrase no longer matches the recipe's check. */
export class PhraseDriftError extends Error {
    constructor();
}
