export const PREFIX: "password:";
export namespace CHARSETS {
    let upper: string;
    let lower: string;
    let digits: string;
    let symbols: string;
}
export const MIN_LENGTH: 8;
export const MAX_LENGTH: 56;
/** The derive label of a password name: trimmed, printable, short. */
export function labelOf(name: any): string;
/** The password a 32-byte secret gives, for this length and these classes. */
export function passwordFrom(secret: any, length: any, classes: any): string;
export function checkOf(password: any): string;
/** A recipe as stored, checked: {label, out: 'password', length, classes, press, check}. */
export function shapeRecipe(r: any): {
    label: any;
    out: string;
    length: any;
    classes: string[];
    press: any;
    check: any;
};
/** Make one from the key. -> {password, recipe} */
export function derivePasswordFor({ okcrypto, name, length, classes, press, onKeepAlive }: {
    okcrypto: any;
    name: any;
    length?: number | undefined;
    classes?: string[] | undefined;
    press: any;
    onKeepAlive?: undefined;
}): Promise<{
    password: string;
    recipe: {
        label: string;
        out: string;
        length: number;
        classes: string[];
        press: boolean;
        check: string;
    };
}>;
/** The saved password again, from its recipe - checked; a mismatch throws DerivedDriftError. */
export function openRecipe({ okcrypto, recipe, onKeepAlive }: {
    okcrypto: any;
    recipe: any;
    onKeepAlive?: undefined;
}): Promise<string>;
export function nameOf(recipe: any): string;
/** Thrown when the key's password no longer matches the recipe's check. */
export class DerivedDriftError extends Error {
    constructor();
}
