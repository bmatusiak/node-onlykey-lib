export namespace MOD {
    let LCTRL: number;
    let LSHIFT: number;
    let LALT: number;
    let LGUI: number;
    let RCTRL: number;
    let RSHIFT: number;
    let RALT: number;
    let RGUI: number;
}
export namespace USAGE {
    let ENTER: number;
    let ESCAPE: number;
    let BACKSPACE: number;
    let TAB: number;
    let SPACE: number;
}
/** The default, and the only layout an OK_EMULATOR debug build can type. */
export const DEFAULT_LAYOUT: "USA_ENGLISH";
/** The layouts this build of the firmware has tables for. */
export function layouts(): {
    name: string;
    id: number;
    supported: boolean;
    compiledIn: boolean;
    ambiguous: any[];
}[];
/**
 * A stateful decoder, because reports arrive one at a time.
 *
 * Held separately from the text so a caller can decode a stream as it lands
 * (a slot being typed out over a second or two) rather than having to buffer
 * every report first and decode at the end.
 */
export function createDecoder({ layout, onEvent }?: {
    layout?: string | undefined;
    onEvent?: null | undefined;
}): {
    push: (report: any) => ({
        usage: any;
        modifiers: any;
        text: string;
        name: string;
    } | {
        accented?: boolean | undefined;
        usage: any;
        modifiers: any;
        text: any;
        name: null;
    })[];
    /** Every report at once, for a capture that is already complete. */
    pushAll(reports: any): {
        push: (report: any) => ({
            usage: any;
            modifiers: any;
            text: string;
            name: string;
        } | {
            accented?: boolean | undefined;
            usage: any;
            modifiers: any;
            text: any;
            name: null;
        })[];
        pushAll(reports: any): /*elided*/ any;
        readonly text: string;
        readonly events: any[];
        readonly layout: string;
        reset(): void;
    };
    readonly text: string;
    readonly events: any[];
    readonly layout: string;
    reset(): void;
};
/** One-shot: a complete capture in, text and events out. */
export function decode(reports: any, opts?: {}): {
    text: string;
    events: any[];
    unmapped: any[];
};
/**
 * Split decoded text on the separators the firmware puts between fields.
 *
 * process_slot() emits TAB or RETURN after each field it types, chosen per slot
 * by the `addchar` byte, and types nothing at all for a field that is not
 * configured. So the separators say where the boundaries are but NOT which
 * field is which - a slot with only a password produces one segment, and so
 * does a slot with only a username.
 *
 * Mapping segments onto url / username / password / OTP therefore needs the
 * slot's own configuration, which the caller has and this does not. Guessing it
 * here would put a username in a password box some of the time, which is the
 * kind of wrong that is discovered late.
 */
export function splitFields(text: any): {
    segments: string[];
    separators: string[];
};
