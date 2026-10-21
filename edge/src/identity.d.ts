export const SET_TYPE: "EDGE_IDENTITY_SET";
export const GET_TYPE: "EDGE_IDENTITY_GET";
export const TYPES: string[];
/**
 * A record well formed? -> {ok: true} or {ok: false, reason}. The reason names the field,
 * because the computer that built a bad one is told exactly which.
 * @param {any} r
 * @returns {{ok: boolean, reason?: string}}
 */
export function checkRecord(r: any): {
    ok: boolean;
    reason?: string;
};
/** Only the record's own fields, in a fixed order (a stored or sent record carries nothing else). */
export function clean(r: any): {
    ssh: any;
    gpgUid: any;
    committer: {
        name: any;
        email: any;
    } | null;
    expires: any;
    cert: {
        armored: any;
        fingerprint: any;
        created: any;
        expires: any;
        signPublic: any;
    };
};
/** The computer: "keep this identity" (the phone asks the person). */
export function buildSet({ record, nonce }: {
    record: any;
    nonce?: (Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) | undefined;
}): {
    type: string;
    v: number;
    nonce: string;
    record: {
        ssh: any;
        gpgUid: any;
        committer: {
            name: any;
            email: any;
        } | null;
        expires: any;
        cert: {
            armored: any;
            fingerprint: any;
            created: any;
            expires: any;
            signPublic: any;
        };
    };
};
/** The computer: "which identity do you keep?" */
export function buildGet({ nonce }?: {
    nonce?: (Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) | undefined;
}): {
    type: string;
    v: number;
    nonce: string;
};
/**
 * The phone: a message well formed and new. seen: nonces already taken. -> {ok} or
 * {ok: false, reason: 'malformed' | 'replayed' | <the record's reason>}.
 * @param {any} msg
 * @param {{seen?: Set<string>}} [o]
 * @returns {{ok: boolean, reason?: string}}
 */
export function verify(msg: any, { seen }?: {
    seen?: Set<string>;
}): {
    ok: boolean;
    reason?: string;
};
/**
 * The rows the phone's sheet and Edge Management show, and the CLI prints: the same words
 * everywhere (no screen invents its own).
 * @param {any} record
 * @returns {Array<[string, string]>}
 */
export function rows(record: any): Array<[string, string]>;
/** Two records the same identity (same labels, same certificate)? */
export function same(a: any, b: any): boolean;
/** "7FBF 276C …" - a fingerprint the way the sheet and the drawer show it. */
export function spacedFingerprint(fp: any): string;
