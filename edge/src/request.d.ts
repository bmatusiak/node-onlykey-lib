export const TYPE: "EDGE_REQUEST";
export const MAX_REQUEST_USES: 300;
export const MAX_LIFETIME_MINUTES: number;
export const REFUSALS: readonly string[];
/** The asking side (an agent on a paired computer): a request. */
export function build({ reason, scopes, lifetime, continueOf, nonce }: {
    reason: any;
    scopes: any;
    lifetime: any;
    continueOf?: null | undefined;
    nonce?: (Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) | undefined;
}): Promise<{
    continue?: undefined;
    type: string;
    v: number;
    nonce: string;
    reason: string;
    scopes: any;
    lifetime: any;
}>;
/**
 * The app side, first: is it a well-formed request, and new? seen: the nonces already taken
 * (a Set the app keeps). -> {ok} or {ok: false, reason: 'malformed' | 'replayed'}. An app DROPS
 * these - it answers nothing. Who asks was settled before: the paired computer's encrypted
 * session (the phone's vendor bridge).
 */
export function verify(msg: any, { seen }?: {}): {
    ok: boolean;
    reason: string;
} | {
    ok: boolean;
    reason?: undefined;
};
/**
 * The app side, second: is the request one a budget may be? Caps (each >= 1,
 * together <= 300, D4), the lifetime (1 minute .. 24 hours), the ops, and an
 * identity on every derived code (R11a) that parses. -> {ok} or {ok: false, reason}.
 */
export function check(msg: any): {
    ok: boolean;
    reason: any;
    uses?: undefined;
} | {
    ok: boolean;
    uses: number;
    reason?: undefined;
};
export function grantScopes(msg: any): any;
export function reasonHash(reason: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/**
 * What the approval sheet shows: the text, the names (the identities the agent asks
 * for), the caps, the lifetime (who asks - the paired computer - the app adds). No "yours" mark and no red warning since
 * 2026-10-08 (Brad: "the agent can look at my keychain ... it can ask me to use it";
 * he reads the identities on the sheet and decides).
 */
export function view(msg: any, { covered }?: {
    covered?: never[] | undefined;
}): {
    reason: any;
    lifetime: any;
    uses: any;
    scopes: any;
    continues: any;
    covered: any[];
};
export function sameScopes(a: any, b: any): any;
export function peerSignerFromSecret(secret: any): {
    publicKey: Uint8Array<ArrayBuffer>;
    sign: (bytes: any) => Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
};
