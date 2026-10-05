export function agentSubject(agentKey: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function peerSubject(peerKey: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function siblingSubject(key: any, deviceId: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function siblingCode(a: any, b: any): string;
export const MAX_USES: 1024;
export function grantGenesis(seed: any, uses: any): any;
/** The value use `step` reveals, from the seed (for tests and fakes - a host never has the seed). */
export function reveal(seed: any, uses: any, step: any): any;
/**
 * Check one self-press: {genesis, uses, step, value, mac, subject}.
 * -> {ok: true} or {ok: false, reason}:
 *    past-cap      step beyond the budget's uses (or below 1)
 *    wrong-step    the value is from THIS budget, but at another step
 *    wrong-budget  the value is from no step of this budget
 *    mac-mismatch  the value is right, but the MAC is not over this subject
 */
export function checkSelfPress({ genesis, uses, step, value, mac, subject }: {
    genesis: any;
    uses: any;
    step: any;
    value: any;
    mac: any;
    subject: any;
}): {
    ok: boolean;
    reason: string;
    actualStep?: undefined;
} | {
    ok: boolean;
    reason: string;
    actualStep: number;
} | {
    ok: boolean;
    reason?: undefined;
    actualStep?: undefined;
};
/**
 * Check a budget's spends in the order the chain recorded them: each must pass
 * checkSelfPress, and the steps must run 1, 2, 3... (a repeated step is a
 * replayed reveal; a skipped one is a self-press missing from the chain).
 * -> {ok, spent, failure?: {index, step, reason}}  reasons: the four above,
 *    plus step-reused and step-skipped.
 */
export function checkSpends(genesis: any, uses: any, spends: any): {
    ok: boolean;
    spent: number;
    failure: {
        index: number;
        step: any;
        reason: string | undefined;
    };
} | {
    ok: boolean;
    spent: any;
    failure?: undefined;
};
export function encodeScopes(scopes: any): Uint8Array<ArrayBuffer>;
export function grantSubject({ scopes, reasonHash, genesis, lifetime }: {
    scopes: any;
    reasonHash: any;
    genesis: any;
    lifetime?: number | undefined;
}): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function requestSubject(bytes: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function armToken({ head, subject }: {
    head: any;
    subject: any;
}): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/**
 * Check a budget's opening as one standalone proof:
 *   {deviceId, publicKey, link (its grant-create link), prevHead (the head
 *    before it), head + signature (the checkpoint the press answered with),
 *    scopes, reasonHash, genesis, uses}
 * -> {ok: true, grantId, seq} or {ok: false, reason}:
 *   uses-mismatch      the scopes' caps do not add up to uses
 *   not-a-grant-create the link is not a grant-create
 *   subject-mismatch   the link does not commit to these scopes, reason and G
 *   weld-mismatch      the signed head is not this link welded onto prevHead
 *   bad-signature      the checkpoint is not the Edge key's over (seq, head)
 * prevHead is not trusted: a wrong one cannot weld to the signed head.
 */
export function verifyBudgetOpening({ deviceId, publicKey, link, prevHead, head, signature, scopes, reasonHash, genesis, uses, lifetime }: {
    deviceId: any;
    publicKey: any;
    link: any;
    prevHead: any;
    head: any;
    signature: any;
    scopes: any;
    reasonHash: any;
    genesis: any;
    uses: any;
    lifetime?: number | undefined;
}): {
    ok: boolean;
    reason: string;
    grantId?: undefined;
    seq?: undefined;
} | {
    ok: boolean;
    grantId: number;
    seq: number;
    reason?: undefined;
};
export const DEFAULT_LIFETIME_MINUTES: number;
export function isDerivedCode(slot: any): boolean;
export function identityLabel(name: any): Uint8Array<ArrayBufferLike>;
export function scopeLabel(s: any): any;
