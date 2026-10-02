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
/** The bytes the digest is taken over (what an ECDSA-SHA256 signer that hashes for itself would sign). */
export function budgetGenesisMessage({ deviceId, grantId, genesis, uses, scopes, reasonHash, chainSeq, chainHead }: {
    deviceId: any;
    grantId: any;
    genesis: any;
    uses: any;
    scopes: any;
    reasonHash: any;
    chainSeq: any;
    chainHead: any;
}): Uint8Array<ArrayBuffer>;
export function budgetGenesisDigest(fields: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/**
 * Check a budget's signed genesis: {deviceId, grantId, genesis, uses, scopes,
 * reasonHash, chainSeq, chainHead}, the key's 64-byte signature, and the Edge
 * public key. -> {ok: true} or {ok: false, reason}:
 *   uses-mismatch  the scopes' caps do not add up to the budget's uses
 *   bad-signature  not signed by this key over exactly these fields
 */
export function verifyBudgetGenesis(fields: any, signature: any, publicKey: any): {
    ok: boolean;
    reason: string;
} | {
    ok: boolean;
    reason?: undefined;
};
/** What the key does at the press - for the fake key and tests; a host never holds the Edge signing key. */
export function signBudgetGenesis(fields: any, secretKey: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
