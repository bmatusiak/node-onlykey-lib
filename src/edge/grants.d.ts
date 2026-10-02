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
