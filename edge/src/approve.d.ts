/**
 * @param {object} msg an EDGE_REQUEST
 * @param {object} o
 * @param {object} o.edge the Edge device service (edge/plugin) for THIS app's key
 * @param {string|null} [o.from] the paired computer that asked (its pairing id) - a continue must come from the same one
 * @param {Set<string>} o.seen nonces already taken (the caller keeps it)
 * @param {(view: object) => Promise<'approve'|'decline'|'timeout'|'copy_unverified'>} o.ask the screen
 *   ('timeout': nobody answered the sheet; 'copy_unverified': the sheet could
 *   not offer Approve, the app's copy did not verify)
 * @param {() => Promise<{ok: boolean, head: Uint8Array}>} o.verifyCopy R27: the
 *   app's copy checked; head = the key's head it verified up to
 * @param {(grantId: number) => ({from: string|null, scopes: object[]} | null)} [o.budgetOf]
 *   a continue: the app's own record of the budget it continues (who asked,
 *   which scopes) - null when the app never opened it
 * @param {(msg: object) => Promise<object[]>|object[]} [o.coverOf] the live
 *   budgets that already cover what this request names (view().covered)
 * @param {() => void} [o.onPress] told when the key waits for the press
 * @param {number} [o.timeoutMs] the press wait (the key's own is 25 s)
 * @returns {Promise<{ok: true, budget: object} | {ok: false, refusal: string} | {dropped: string}>}
 *   dropped: nothing is answered (malformed, replayed)
 */
export function approveRequest(msg: object, { edge, from, seen, ask, verifyCopy, budgetOf, coverOf, onPress, timeoutMs }: {
    edge: object;
    from?: string | null | undefined;
    seen: Set<string>;
    ask: (view: object) => Promise<"approve" | "decline" | "timeout" | "copy_unverified">;
    verifyCopy: () => Promise<{
        ok: boolean;
        head: Uint8Array;
    }>;
    budgetOf?: ((grantId: number) => ({
        from: string | null;
        scopes: object[];
    } | null)) | undefined;
    coverOf?: ((msg: object) => Promise<object[]> | object[]) | undefined;
    onPress?: (() => void) | undefined;
    timeoutMs?: number | undefined;
}): Promise<{
    ok: true;
    budget: object;
} | {
    ok: false;
    refusal: string;
} | {
    dropped: string;
}>;
