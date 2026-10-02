/**
 * copy: {
 *   links:    [{link, head?, reveal?}] from seq 0, oldest first (reveal = the
 *             self-press's v_i, as PICKUP gave it),
 *   openings: {[grantId]: {scopes, reasonHash, genesis, uses, signature}} -
 *             what the host asked for and the checkpoint signature its press
 *             answered with (edge.grant's reply),
 * }
 * key: what the host read from the key THIS session: {publicKey, head (edge.head()),
 *      checkpoint (edge.checkpoint())}
 *
 * -> {ok: true, verifiedThrough, head} or {ok: false, reason, seq?, detail?}
 */
export function verifyCopy(copy: any, key: any): {
    ok: boolean;
    reason: any;
} | {
    ok: boolean;
    verifiedThrough: any;
    head: any;
};
