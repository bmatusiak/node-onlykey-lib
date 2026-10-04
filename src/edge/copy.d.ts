/**
 * copy: {
 *   links:    [{link, head?, reveal?}] from seq 0, oldest first (reveal = the
 *             self-press's v_i, as PICKUP gave it),
 *   openings: {[grantId]: {scopes, reasonHash, genesis, uses, lifetime, signature}} -
 *             what the host asked for and the checkpoint signature its press
 *             answered with (edge.grant's reply),
 * }
 * key: what the host read from the key THIS session: {publicKey, head (edge.head()),
 *      held (optional: the links PICKUP gave from the key's ring - trusted as they are),
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
/**
 * The one answer to "what does this copy prove" (R27), for the banner and
 * Approve alike. key: {publicKey, head {seq, head}, held?, checkpoint?} -
 * or {deviceId, ...} with no public key (a test key that signs nothing): then
 * the anchors are the genesis and HEAD only;
 * opts.ringFrom: the oldest seq the key still holds (missing links at or
 * above it were removed, not lost); opts.lastSeen: the head this host verified
 * last session (an older one now is a rollback).
 * -> {chain (chain.verify's result), anchors, missing, losses, open}
 *    missing: ranges no anchor reaches, minus the key's own links;
 *    losses: the verified LOSS links; open: missing ranges none of them covers.
 */
export function assess(copy: any, key: any, opts?: {}): {
    chain: {
        ok: boolean;
        verifiedThrough: number;
        gaps: never[];
        failure: {
            seq: any;
            reason: any;
        };
    } | {
        ok: boolean;
        verifiedThrough: number;
        gaps: {
            from: any;
            to: any;
        }[];
        failure: {
            seq: any;
            reason: string;
        };
    } | {
        ok: boolean;
        verifiedThrough: number;
        gaps: {
            from: any;
            to: any;
        }[];
        failure?: undefined;
    };
    anchors: any[];
    missing: {
        from: any;
        to: number;
    }[];
    losses: {
        seq: number;
        from: number;
        to: number;
        next: Uint8Array<ArrayBuffer> | null;
    }[];
    open: {
        from: any;
        to: number;
    }[];
};
/** The LOSS links in a run of entries: [{seq, from, to}] (to = 0xFFFFFFFF: not said - covers to the LOSS itself). */
export function lossesIn(entries: any): {
    seq: number;
    from: number;
    to: number;
    next: Uint8Array<ArrayBuffer> | null;
}[];
/** The really missing ranges no verified, later LOSS links cover. held: the key's own links, this session. */
export function uncoveredGaps(entries: any, gaps: any, held: any): {
    from: any;
    to: number;
}[];
/** gaps (from chain.verify) minus the links the key itself vouches for - what is really missing */
export function missingGaps(entries: any, gaps: any, held: any): {
    from: any;
    to: number;
}[];
export function checkContinue(link: any, oldCopy: any): {
    ok: boolean;
    reason: string;
    oldSeq?: undefined;
    debts?: undefined;
    debtsChecked?: undefined;
} | {
    ok: boolean;
    reason: string;
    oldSeq: number;
    debts?: undefined;
    debtsChecked?: undefined;
} | {
    ok: boolean;
    oldSeq: number;
    debts: any[];
    debtsChecked: boolean;
    reason?: undefined;
};
