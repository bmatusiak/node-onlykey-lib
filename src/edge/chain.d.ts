export const LINK_BYTES: 64;
export const REASONS: readonly string[];
export function encodeLink(f: any): Uint8Array<ArrayBuffer>;
export function decodeLink(b: any): {
    reservedZero: boolean;
    code?: number | undefined;
    refSeq?: number | undefined;
    seq: number;
    op: number;
    decision: number;
    slot: number;
    flags: number;
    subject: Uint8Array<ArrayBuffer>;
    grantId: number;
    grantStep: number;
};
export function genesis(deviceId: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function weld(head: any, link: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/** Heads for a run of links from a start head: [head[first], head[first+1], ...]. */
export function heads(links: any, startHead: any): (Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>)[];
/**
 * Verify a run of links (oldest first, as the mirror holds them).
 *
 * opts:
 *   deviceId        the key being verified (its genesis is the default start)
 *   mirrorDeviceId  the key the mirror says it belongs to -> device-mismatch
 *   fromSeq, fromHead  start somewhere other than genesis: fromHead = head[fromSeq-1]
 *   anchors         [{seq, head}] verified checkpoints: resume points after a gap
 *   expectHead      {seq, head} the key's live HEAD
 *   lastSeen        {seq, head} the head this host verified last session -> rollback
 *   ringFrom        lowest seq the key's ring still holds: missing links at or
 *                   above it are tampering (they could have been read), below it
 *                   they are a gap
 *
 * -> {ok, verifiedThrough, gaps: [{from, to}], failure?: {seq, reason}}
 *    verifiedThrough = the last seq of the unbroken verified run from the start
 *    (fromSeq - 1 when none); gaps = every unverifiable range up to the end.
 */
export function verify(entries: any, opts?: {}): {
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
