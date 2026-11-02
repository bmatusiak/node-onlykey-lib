export const NO_SEQ: 4294967295;
/**
 * A copy's records + the offered ones, by seq. A seq on both sides with different bytes is a FORK - reported, never
 * chosen between.
 * -> {links (sorted by seq), added: [records], conflicts: [seq]}
 */
export function merge(have: any, offered: any): {
    links: any[];
    added: any[];
    conflicts: number[];
};
/**
 * Before another device's log is kept, that chain must hold up - no I/O (devices.classify runs it). (Named for the
 * anchors it served until 2026-10-08; the check itself is unchanged.)
 *   records:    the copy of that chain merged with what came
 *   publicKey:  that device's checkpoint key (X || Y), as its statement names it
 *   publicKeyPq: its ML-DSA-65 twin (1952 bytes), as its statement names it
 *   checkpoint: {seq, head, signature, signaturePq} read from that device's key
 *   anchors:    [{seq, head}] the points of that chain kept before
 * ALARMS:
 *   bad-checkpoint - not signed by that device's keys (both halves of the hybrid);
 *   rollback       - that device's head is now older than one kept before;
 *   changed        - at a seq kept before, that device's chain now holds another head;
 *   tampered       - the links do not verify up to the signed checkpoint.
 * -> {ok: true, verifiedThrough, open} | {ok: false, alarm, seq?, detail?}
 *
 * @param {{records: Array<{link: Uint8Array, head: Uint8Array, reveal?: Uint8Array|null}>, publicKey: Uint8Array, publicKeyPq: Uint8Array,
 *   checkpoint: {seq: number, head: Uint8Array, signature: Uint8Array, signaturePq: Uint8Array}, anchors?: Array<{seq: number, head: Uint8Array}>}} o
 * @returns {{ok: boolean, alarm?: string, seq?: number, detail?: string, verifiedThrough?: number, open?: any[]}}
 */
export function anchorCheck({ records, publicKey, publicKeyPq, checkpoint, anchors }: {
    records: Array<{
        link: Uint8Array;
        head: Uint8Array;
        reveal?: Uint8Array | null;
    }>;
    publicKey: Uint8Array;
    publicKeyPq: Uint8Array;
    checkpoint: {
        seq: number;
        head: Uint8Array;
        signature: Uint8Array;
        signaturePq: Uint8Array;
    };
    anchors?: Array<{
        seq: number;
        head: Uint8Array;
    }>;
}): {
    ok: boolean;
    alarm?: string;
    seq?: number;
    detail?: string;
    verifiedThrough?: number;
    open?: any[];
};
