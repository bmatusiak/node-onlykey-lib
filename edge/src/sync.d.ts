export const HAVE_TYPE: "EDGE_SYNC_HAVE";
export const LINKS_TYPE: "EDGE_SYNC_LINKS";
export const COMMIT_TYPE: "EDGE_SYNC_COMMIT";
export const GIVE_TYPE: "EDGE_SYNC_GIVE";
export const OFFER_TYPE: "EDGE_SYNC_OFFER";
export const BATCH: 40;
export const NO_SEQ: 4294967295;
/** R30: the place asks the phone whose key is `deviceId` for its copy of its own chain, from seq `from` (BATCH at a time). */
export function buildGive({ signer, deviceId, from }: {
    signer: any;
    deviceId: any;
    from?: number | undefined;
}): Promise<{
    type: any;
    v: number;
    peer: string;
    nonce: string;
    payload: any;
}>;
/**
 * The computer's side: "that is device `chain`'s log up to its signed checkpoint, with its
 * statement" - for the phone whose key is `deviceId` to HOLD until the person approves.
 * checkpoint: {seq, head, signature}; statement: {publicKey, seq, nametag, signature} (as
 * plugin.statement gives it, or as that device's phone kept it).
 */
export function buildOffer({ signer, deviceId, sid, chain: chainId, linkParts, checkpoint, statement, openings, notes }: {
    signer: any;
    deviceId: any;
    sid: any;
    chain: any;
    linkParts: any;
    checkpoint: any;
    statement: any;
    openings?: never[] | undefined;
    notes?: null | undefined;
}): Promise<{
    type: any;
    v: number;
    peer: string;
    nonce: string;
    payload: any;
}>;
/**
 * Before a phone merges another device's log, that chain as offered must hold up - the
 * phone's side, no I/O (devices.classify runs it). (Named for the anchors it served until
 * 2026-10-08; the check itself is unchanged.)
 *   records:    the phone's copy of that chain merged with what came
 *   publicKey:  that device's checkpoint key (X || Y), as its statement names it
 *   checkpoint: {seq, head, signature} read from that device's key
 *   anchors:    [{seq, head}] the points of that chain this phone merged before
 * ALARMS (spec R30, written when the key kept siblings: "a sibling anchors a head its
 * own chain doesn't contain: one device's rollback or tampering is proven by the other";
 * the check now runs on the phone, against heads it merged before):
 *   bad-checkpoint - not signed by that device's key;
 *   rollback       - that device's head is now older than one this phone merged before;
 *   changed        - at a seq merged before, that device's chain now holds another head;
 *   tampered       - the links do not verify up to the signed checkpoint.
 * -> {ok: true, verifiedThrough, open} | {ok: false, alarm, seq?, detail?}
 *
 * @param {{records: Array<{link: Uint8Array, head: Uint8Array, reveal?: Uint8Array|null}>, publicKey: Uint8Array,
 *   checkpoint: {seq: number, head: Uint8Array, signature: Uint8Array}, anchors?: Array<{seq: number, head: Uint8Array}>}} o
 * @returns {{ok: boolean, alarm?: string, seq?: number, detail?: string, verifiedThrough?: number, open?: any[]}}
 */
export function anchorCheck({ records, publicKey, checkpoint, anchors }: {
    records: Array<{
        link: Uint8Array;
        head: Uint8Array;
        reveal?: Uint8Array | null;
    }>;
    publicKey: Uint8Array;
    checkpoint: {
        seq: number;
        head: Uint8Array;
        signature: Uint8Array;
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
/** The place's side: "that is every part" - the phone merges its own links at once (no sheet, no press since 2026-10-08). */
export function buildCommit({ signer, deviceId, sid, linkParts }: {
    signer: any;
    deviceId: any;
    sid: any;
    linkParts: any;
}): Promise<{
    type: any;
    v: number;
    peer: string;
    nonce: string;
    payload: any;
}>;
export function body({ type, peer, nonce, payload }: {
    type: any;
    peer: any;
    nonce: any;
    payload: any;
}): Uint8Array<ArrayBuffer>;
/** The place's side, first: what does the phone's copy of this chain hold? */
export function buildHave({ signer, deviceId, name, chain }: {
    signer: any;
    deviceId: any;
    name: any;
    chain?: null | undefined;
}): Promise<{
    type: any;
    v: number;
    peer: string;
    nonce: string;
    payload: any;
}>;
/**
 * The place's side: the links the phone lacks, in signed batches of <= BATCH.
 * records: [{link, head, reveal?}] (bytes). -> [message, ...] (one sid for all)
 */
export function buildLinks({ signer, deviceId, records, sid, chain }: {
    signer: any;
    deviceId: any;
    records: any;
    sid?: string | undefined;
    chain?: null | undefined;
}): Promise<{
    type: any;
    v: number;
    peer: string;
    nonce: string;
    payload: any;
}[]>;
/**
 * The phone's side: signed by the key it names, well formed, new. Which computer
 * that key is, is the caller's to show (the link itself came over a Bluetooth
 * pairing the person approved with its 6-digit code).
 * -> {ok} | {ok: false, reason}
 */
export function verify(msg: any, { seen }?: {}): {
    ok: boolean;
    reason: string;
} | {
    ok: boolean;
    reason?: undefined;
};
/** The records a LINKS message carries, as bytes. */
export function recordsOf(msg: any): any;
/** [[from, to], ...] covering a set of seqs - what a copy holds, said compactly. */
export function rangesOf(seqs: any): any[][];
/** The place's side: its records the phone's ranges do not cover. */
export function missing(records: any, ranges: any): any;
/**
 * The phone's side: its copy's records + the offered ones, by seq. A seq on
 * both sides with different bytes is a FORK - reported, never chosen between.
 * -> {links (sorted by seq), added: [records], conflicts: [seq]}
 */
export function merge(have: any, offered: any): {
    links: any[];
    added: any[];
    conflicts: number[];
};
