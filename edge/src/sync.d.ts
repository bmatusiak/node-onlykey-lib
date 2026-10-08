export const HAVE_TYPE: "EDGE_SYNC_HAVE";
export const LINKS_TYPE: "EDGE_SYNC_LINKS";
export const KEYCHAIN_TYPE: "EDGE_SYNC_KEYCHAIN";
export const COMMIT_TYPE: "EDGE_SYNC_COMMIT";
export const TAKE_TYPE: "EDGE_SYNC_TAKE";
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
/** The place's side: "that is everything - merge it and ask". pcIds: the ids its list holds. */
/**
 * The computer's side: "that is device `chain`'s log up to its signed checkpoint, with its
 * statement" - for the phone whose key is `deviceId` to HOLD until the person approves.
 * checkpoint: {seq, head, signature}; statement: {publicKey, seq, nametag, signature} (as
 * plugin.statement gives it, or as that device's phone kept it).
 */
export function buildOffer({ signer, deviceId, sid, chain: chainId, linkParts, checkpoint, statement }: {
    signer: any;
    deviceId: any;
    sid: any;
    chain: any;
    linkParts: any;
    checkpoint: any;
    statement: any;
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
 * ALARMS (spec R30: "a sibling anchors a head its own chain doesn't contain:
 * one device's rollback or tampering is proven by the other"):
 *   bad-checkpoint - not signed by the sibling's key;
 *   rollback       - the sibling's head is now older than one already anchored;
 *   changed        - at a seq already anchored, the sibling's chain now holds another head;
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
/** The entries as list.serialize writes them (public key hex), id order, keys sorted, no lastSeen - one text for one list, on any side. */
export function keychainText(entries: any): string;
/** SHA256 of the list in id order - the sync link's last field when a list moved. */
export function keychainDigest(entries: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/** Entries as plain JSON objects (public key hex), split into parts of about KEYCHAIN_PART_CHARS. */
export function keychainParts(entries: any): any[][];
/** Plain entry objects back to entries - every one checked again (list.parse refuses anything private or "yours"). */
export function keychainEntriesOf(plain: any): any;
/** The place's side: its whole list, signed parts under the sync's sid. */
export function buildKeychain({ signer, deviceId, sid, entries }: {
    signer: any;
    deviceId: any;
    sid: any;
    entries: any;
}): Promise<{
    type: any;
    v: number;
    peer: string;
    nonce: string;
    payload: any;
}[]>;
export function buildCommit({ signer, deviceId, sid, linkParts, keychainParts: kcParts }: {
    signer: any;
    deviceId: any;
    sid: any;
    linkParts: any;
    keychainParts: any;
}): Promise<{
    type: any;
    v: number;
    peer: string;
    nonce: string;
    payload: any;
}>;
/** The place's side, after the press: one part of the merged list. */
export function buildTake({ signer, deviceId, sid, part }: {
    signer: any;
    deviceId: any;
    sid: any;
    part: any;
}): Promise<{
    type: any;
    v: number;
    peer: string;
    nonce: string;
    payload: any;
}>;
/**
 * The phone's side: its list + the place's. -> {merged, in (entries new to the
 * phone, or joined with a twin), out (merged entries the place does not hold as
 * they are)} - out is what TAKE will give back.
 */
export function keychainPlan(phoneEntries: any, placeEntries: any): {
    merged: object[];
    in: number;
    out: number;
};
/**
 * The place's side, after TAKE: the merged list must hold every entry the place
 * had (by id, or joined into a twin) - a phone that dropped one is refused.
 * -> {ok, entries} | {ok: false, missing: [id]}
 */
export function checkTaken(placeEntries: any, taken: any): {
    ok: boolean;
    missing: any;
    entries?: undefined;
} | {
    ok: boolean;
    entries: any;
    missing?: undefined;
};
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
