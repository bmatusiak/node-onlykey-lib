export const HAVE_TYPE: "EDGE_SYNC_HAVE";
export const LINKS_TYPE: "EDGE_SYNC_LINKS";
export const KEYCHAIN_TYPE: "EDGE_SYNC_KEYCHAIN";
export const COMMIT_TYPE: "EDGE_SYNC_COMMIT";
export const TAKE_TYPE: "EDGE_SYNC_TAKE";
export const SIBLING_TYPE: "EDGE_SIBLING_ADD";
export const GIVE_TYPE: "EDGE_SYNC_GIVE";
export const ANCHOR_TYPE: "EDGE_SYNC_ANCHOR";
export const BATCH: 40;
export const NO_SEQ: 4294967295;
/**
 * R29 (P2b): ask the phone whose key is `deviceId` to pair it with another
 * key of yours (its Edge key X || Y and device id, read from that key by this
 * place). The place only RELAYS that key - the phone shows a code made from
 * both keys (grants.siblingCode) that the other phone shows too.
 */
export function buildSibling({ signer, deviceId, key, id, name }: {
    signer: any;
    deviceId: any;
    key: any;
    id: any;
    name: any;
}): Promise<{
    type: any;
    v: number;
    peer: string;
    nonce: string;
    payload: any;
}>;
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
 * R30: "that is the sibling's chain up to its signed checkpoint - anchor it".
 * chain: the sibling's device id; checkpoint: {seq, head, signature} from the
 * sibling's key; name: the sibling as the place calls it (shown, never trusted).
 */
export function buildAnchor({ signer, deviceId, sid, chain, linkParts, checkpoint, name }: {
    signer: any;
    deviceId: any;
    sid: any;
    chain: any;
    linkParts: any;
    checkpoint: any;
    name: any;
}): Promise<{
    type: any;
    v: number;
    peer: string;
    nonce: string;
    payload: any;
}>;
/**
 * R30 (P2c): before a phone anchors its sibling, the sibling's chain as offered
 * must hold up - the phone's side, no I/O.
 *   records:    the phone's copy of the sibling's chain merged with what came
 *   publicKey:  the sibling's Edge key (X || Y), from the KEY's sibling list
 *   checkpoint: {seq, head, signature} the place read from the sibling's key
 *   anchors:    [{seq, head}] this phone anchored that sibling at before
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
/** The place's side: "that is everything - merge it and ask". pcIds: the ids its list holds. */
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
 * The phone's side: signed by the key it names, well formed, new. Whether that
 * key is on the KEY's peer list is the caller's check (it needs the device).
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
/**
 * The `sync` link's fields (spec, 2026-10-05; onlykey-edge firmware.md):
 * SHA256(peer pubkey X || Y) . first seq moved . last seq moved . the phone
 * copy's head after the merge . SHA256(the merged Key Chain list), or 32 zero
 * bytes when no list moved. The KEY computes the subject from these (SYNC's
 * three parts) and checks the peer hash is one of its own peers.
 * -> {peerHash, first, last, head, keychain}
 */
export function syncFields({ peer, added, head, keychainHash }: {
    peer: any;
    added: any;
    head: any;
    keychainHash?: null | undefined;
}): {
    peerHash: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
    first: number;
    last: number;
    head: Uint8Array<ArrayBufferLike>;
    keychain: Uint8Array<ArrayBufferLike>;
};
/**
 * The subject: SHA256("OKEDGE-SYNC-v1" || peerHash || u32le first || u32le last
 * || head || keychain) - the bytes the key hashes, in its order.
 */
export function syncSubject(fields: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
