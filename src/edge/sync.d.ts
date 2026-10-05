export const HAVE_TYPE: "EDGE_SYNC_HAVE";
export const LINKS_TYPE: "EDGE_SYNC_LINKS";
export const BATCH: 40;
export function body({ type, peer, nonce, payload }: {
    type: any;
    peer: any;
    nonce: any;
    payload: any;
}): Uint8Array<ArrayBuffer>;
/** The place's side, first: what does the phone's copy of this chain hold? */
export function buildHave({ signer, deviceId, name }: {
    signer: any;
    deviceId: any;
    name: any;
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
export function buildLinks({ signer, deviceId, records, sid }: {
    signer: any;
    deviceId: any;
    records: any;
    sid?: string | undefined;
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
