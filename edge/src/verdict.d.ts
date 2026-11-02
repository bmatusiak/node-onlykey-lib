/**
 * @param {{deviceId: Uint8Array, links: Array<{link: Uint8Array, head: Uint8Array, reveal?: Uint8Array|null}>, anchor?: {seq: number, head: Uint8Array}|null, seals?: Array<{seq: number, head: Uint8Array, signature: Uint8Array}>, lastSeen?: {seq: number, head: Uint8Array}|null}} c
 * @param {{seq: number, head: Uint8Array|null, ringFrom: number}|null} head
 * @param {{publicKey?: Uint8Array|null, publicKeyPq?: Uint8Array|null, checkpoint?: {seq: number, head: Uint8Array, signature: Uint8Array, signaturePq?: Uint8Array|null}|null, openings?: any}|null} key
 * @param {{held?: Array<{link: Uint8Array, head: Uint8Array}>, prev?: any, noFull?: boolean, say?: (t: string) => void}} [opts]
 * @returns {{verdict: any, unverified: number[], state: any, path: string|null} | null}
 */
export function verdict(c: {
    deviceId: Uint8Array;
    links: Array<{
        link: Uint8Array;
        head: Uint8Array;
        reveal?: Uint8Array | null;
    }>;
    anchor?: {
        seq: number;
        head: Uint8Array;
    } | null;
    seals?: Array<{
        seq: number;
        head: Uint8Array;
        signature: Uint8Array;
    }>;
    lastSeen?: {
        seq: number;
        head: Uint8Array;
    } | null;
}, head: {
    seq: number;
    head: Uint8Array | null;
    ringFrom: number;
} | null, key: {
    publicKey?: Uint8Array | null;
    publicKeyPq?: Uint8Array | null;
    checkpoint?: {
        seq: number;
        head: Uint8Array;
        signature: Uint8Array;
        signaturePq?: Uint8Array | null;
    } | null;
    openings?: any;
} | null, { held, prev, noFull, say }?: {
    held?: Array<{
        link: Uint8Array;
        head: Uint8Array;
    }>;
    prev?: any;
    noFull?: boolean;
    say?: (t: string) => void;
}): {
    verdict: any;
    unverified: number[];
    state: any;
    path: string | null;
} | null;
/**
 * The digest of a copy's first n links (each link and its head, in order).
 * @param {Array<{link: Uint8Array, head: Uint8Array}>} links
 * @param {number} [n]
 * @returns {string}
 */
export function digestOf(links: Array<{
    link: Uint8Array;
    head: Uint8Array;
}>, n?: number): string;
export function anchorOf(c: any): any;
export function sealedStart(c: any, head: any, key: any, say: any): {
    seq: any;
    head: any;
} | null;
/**
 * May links offered for a key's OWN chain be taken into its copy? (S4 step 6 - one set of rules for every host: the
 * desktop taking this computer's shared records, a CLI taking a copy it was given.) In: what merging them gave
 * (sync.merge: added, conflicts), the copy WITH them checked like any copy (its verdict, the seqs that check verified),
 * and its accepted losses (copy.lossesIn). Out: {ok: true} or {ok: false, refusal, detail}.
 *
 *   a fork (a link that disagrees with one the copy holds): refused - never chosen between
 *   the copy would not verify with them (other than a gap): refused
 *   EVERY LINK TAKEN IS A CHECKED ONE (Brad, 2026-10-11: "checking every field in a token means nothing if we never
 *   check the signature"): a link the check did not verify - welded to the key's signed checkpoint - is refused, unless
 *   it lies inside a range the key accepted as lost (a LOSS link, R24: the LOSS accounts for it, and the link after it
 *   welds to it - key 1, 2026-10-24). A gap verdict alone once let links inside the gap in unchecked; the real links at
 *   those seqs were refused later as a fork.
 *
 * @param {{added: Array<{link: Uint8Array}>, conflicts: number[], verdict: {kind: string}, verifiedSeqs: Set<number> | number[], losses?: Array<{from: number, to: number}>}} o
 * @returns {{ok: true} | {ok: false, refusal: string, detail: string}}
 */
export function takeOwn({ added, conflicts, verdict: v, verifiedSeqs, losses }: {
    added: Array<{
        link: Uint8Array;
    }>;
    conflicts: number[];
    verdict: {
        kind: string;
    };
    verifiedSeqs: Set<number> | number[];
    losses?: Array<{
        from: number;
        to: number;
    }>;
}): {
    ok: true;
} | {
    ok: false;
    refusal: string;
    detail: string;
};
export const NO_SEQ: 4294967295;
