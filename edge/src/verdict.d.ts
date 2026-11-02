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
export const NO_SEQ: 4294967295;
