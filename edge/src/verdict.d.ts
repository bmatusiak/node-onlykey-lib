export function verdict(c: any, head: any, key: any, { held, prev, noFull, say }?: {
    held?: never[] | undefined;
    prev?: null | undefined;
    noFull?: boolean | undefined;
    say?: (() => void) | undefined;
}): {
    verdict: any;
    unverified: any[];
    state: {
        seq: any;
        head: string;
        count: any;
        lastSeq: number;
        lastHead: string;
        digest: string;
        verdict: any;
        unverified: any[];
    } | null;
    path: any;
} | {
    verdict: any;
    unverified: any;
    state: never;
    path: string;
} | null;
/** The digest of a copy's first n links (each link and its head, in order). */
export function digestOf(links: any, n?: any): string;
export function anchorOf(c: any): any;
export function sealedStart(c: any, head: any, key: any, say: any): {
    seq: any;
    head: any;
} | null;
export const NO_SEQ: 4294967295;
