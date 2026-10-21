export const VERSION: 1;
/** A copy with nothing in it yet. */
export function empty(deviceId: any): {
    deviceId: any;
    links: never[];
    lastSeen: null;
    publicKey: null;
    publicKeyPq: null;
    seals: never[];
    checkpoint: null;
    statement: null;
    openings: never[];
};
/**
 * A copy from its JSON (the CLI's copy-<id>.json, the bucket's edge.copies entries). An older
 * version is the old chain's: read as no copy.
 * @param {object|null} s
 * @param {Uint8Array} deviceId
 */
export function fromJSON(s: object | null, deviceId: Uint8Array): {
    deviceId: any;
    links: never[];
    lastSeen: null;
    publicKey: null;
    publicKeyPq: null;
    seals: never[];
    checkpoint: null;
    statement: null;
    openings: never[];
} | {
    deviceId: Uint8Array<ArrayBufferLike>;
    links: any;
    lastSeen: {
        seq: any;
        head: Uint8Array<ArrayBuffer>;
    } | null;
    publicKey: Uint8Array<ArrayBuffer> | null;
    publicKeyPq: Uint8Array<ArrayBuffer> | null;
    seals: any;
    openings: any;
    notes: any;
    checkpoint: {
        seq: any;
        head: Uint8Array<ArrayBuffer>;
        signature: Uint8Array<ArrayBuffer>;
        signaturePq: Uint8Array<ArrayBuffer>;
    } | null;
    statement: {
        deviceId: Uint8Array<ArrayBuffer>;
        publicKey: Uint8Array<ArrayBuffer>;
        publicKeyPq: Uint8Array<ArrayBuffer>;
        seq: any;
        nametag: any;
        signature: Uint8Array<ArrayBuffer>;
        signaturePq: Uint8Array<ArrayBuffer>;
    } | null;
};
/**
 * A copy as JSON.
 * @param {ReturnType<typeof empty>} c
 */
export function toJSON(c: ReturnType<typeof empty>): {
    statement?: {
        deviceId: string;
        publicKey: string;
        publicKeyPq: string;
        seq: any;
        nametag: any;
        signature: string;
        signaturePq: string;
    } | undefined;
    checkpoint?: {
        seq: any;
        head: string;
        signature: string;
        signaturePq: string;
    } | undefined;
    notes?: any;
    openings?: never[] | undefined;
    seals: {
        signaturePq?: string | undefined;
        seq: any;
        head: string;
        signature: string;
    }[];
    publicKeyPq?: string | undefined;
    publicKey?: string | undefined;
    v: number;
    deviceId: string;
    links: {
        reveal?: string | undefined;
        link: string;
        head: string;
    }[];
    lastSeen: {
        seq: any;
        head: string;
    } | null;
};
/**
 * Two copies of one device into one.
 * @param {ReturnType<typeof empty>} a the copy kept here
 * @param {ReturnType<typeof empty>} b the copy brought in
 * @returns {{copy: ReturnType<typeof empty>, taken: number, fork: null | {seq: number, reason: string}}}
 *   fork: the copies disagree - `a` is kept as it was, nothing of `b` is taken
 */
export function merge(a: ReturnType<typeof empty>, b: ReturnType<typeof empty>): {
    copy: ReturnType<typeof empty>;
    taken: number;
    fork: null | {
        seq: number;
        reason: string;
    };
};
/**
 * The copy as JSON blocks (block.js), each checked against the public keys kept with the copy - the
 * newest block with both halves (the one hybrid anchor), older ones by P-256 - and against the block
 * before it. The audit dump: public, checkable by anyone with the keys.
 * @param {ReturnType<typeof empty>} c
 * @param {{net: string}} opts
 */
export function blocks(c: ReturnType<typeof empty>, { net }: {
    net: string;
}): {
    reason?: string | undefined;
    deviceId: string;
    blocks: {
        reason?: any;
        block: {
            v: number;
            net: "test" | "live";
            device: string;
            prev: string | null;
            start: {
                seq: number;
                head: string;
            };
            links: {
                seq: number;
                op: string;
                decision: number;
                slot: number;
                flags: number;
                subject: string;
                grant: number;
                step: number;
                scope: number;
                intent: string | null;
                v: number;
            }[];
            checkpoint: {
                sigPq?: string | undefined;
                seq: number;
                head: string;
                sig: string;
            };
        };
        id: string;
        ok: any;
    }[];
    open: number;
};
export function seqOf(r: any): number;
