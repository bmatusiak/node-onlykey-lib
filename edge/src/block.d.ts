export const BLOCK_VERSION: 1;
export const NETS: readonly string[];
export function canonical(value: any): string;
export function blockId(block: any): string;
/**
 * One block: the links between two seals, and the seal.
 *
 * @param {object} o
 * @param {'live'|'test'} o.net
 * @param {Uint8Array} o.deviceId           16 bytes
 * @param {{seq: number, head: Uint8Array}} o.start  the head BEFORE the first link: the
 *   previous block's checkpoint, or genesis (seq = the first link's seq)
 * @param {string|null} o.prev               the previous block's id (hex), null for the first
 * @param {Uint8Array[]} o.links             64-byte links, in seq order, ending at the checkpoint
 * @param {{seq: number, head: Uint8Array, signature: Uint8Array}} o.checkpoint  the key's seal
 * @param {{deviceId, seq, head, signature}[]} [o.seen]  the sibling checkpoints this block's
 *   ANCHOR links record (each must match an ANCHOR link's subject)
 */
export function buildBlock({ net, deviceId, start, prev, links, checkpoint, seen }: {
    net: "live" | "test";
    deviceId: Uint8Array;
    start: {
        seq: number;
        head: Uint8Array;
    };
    prev: string | null;
    links: Uint8Array[];
    checkpoint: {
        seq: number;
        head: Uint8Array;
        signature: Uint8Array;
    };
    seen?: {
        deviceId: any;
        seq: any;
        head: any;
        signature: any;
    }[] | undefined;
}): {
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
        seq: number;
        head: string;
        sig: string;
    };
    seen: {
        device: string;
        seq: any;
        head: string;
        sig: string;
    }[];
};
/**
 * The blocks a copy holds: its links cut at its seals, each block naming the one
 * before it. A copy that does not reach back to its chain's start (genesis, or a
 * CONTINUE link) cannot say what came before, so it gives no blocks - after the
 * clean start every copy is whole from genesis.
 *
 * @param {object} o
 * @param {'live'|'test'} o.net
 * @param {Uint8Array} o.deviceId
 * @param {{link: Uint8Array}[]} o.records  the copy, in seq order
 * @param {{seq, head, signature}[]} o.seals  the key's checkpoints taken when a block closed
 * @param {{deviceId, seq, head, signature}[]} [o.seen]  sibling checkpoints this chain anchored
 * -> {blocks, open (links after the last seal), reason?}
 */
export function blocksFrom({ net, deviceId, records, seals, seen }: {
    net: "live" | "test";
    deviceId: Uint8Array;
    records: {
        link: Uint8Array;
    }[];
    seals: {
        seq: any;
        head: any;
        signature: any;
    }[];
    seen?: {
        deviceId: any;
        seq: any;
        head: any;
        signature: any;
    }[] | undefined;
}): {
    blocks: {
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
            seq: number;
            head: string;
            sig: string;
        };
        seen: {
            device: string;
            seq: any;
            head: string;
            sig: string;
        }[];
    }[];
    open: number;
    reason: string;
} | {
    blocks: {
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
            seq: number;
            head: string;
            sig: string;
        };
        seen: {
            device: string;
            seq: any;
            head: string;
            sig: string;
        }[];
    }[];
    open: number;
    reason?: undefined;
};
/**
 * Check a block on its own terms, trusting only `publicKey` (the device's Edge
 * key, read from the key). With `prevBlock`, also check it continues that block.
 * -> {ok: true, id} or {ok: false, reason}
 *
 * @param {object} block
 * @param {Uint8Array} publicKey  the device's Edge public key (X||Y), from the key
 * @param {object|null} [prevBlock]
 * @returns {{ok: boolean, id?: string, reason?: string}}
 */
export function verifyBlock(block: object, publicKey: Uint8Array, prevBlock?: object | null): {
    ok: boolean;
    id?: string;
    reason?: string;
};
export function linkFields(bytes: any): {
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
};
export function linkBytes(f: any): Uint8Array<ArrayBuffer>;
