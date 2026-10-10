export function messageHash(message: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function receiptSubject({ refSeq, refHead, code, msgHash }: {
    refSeq: any;
    refHead: any;
    code: any;
    msgHash: any;
}): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/**
 * Pair receipts with the uses they answer.
 *
 * entries: [{link, head}] in chain order (head = the weld stored with the
 *          link; needed to check a message against its receipt)
 * messages: {[refSeq]: text} - receipt messages from sync, untrusted
 *
 * -> {uses: [{seq, op, status, receipt?, message?}], orphans: [{seq, refSeq, reason}]}
 *    status: receipted | alarm | waiting | missing | no-receipt-owed
 *            (waiting = the latest use, still able to get its receipt)
 *    receipt: {seq, code, name, alarm}; message: the text, only when it matches,
 *            else null with messageStatus 'none' | 'mismatch' | 'unchecked'
 *    orphans: receipts for a seq that is not a use (or not one that came
 *             before), or a second receipt for the same use
 */
export function settleSubject(seq: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function pairReceipts(entries: any, messages?: {}): {
    uses: {
        seq: number;
        op: 1 | 2;
        status: string;
        /** @type {{seq: number, code: number, name: string | null, alarm: boolean} | null} */
        receipt: {
            seq: number;
            code: number;
            name: string | null;
            alarm: boolean;
        } | null;
        /** @type {string | null} */
        message: string | null;
        /** @type {'none' | 'match' | 'mismatch' | 'unchecked' | null} */
        messageStatus: "none" | "match" | "mismatch" | "unchecked" | null;
        /** @type {number | null} the settle link that cleared it, if a settle did */
        settledBy: number | null;
    }[];
    orphans: {
        seq: number;
        refSeq: number | undefined;
        reason: string;
    }[];
};
/**
 * The key's debt, replayed over the chain (SPEC.md R16-R18), so a host can compare its copy
 * with what HEAD reports (R27). The key keeps ONE owed use: nothing starts while one is owed
 * (Brad, 2026-10-10: "Drop the owed list = yes").
 *   - a use the key marked owes_receipt becomes the owed use;
 *   - a receipt for it pays it;
 *   - a SETTLE (0x8F, the press flag, the subject over its seq) clears it.
 * Replay from the chain's first link; a copy that starts later cannot know what it started with.
 * -> {owed: [seq] or []}
 */
export function keyDebts(entries: any): {
    owed: number[];
};
