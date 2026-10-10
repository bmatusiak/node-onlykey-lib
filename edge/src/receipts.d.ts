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
export function settleSubject(seqs: any, overflow: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
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
 * The key's own debt list, replayed over the chain (firmware R16-R18), so a
 * host can compare its copy with what HEAD reports (R27):
 *   - an approved sign/decrypt is pushed; past OWED_MAX the oldest falls off
 *     for good and `overflow` is set (only a settle clears it);
 *   - a receipt pays its ref_seq if that use is still on the list;
 *   - a SETTLE (0x8F, the press flag, the subject over exactly this list and
 *     this overflow) clears the list and the overflow.
 * Nothing else changes it: a deny, a timeout, a grant-end, a LOSS.
 *
 * The list does not refill: once a use fell off, a later receipt for a newer
 * one does not bring it back. (Taking "the newest 4 unpaid" instead disagrees
 * with the key after a 5th use and one receipt - 4 waiting by that count, 3
 * owed + overflow on the key.)
 *
 * Replay from the chain's first link; a copy that starts later cannot know
 * the list it started with.
 * -> {owed: [seq, oldest first], overflow, dropped: [seq] (fell off, never paid by a receipt)}
 */
export function keyDebts(entries: any): {
    owed: any[];
    overflow: boolean;
    dropped: any[];
};
export const OWED_MAX: 4;
