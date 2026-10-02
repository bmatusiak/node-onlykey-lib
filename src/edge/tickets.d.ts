export function messageHash(message: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function ticketSubject({ refSeq, refHead, code, msgHash }: {
    refSeq: any;
    refHead: any;
    code: any;
    msgHash: any;
}): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/**
 * Pair tickets with the uses they answer.
 *
 * entries: [{link, head}] in chain order (head = the weld stored with the
 *          link; needed to check a message against its ticket)
 * messages: {[refSeq]: text} - ticket messages from sync, untrusted
 *
 * -> {uses: [{seq, op, status, ticket?, message?}], orphans: [{seq, refSeq, reason}]}
 *    status: ticketed | alarm | missing | no-ticket-owed
 *    ticket: {seq, code, name, alarm}; message: the text, only when it matches,
 *            else null with messageStatus 'none' | 'mismatch' | 'unchecked'
 *    orphans: tickets for a seq that is not a use (or not one that came
 *             before), or a second ticket for the same use
 */
export function pairTickets(entries: any, messages?: {}): {
    uses: {
        seq: number;
        op: 1 | 2;
        status: string;
    }[];
    orphans: {
        seq: number;
        refSeq: number | undefined;
        reason: string;
    }[];
};
