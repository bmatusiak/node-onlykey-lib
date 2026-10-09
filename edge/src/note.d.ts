export const TYPE: "EDGE_NOTE";
export const MAX_REASON: 280;
export const MAX_RECEIPT_MSG: 1024;
export const MAX_TX_REFUSED: 64;
/** The asking side: a note about `seq`. */
export function build({ seq, reason, receiptMsg, txRefused, nonce }: {
    seq: any;
    reason: any;
    receiptMsg: any;
    txRefused: any;
    nonce?: (Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) | undefined;
}): Promise<{
    txRefused?: string | undefined;
    receiptMsg?: string | undefined;
    reason?: string | undefined;
    type: string;
    v: number;
    nonce: string;
    seq: any;
}>;
/**
 * The app side: a note well formed and new. seen: nonces already taken. -> {ok} or {ok: false,
 * reason: 'malformed' | 'replayed'}. An app DROPS the rest. Who sent it is the paired computer.
 */
export function verify(msg: any, { seen }?: {}): {
    ok: boolean;
    reason: string;
} | {
    ok: boolean;
    reason?: undefined;
};
