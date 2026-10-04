export const TYPE: "EDGE_NOTE";
export const MAX_REASON: 280;
export const MAX_TICKET_MSG: 1024;
export const MAX_ARM_REFUSED: 64;
/** The signed bytes of a note. */
export function body({ agent, nonce, seq, reason, ticketMsg, armRefused }: {
    agent: any;
    nonce: any;
    seq: any;
    reason: any;
    ticketMsg: any;
    armRefused: any;
}): Uint8Array<ArrayBuffer>;
/** The agent side: a signed note about `seq`. */
export function build({ signer, seq, reason, ticketMsg, armRefused, nonce }: {
    signer: any;
    seq: any;
    reason: any;
    ticketMsg: any;
    armRefused: any;
    nonce?: (Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) | undefined;
}): Promise<{
    armRefused?: string | undefined;
    ticketMsg?: string | undefined;
    reason?: string | undefined;
    type: string;
    v: number;
    agent: string;
    nonce: string;
    seq: any;
}>;
/**
 * The app side: a note from a registered agent, signed, well formed and new.
 * registered: agent public keys (hex) registered with a press; seen: nonces
 * already taken. -> {ok} or {ok: false, reason: 'malformed' | 'unregistered' |
 * 'bad-signature' | 'replayed'}. An app DROPS the rest.
 */
export function verify(msg: any, { registered, seen }?: {}): {
    ok: boolean;
    reason: string;
} | {
    ok: boolean;
    reason?: undefined;
};
