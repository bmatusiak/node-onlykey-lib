export const TYPE: "EDGE_PRESS_ASK";
export const MAX_WHAT: 280;
/** The computer: "may I ask the key for this press?" */
export function build({ what, subject, code, nonce }: {
    what: any;
    subject: any;
    code: any;
    nonce?: (Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) | undefined;
}): {
    type: string;
    v: number;
    nonce: string;
    what: string;
};
/**
 * The app: a message well formed and new. seen: nonces already taken.
 * @returns {{ok: boolean, reason?: string}}
 */
export function verify(msg: any, { seen }?: {}): {
    ok: boolean;
    reason?: string;
};
/** "fdcb 11e0 5954 9b90" - the message's first 8 bytes, the way the CLI prints it */
export function shortSubject(hex: any): string;
