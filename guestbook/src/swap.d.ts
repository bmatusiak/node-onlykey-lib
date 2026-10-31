export const VERSION: 1;
export const T: Readonly<{
    OPEN: 49;
    KEYS: 50;
    REVEAL: 51;
    DONE: 52;
    CONFIRM: 53;
    CARD: 54;
    BYE: 55;
}>;
export const BYE_REASONS: string[];
/** @param {{identity: {publicKey, decapsulate}, invite: {id, token}, randomBytes}} p */
export function showerStart({ identity, invite, randomBytes }: {
    identity: {
        publicKey: any;
        decapsulate: any;
    };
    invite: {
        id: any;
        token: any;
    };
    randomBytes: any;
}): {
    role: string;
    identity: {
        publicKey: any;
        decapsulate: any;
    };
    invite: {
        id: any;
        token: any;
    };
    randomBytes: any;
    step: string;
};
/** OPEN -> KEYS. */
export function showerOnOpen(state: any, msg: any): {
    state: any;
    msg: Uint8Array<any>;
};
/**
 * REVEAL -> DONE. The token is checked first; only then is the OnlyKey asked to open the
 * scanner's seal (the press). Async: that is the device.
 */
export function showerOnReveal(state: any, msg: any, now?: number): Promise<{
    state: any;
    msg: Uint8Array<any>;
}>;
/** CONFIRM -> the session, and the scanner's contact key. */
export function showerOnConfirm(state: any, msg: any): {
    session: {
        send: Uint8Array<ArrayBuffer>;
        recv: Uint8Array<ArrayBuffer>;
        sendCtr: number;
        recvCtr: number;
        dirSend: number;
        dirRecv: number;
    };
    peer: {
        publicKey: any;
        id: Uint8Array<ArrayBuffer>;
    };
};
/** @param {{identity: {publicKey, decapsulate}, invite: {id, token}, randomBytes}} p -> {state, msg: OPEN} */
export function scannerStart({ identity, invite, randomBytes }: {
    identity: {
        publicKey: any;
        decapsulate: any;
    };
    invite: {
        id: any;
        token: any;
    };
    randomBytes: any;
}): {
    state: {
        role: string;
        identity: {
            publicKey: any;
            decapsulate: any;
        };
        invite: {
            id: any;
            token: any;
        };
        nB: any;
        pubB: any;
        step: string;
    };
    msg: Uint8Array<any>;
};
/** KEYS -> REVEAL. The shower's key must be the one the QR names. */
export function scannerOnKeys(state: any, msg: any): {
    state: any;
    msg: Uint8Array<any>;
};
/** DONE -> CONFIRM, the session and the shower's contact key. Async: this OnlyKey's press. */
export function scannerOnDone(state: any, msg: any): Promise<{
    msg: Uint8Array<any>;
    session: {
        send: Uint8Array<ArrayBuffer>;
        recv: Uint8Array<ArrayBuffer>;
        sendCtr: number;
        recvCtr: number;
        dirSend: number;
        dirRecv: number;
    };
    peer: {
        publicKey: any;
        id: Uint8Array<ArrayBuffer>;
    };
}>;
/** Seal this person's card for the other phone. */
export function sealCard(session: any, card: any): Uint8Array<any>;
/** Open the other phone's card; refused if tampered, replayed, malformed or carrying a private key. */
export function openCard(session: any, msg: any): {
    name: string;
    keys: any;
};
/** The keys a person picked: {name, keys: [{format, label, text}]}, public only and bounded. */
export function checkCard(card: any): {
    name: string;
    keys: any;
};
export function sealBye(session: any, reason: any): Uint8Array<any>;
/** The other phone's next sealed message: {kind: 'card', card} or {kind: 'bye', reason}. */
export function openMessage(session: any, msg: any): {
    kind: string;
    card: {
        name: string;
        keys: any;
    };
    reason?: undefined;
} | {
    kind: string;
    reason: any;
    card?: undefined;
};
/** Seal one message: [ctr 4][AES-256-GCM ct][tag 16]. Mutates the session's send counter. */
export function sealFrame(session: any, plaintext: any): Uint8Array<any>;
/** Open one frame, or throw. Only a counter higher than the last one is taken. */
export function openFrame(session: any, frame: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
