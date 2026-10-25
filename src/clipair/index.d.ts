export const VERSION: 1;
export const T: Readonly<{
    COMMIT: 1;
    KEYS: 2;
    REVEAL: 3;
    DONE: 4;
    CONFIRM: 5;
    PAIRED: 6;
    HELLO: 16;
    HELLO_OK: 17;
    RENEW_OFFER: 32;
    RENEW_ACCEPT: 33;
}>;
export const PAIR_WINDOW: number;
export const RENEW_AFTER: number;
export const EXPIRES_AFTER: number;
/** A static X-Wing key pair: the CLI user's (in its owner-only file) or the phone's (Keystore-wrapped). */
export function generateIdentity(): {
    secretKey: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
    publicKey: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
};
/** A pairing is named by its CLI user's public key: SHA256("OKT-ID-v1" || pub)[0..16]. */
export function idOf(pub: any): Uint8Array<ArrayBuffer>;
export function codeOf(cliPub: any, phonePub: any, cliNonce: any, phoneNonce: any): string;
/** CLI step 1 -> PAIR_COMMIT {C, name}. Keep `state` for the next step. */
export function cliPairStart({ identity, name }: {
    identity: any;
    name: any;
}): {
    state: {
        identity: any;
        nonce: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
        commit: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
        nameBytes: any;
    };
    msg: Uint8Array<any>;
};
/**
 * Phone step 1: a PAIR_COMMIT while "Pair a computer" is open (`windowOpenUntil`,
 * ms) -> PAIR_KEYS {phone pub, phone nonce}. Outside the window: null (silence).
 */
export function phonePairOnCommit({ identity, windowOpenUntil, now }: {
    identity: any;
    windowOpenUntil: any;
    now: any;
}, msg: any): {
    state: {
        identity: any;
        commit: Uint8Array<ArrayBuffer>;
        name: any;
        nonce: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
        windowOpenUntil: any;
    };
    msg: Uint8Array<any>;
} | null;
/** CLI step 2: PAIR_KEYS -> PAIR_REVEAL {cli pub, cli nonce, ct to the phone} and the code to print. */
export function cliPairOnKeys(state: any, msg: any): {
    state: any;
    msg: Uint8Array<any>;
    code: string;
};
/** Phone step 2: PAIR_REVEAL -> the code to show (or null: the reveal does not match the commitment - silence). */
export function phonePairOnReveal(state: any, msg: any, now: any): {
    state: any;
    code: string;
} | null;
/**
 * Phone step 3, after Brad checked the code and approved (Pair + confirm):
 * -> PAIR_DONE {ct to the CLI, MAC} and a PENDING record, stored only once the
 * CLI's PAIR_CONFIRM proves it derived the same secret.
 */
export function phonePairApprove(state: any, now: any, { peerAddress }?: {}): {
    pending: {
        id: string;
        name: any;
        mac: string | null;
        cliPub: string;
        ps: string;
        epoch: number;
        renewedAt: any;
        on: boolean;
        lastUsed: null;
        oldPs: never[];
        code: any;
    };
    msg: Uint8Array<any>;
};
/** CLI step 3: PAIR_DONE -> the CLI's record to store, and PAIR_CONFIRM for the phone. */
export function cliPairOnDone(state: any, msg: any, now: any): {
    record: {
        phoneId: string;
        phonePub: string;
        id: string;
        ps: string;
        epoch: number;
        renewedAt: any;
        code: any;
    };
    msg: Uint8Array<any>;
};
/** Phone step 4: PAIR_CONFIRM -> the record becomes active (true), or not (false: drop it). */
export function phonePairOnConfirm(pending: any, msg: any): boolean;
export function phonePairAck(record: any): Uint8Array<any>;
export function cliPairOnAck(record: any, msg: any): boolean;
/** CLI: HELLO {pairing id, epoch, computer name, ephemeral pub, MAC(PS)}; keep `state` for HELLO_OK. */
export function cliHello(record: any, { name }?: {}): {
    state: {
        record: any;
        eph: {
            secretKey: import("@noble/post-quantum/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array>;
            publicKey: import("@noble/post-quantum/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array>;
        };
        body: Uint8Array<any>;
    };
    msg: Uint8Array<any>;
};
export function phoneOnHello(records: any, msg: any, now: any, { peerAddress }?: {}): {
    revoke: any;
    reason: string;
    silence?: undefined;
    expired?: undefined;
    session?: undefined;
    record?: undefined;
    msg?: undefined;
} | {
    silence: boolean;
    revoke?: undefined;
    reason?: undefined;
    expired?: undefined;
    session?: undefined;
    record?: undefined;
    msg?: undefined;
} | {
    silence: boolean;
    expired: any;
    revoke?: undefined;
    reason?: undefined;
    session?: undefined;
    record?: undefined;
    msg?: undefined;
} | {
    session: {
        send: Uint8Array<ArrayBuffer>;
        recv: Uint8Array<ArrayBuffer>;
        sendCtr: number;
        recvCtr: number;
        dirSend: number;
        dirRecv: number;
        id: any;
    };
    record: any;
    msg: Uint8Array<any>;
    revoke?: undefined;
    reason?: undefined;
    silence?: undefined;
    expired?: undefined;
} | {
    alarm: string;
};
/** CLI: HELLO_OK -> its session (throws on a bad answer - never talks to a phone that can't prove PS). */
export function cliOnHelloOk(state: any, msg: any): {
    send: Uint8Array<ArrayBuffer>;
    recv: Uint8Array<ArrayBuffer>;
    sendCtr: number;
    recvCtr: number;
    dirSend: number;
    dirRecv: number;
    id: any;
};
/** Seal one message: [ctr 4][AES-256-GCM ct][tag 16]. Mutates the session's send counter. */
export function seal(session: any, plaintext: any): Uint8Array<any>;
/** Open one frame, or throw. Only a counter higher than the last one is taken. */
export function open(session: any, frame: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function renewDue(record: any, now: any): boolean;
/** Phone, in a session, on day 6+: RENEW_OFFER {ephemeral pub} (send it sealed); keep `state`. */
export function phoneRenewOffer(): {
    state: {
        eph: {
            secretKey: import("@noble/post-quantum/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array>;
            publicKey: import("@noble/post-quantum/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array>;
        };
    };
    payload: Uint8Array<any>;
};
/**
 * CLI: RENEW_OFFER -> RENEW_ACCEPT {ct, MAC(PS')} (send it sealed) and the record
 * to SAVE: the current secret kept, the renewed one beside it as `next`
 * (two-phase - see phoneOnHello). cliUseNext / cliDropNext settle it on the
 * next connection.
 */
export function cliRenewAccept(record: any, payload: any, now: any): {
    record: any;
    payload: Uint8Array<any>;
};
/** Phone: RENEW_ACCEPT -> the record with the renewed secret PENDING until the CLI first proves it (or null). */
export function phoneRenewFinish(record: any, state: any, payload: any, now: any): any;
/** CLI: the renewed secret worked (the phone answered a hello under it) - it becomes the pairing; the old is forgotten. */
export function cliUseNext(record: any): any;
/** CLI: the phone never got the renewal (it answered the current secret) - forget the unused one. */
export function cliDropNext(record: any): any;
