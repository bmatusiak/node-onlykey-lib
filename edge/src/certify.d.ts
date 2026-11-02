export const TAGS: Readonly<{
    nametag: "OKEDGE-NAMETAG-v1";
    'login-card': "OKEDGE-CARD-v1";
    agent: "OKEDGE-AGENT-v1";
    revoke: "OKEDGE-AGENT-REVOKE-v1";
}>;
export const ACCEPTS: Readonly<{
    nametag: 1[];
    'login-card': 1[];
    agent: (1 | 2)[];
    revoke: 1[];
}>;
export const TOP_REACH: 1024;
/**
 * A login card, canonical: the fields in one fixed order, hex lower-case, the derive labels sorted - so every host that
 * rebuilds it gets the same bytes. Throws on a malformed one.
 * @param {{device: string, identity: string, site: string, derives: string[], signs: {slot: number, label: string, cap: number}}} c
 */
export function loginCard(c: {
    device: string;
    identity: string;
    site: string;
    derives: string[];
    signs: {
        slot: number;
        label: string;
        cap: number;
    };
}): {
    v: number;
    kind: string;
    device: string;
    identity: string;
    site: string;
    derives: string[];
    signs: {
        slot: number;
        label: string;
        cap: number;
    };
};
export function agentCard(c: any): {
    v: number;
    kind: string;
    label: string;
    created: any;
    expires: any;
    derive: {
        ssh: string;
        gpg: string;
    };
    committer: {
        name: string;
        email: string;
    } | null;
};
/** The 32 bytes the key certifies for a thing of this kind (the card's canonical JSON; a nametag its hash). */
export function subjectOf(kind: any, thing: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/**
 * A certified thing as hosts keep and sync it: {kind, thing, certification (hex)}.
 * @param {string} kind @param {object} thing @param {object} certification edge.certify()'s answer
 */
export function record(kind: string, thing: object, certification: object): {
    v: number;
    kind: string;
    thing: object;
    certification: {
        [k: string]: any;
    };
};
/**
 * The top as a card keeps it (hex). checkpoint: {seq, head, signature, signaturePq, gate?} with the head this host
 * welded - or {seq, gate} alone, a checkpoint whose head this host never held (a certify's); links: the raw links
 * after it, oldest first (none without the head).
 * @param {{seq: number, head?: Uint8Array | null, signature?: Uint8Array, signaturePq?: Uint8Array, gate?: Uint8Array}} checkpoint
 * @param {Uint8Array[]} links
 */
export function top(checkpoint: {
    seq: number;
    head?: Uint8Array | null;
    signature?: Uint8Array;
    signaturePq?: Uint8Array;
    gate?: Uint8Array;
}, links?: Uint8Array[]): {
    checkpoint: {
        seq: number;
        gate: string | null;
    };
    links: never[];
} | {
    checkpoint: {
        gate?: string | undefined;
        seq: number;
        head: string;
        signature: string;
        signaturePq: string;
    };
    links: string[];
};
/**
 * Does this top stand? Both checkpoint signatures under the key's checkpoint keys (READ from the key, never from the
 * card), every link welding on from the checkpoint's head in order, and the checkpoint at most TOP_REACH links behind
 * the key's head. -> {ok: true, checkpoint, newest: {seq, head}, links: [{link, head}]} | {ok: false, reason}
 * @param {object} t a card's top @param {{deviceId: Uint8Array, publicKey: Uint8Array, publicKeyPq: Uint8Array, keySeq: number}} key
 */
export function verifyTop(t: object, key: {
    deviceId: Uint8Array;
    publicKey: Uint8Array;
    publicKeyPq: Uint8Array;
    keySeq: number;
}): {
    ok: boolean;
    reason: any;
} | {
    ok: boolean;
    checkpoint: {
        seq: any;
        head: Uint8Array<ArrayBuffer>;
        signature: Uint8Array<ArrayBuffer>;
        signaturePq: Uint8Array<ArrayBuffer>;
    };
    newest: {
        seq: any;
        head: Uint8Array<ArrayBuffer>;
    };
    links: {
        link: Uint8Array<ArrayBuffer>;
        head: Uint8Array<ArrayBuffer>;
    }[];
};
/**
 * Is this record certified by MY owner keys, for exactly this thing, with an approval its kind accepts - and (a login
 * card) by the device it names? -> boolean (false on anything malformed).
 * @param {{kind: string, thing: object, certification: object}} rec
 * @param {Uint8Array} ownerKey @param {Uint8Array} ownerKeyPq the owner keys READ from the key (never from the record)
 */
export function verify(rec: {
    kind: string;
    thing: object;
    certification: object;
}, ownerKey: Uint8Array, ownerKeyPq: Uint8Array): boolean;
export function budgetAllowed(rec: any, scopes: any): {
    ok: boolean;
    why: any;
} | {
    ok: boolean;
    why?: undefined;
};
/**
 * MAY THIS BUDGET OPEN? (Brad, 2026-10-30: Edge auto-presses only what is inside a certified card picked from the list.)
 * Every scope inside the card: a derive scope on one of its labels (cap 1), a sign scope on slot 201 with its label and
 * no more than its cap. The HOSTS enforce this today; `keyEnforces` (the firmware checking its own signature over the card
 * at GRANT_CREATE) is the gate for later - off, and a host never relies on it being on.
 * @param {{thing: object}} rec a verified login-card record @param {Array<object>} scopes as grants.encodeScopes takes them
 * -> {ok: true} | {ok: false, why}
 */
export function deriveHash(d: any): string;
export const keyEnforces: false;
export function toStored(c: any): {
    [k: string]: any;
};
export function fromStored(c: any): {
    [k: string]: any;
};
