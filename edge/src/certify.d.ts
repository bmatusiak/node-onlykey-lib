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
/** The 32 bytes the key certifies for a thing of this kind (the card's canonical JSON; a nametag its hash). */
export function subjectOf(kind: any, thing: any): any;
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
/**
 * MAY THIS BUDGET OPEN? (Brad, 2026-10-30: Edge auto-presses only what is inside a certified card picked from the list.)
 * Every scope inside the card: a derive scope on one of its labels (cap 1), a sign scope on slot 201 with its label and
 * no more than its cap. The HOSTS enforce this today; `keyEnforces` (the firmware checking its own signature over the card
 * at GRANT_CREATE) is the gate for later - off, and a host never relies on it being on.
 * @param {{thing: object}} rec a verified login-card record @param {Array<object>} scopes as grants.encodeScopes takes them
 * -> {ok: true} | {ok: false, why}
 */
export function budgetAllowed(rec: {
    thing: object;
}, scopes: Array<object>): {
    ok: boolean;
    why: any;
} | {
    ok: boolean;
    why?: undefined;
};
export const keyEnforces: false;
export function toStored(c: any): {
    [k: string]: any;
};
export function fromStored(c: any): {
    [k: string]: any;
};
