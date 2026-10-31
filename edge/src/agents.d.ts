export const LIST_TYPE: "EDGE_AGENT_LIST";
export const GET_TYPE: "EDGE_AGENT_GET";
export const CREATE_TYPE: "EDGE_AGENT_CREATE";
export const TYPES: string[];
export function store(net: any): "edge-agents-test" | "edge-agents";
export function infoFromRecord(record: any, label: any): {
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
export function certsFromRecord(record: any): {
    gpg: {
        armored: any;
        fingerprint: any;
        signPublic: any;
    };
};
/**
 * The list as a host shows it: each entry checked. status: 'usable' | 'expired' | 'revoked' | 'unverified' (not this
 * owner's, or malformed - never given to an agent).
 * @param {Object<string, string>} entries the store's live keys -> values (JSON)
 * @param {Uint8Array} ownerKey @param {Uint8Array} ownerKeyPq read from the key
 * @param {number} [now] seconds
 */
export function list(entries: {
    [x: string]: string;
}, ownerKey: Uint8Array, ownerKeyPq: Uint8Array, now?: number): {
    label: string;
    status: string;
    created: any;
    expires: any;
    kinds: string[];
    entry: any;
}[];
/** One usable identity by label -> {card, certs}; throws naming why not (missing, revoked, expired, unverified). */
export function pick(entries: any, label: any, ownerKey: any, ownerKeyPq: any, now: any): {
    card: any;
    certs: any;
};
/** A label already taken (any status - a revoked one stays taken): creating it again is refused. */
export function taken(entries: any, label: any): boolean;
export function budgetAllowed(card: any, scopes: any): {
    ok: boolean;
    why: any;
} | {
    ok: boolean;
    why?: undefined;
};
export function budgetNames(card: any): any[];
export function scopeLabels(card: any): Uint8Array<ArrayBufferLike>[];
export function buildList({ nonce }?: {
    nonce?: (Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) | undefined;
}): {
    type: string;
    v: number;
    nonce: string;
};
export function buildGet({ label, nonce }: {
    label: any;
    nonce?: (Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) | undefined;
}): {
    type: string;
    v: number;
    nonce: string;
    label: string;
};
export function buildCreate({ info, nonce }: {
    info: any;
    nonce?: (Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) | undefined;
}): {
    type: string;
    v: number;
    nonce: string;
    info: {
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
};
export function verify(msg: any, { seen }?: {}): {
    ok: boolean;
    reason: any;
} | {
    ok: boolean;
    reason?: undefined;
};
