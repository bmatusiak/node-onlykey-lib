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
export function buildCreate({ info, certs, nonce }: {
    info: any;
    certs?: {} | undefined;
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
    certs: {
        gpg?: undefined;
    } | {
        gpg: {
            armored: any;
            fingerprint: any;
            signPublic: any;
        };
    };
};
export function verify(msg: any, { seen }?: {}): {
    ok: boolean;
    reason: any;
} | {
    ok: boolean;
    reason?: undefined;
};
export function recordFromCard(card: any, certs?: {}): {
    label: string;
    cert?: {
        armored: any;
        fingerprint: any;
        created: any;
        expires: any;
        signPublic: any;
    } | undefined;
    committer: {
        name: string;
        email: string;
    } | null;
    expires: any;
    gpgUid?: string | undefined;
    ssh?: string | undefined;
};
export function answer(msg: any, { entries, owner, approve, certifyAgent, write, now }: {
    entries: any;
    owner: any;
    approve: any;
    certifyAgent: any;
    write: any;
    now: any;
}): Promise<{
    ok: boolean;
    agents: {
        label: string;
        status: string;
        created: any;
        expires: any;
        kinds: string[];
    }[];
    agent?: undefined;
    refusal?: undefined;
    detail?: undefined;
} | {
    ok: boolean;
    agent: {
        card: any;
        certs: any;
    };
    agents?: undefined;
    refusal?: undefined;
    detail?: undefined;
} | {
    ok: boolean;
    refusal: string;
    detail: any;
    agents?: undefined;
    agent?: undefined;
} | {
    ok: boolean;
    refusal: string;
    agents?: undefined;
    agent?: undefined;
    detail?: undefined;
} | {
    ok: boolean;
    agent: {
        label: string;
        created: any;
        expires: any;
        kinds: string[];
    };
    agents?: undefined;
    refusal?: undefined;
    detail?: undefined;
}>;
