/**
 * Sort one offered log.
 * @param {object} o
 * @param {{deviceId, publicKey, publicKeyPq, records, checkpoint, statement, card}} o.log
 *   records: [{link, head, reveal?}] of that device's chain; checkpoint: {seq, head, signature,
 *   signaturePq} from its key; statement (optional): {deviceId, publicKey, publicKeyPq, seq, nametag,
 *   signature, signaturePq}; card (optional): its certified login card (certify.record)
 * @param {Uint8Array} o.ownerKey   THIS device's own owner public key (X||Y)
 * @param {Uint8Array} o.ownerKeyPq THIS device's own owner ML-DSA-65 public key (1952 bytes)
 * @param {Array<{deviceId: string}>} [o.known]  your devices (deviceId hex)
 * @param {Array<{seq, head}>} [o.merged]  the points of that chain this device merged before
 * -> {class, deviceId (hex), nametag, check}. class: mine-known / mine-new (a verified card or nametag of this owner),
 *    unproven (neither carried: kept, shown, never yours, never the leak alarm), forged (a proof that does not verify)
 */
export function classify({ log, ownerKey, ownerKeyPq, known, merged }: {
    log: {
        deviceId: any;
        publicKey: any;
        publicKeyPq: any;
        records: any;
        checkpoint: any;
        statement: any;
        card: any;
    };
    ownerKey: Uint8Array;
    ownerKeyPq: Uint8Array;
    known?: {
        deviceId: string;
    }[] | undefined;
    merged?: {
        seq: any;
        head: any;
    }[] | undefined;
}): {
    class: string;
    deviceId: string;
    nametag: any;
    check: {
        ok: boolean;
        alarm?: string;
        seq?: number;
        detail?: string;
        verifiedThrough?: number;
        open?: any[];
    };
};
/**
 * The nametag a device goes by, from every statement of its own seen so far: the one with
 * the highest seq names it; the others are its history ("previously"). A statement that
 * does not verify under `ownerKey` and `ownerKeyPq` (both halves) is not counted.
 * -> {nametag, seq, previously: [nametag]} | null
 */
export function nametagOf(statements: any, ownerKey: any, ownerKeyPq: any): {
    nametag: any;
    seq: any;
    previously: any[];
} | null;
/**
 * Your devices list after a statement of one of them (yes to "is it yours?", or a newer
 * statement of a known one): one entry per fingerprint, its nametag history kept.
 * -> a new list; `devices` is not changed
 */
export function remember(devices: any, statement: any, { at }?: {
    at?: number | undefined;
}): any;
/** A device's stored statements as verifyStatement takes them. */
export function statementsOf(device: any): any;
export function checkOpenings({ deviceId, publicKey, records, openings }: {
    deviceId: any;
    publicKey: any;
    records: any;
    openings: any;
}): {
    from?: any;
    opened?: any;
    grantId: any;
    reason: any;
    scopes: any;
    uses: any;
    lifetime: any;
    genesis: string;
    signature: string;
}[];
export function shapeNotes(notes: any): {
    reasons: {};
    messages: {};
    seen: {};
};
export function completeness({ deviceId, publicKey, records, openings, notes }: {
    deviceId: any;
    publicKey: any;
    records: any;
    openings: any;
    notes: any;
}): {
    ok: boolean;
    missing: string[];
} | {
    ok: boolean;
    missing?: undefined;
};
