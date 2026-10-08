/**
 * Sort one offered log.
 * @param {object} o
 * @param {{deviceId, publicKey, records, checkpoint, statement}} o.log
 *   records: [{link, head, reveal?}] of that device's chain; checkpoint: {seq, head, signature}
 *   from its key; statement: {deviceId, publicKey, seq, nametag, signature}
 * @param {Uint8Array} o.ownerKey   THIS device's own owner public key (X||Y)
 * @param {Array<{deviceId: string}>} [o.known]  your devices (deviceId hex)
 * @param {Array<{seq, head}>} [o.merged]  the points of that chain this device merged before
 * -> {class, deviceId (hex), nametag, check}
 */
export function classify({ log, ownerKey, known, merged }: {
    log: {
        deviceId: any;
        publicKey: any;
        records: any;
        checkpoint: any;
        statement: any;
    };
    ownerKey: Uint8Array;
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
 * does not verify under `ownerKey` is not counted. -> {nametag, seq, previously: [nametag]} | null
 */
export function nametagOf(statements: any, ownerKey: any): {
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
