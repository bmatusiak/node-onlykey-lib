/**
 * Build (or renew - the same `created` keeps the fingerprint) the certificate.
 * Two presses: the user ID certification and the subkey binding.
 * @param {object} okcrypto  the app's okcrypto service
 * @param {object} openpgp   the fork (node-onlykey-lib/crypto/pgp)
 * @param {{label: string, version?: number, created?: number, expires?: number, onPress?: Function}} o
 *   expires: seconds after `created` (0 / absent: never)
 * @returns {Promise<{uid: string, armored: string, fingerprint: string, created: number, expires: number, signPublic: Uint8Array}>}
 */
export function makeCertificate(okcrypto: object, openpgp: object, { label, version, created, expires, onPress }?: {
    label: string;
    version?: number;
    created?: number;
    expires?: number;
    onPress?: Function;
}): Promise<{
    uid: string;
    armored: string;
    fingerprint: string;
    created: number;
    expires: number;
    signPublic: Uint8Array;
}>;
/**
 * A revocation certificate for the key (one press).
 * @param {{label: string, version?: number, created: number, reason?: number, text?: string, onPress?: Function}} o
 *   created: the certificate's creation time - it is in the fingerprint being revoked
 */
export function makeRevocation(okcrypto: any, openpgp: any, { label, version, created, reason, text, onPress }?: {
    version?: number | undefined;
    reason?: number | undefined;
    text?: string | undefined;
}): Promise<{
    uid: string;
    armored: string;
    fingerprint: string;
}>;
export function uidOf(label: any): string;
/**
 * Before a certificate (spec session, 2026-10-03, no firmware exemption):
 * refuse while the key owes anything - R18 would hold every budget anyway, and
 * our own presses would join an unexplained list. -> the seq to ticket after.
 * @param {object|null} edge the key's Edge plugin, or null (no Edge: nothing to do)
 * @returns {Promise<number|null>}
 */
export function guardOwed(edge: object | null): Promise<number | null>;
/**
 * After the presses: under R16 a press with a key a live budget covers owes a
 * ticket. File ours at once - code OK, "cert self-signature <fingerprint>".
 * @returns {Promise<number[]>} the seqs ticketed
 */
export function ticketOwnPresses(edge: any, startSeq: any, fingerprint: any): Promise<number[]>;
