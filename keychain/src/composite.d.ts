/**
 * Make a composite key on the host. The blob is the private half: load() it
 * into a slot, or discard() it.
 * @param {object} openpgp the vendored PQC openpgp.js
 * @param {{name?: string, email?: string}} [who] the user ID on the certificate
 * @returns {Promise<{blob: Uint8Array, pgp: string, pgpFingerprint: string, userId: string}>}
 */
export function make(openpgp: object, { name, email }?: {
    name?: string;
    email?: string;
}): Promise<{
    blob: Uint8Array;
    pgp: string;
    pgpFingerprint: string;
    userId: string;
}>;
/** Zero a made key's private half; it can no longer be loaded. */
export function discard(made: any): void;
/**
 * Load a made key into an RSA slot (1-4), in config mode as OKSETPRIV
 * requires, then zero the blob. On a refusal the blob is kept, so the same
 * key can be loaded again once the reason is fixed - discard() it to give up.
 * @param {{loadKey: Function}} device the lib's device service
 * @param {number} slot
 * @param {object} made from make()
 * @param {{label?: string|null}} [opts] passed to loadKey: the slot's label tag
 * @returns {Promise<object>} the Key Chain entry for the slot
 */
export function load(device: {
    loadKey: Function;
}, slot: number, made: object, opts?: {
    label?: string | null;
}): Promise<object>;
/**
 * The Key Chain entry for a composite key in a slot: its certificate, its
 * fingerprint (what tells two composite keys in one slot apart - there is no
 * raw public key to hash), no public key bytes.
 */
export function entry({ slot, pgp, pgpFingerprint, name, ...rest }: {
    [x: string]: any;
    slot: any;
    pgp: any;
    pgpFingerprint: any;
    name: any;
}): object;
