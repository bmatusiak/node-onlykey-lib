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
export const RSA_SLOTS: number[];
/**
 * What RSA slots 1-4 hold, with their labels: probeKeySlot's answer per slot (empty / composite / rsa).
 * @param {{probeKeySlot: Function, readKeyLabels?: Function}} device the lib's device service
 * @returns {Promise<Array<{slot: number, kind: string, label: string}>>}
 */
export function readRsaSlots(device: {
    probeKeySlot: Function;
    readKeyLabels?: Function;
}): Promise<Array<{
    slot: number;
    kind: string;
    label: string;
}>>;
/**
 * The slot to ask for this composite key, from the list and what the slots hold now. In order: a composite slot the
 * list has this key in; a composite slot labelled with its name; any other composite slot. A composite slot the list
 * gives to ANOTHER key is never chosen - the user is using it. The choice is a guess until the key answers: the
 * signature hook checks the answer against the certificate (composite_pgp registerCompositeHooks).
 * @param {object[]} entries the Key Chain list
 * @param {{pgpFingerprint: string, name?: string}} key the certificate's fingerprint and name
 * @param {Array<{slot: number, kind: string, label?: string}>} slots readRsaSlots()
 * @returns {{slot: number|null, candidates: number[], why: string|null}}
 */
export function locate(entries: object[], key: {
    pgpFingerprint: string;
    name?: string;
}, slots: Array<{
    slot: number;
    kind: string;
    label?: string;
}>): {
    slot: number | null;
    candidates: number[];
    why: string | null;
};
/**
 * The list after a slot read: an entry whose slot now holds a different kind of key (or none) is marked gone - never
 * dropped (list.present). Returns null when nothing changed.
 * @param {object[]} entries
 * @param {Array<{slot: number, kind: string}>} slots probes of some slots (only those are judged)
 * @param {string} [when] ISO time
 * @returns {object[]|null}
 */
export function reconcile(entries: object[], slots: Array<{
    slot: number;
    kind: string;
}>, when?: string): object[] | null;
/**
 * The list after the key PROVED this composite key is in `slot` (a signature that checked against the certificate,
 * a message it decrypted): an entry for the key at that slot, last seen now - made from the certificate the list
 * already holds when the key was listed elsewhere.
 * @param {object[]} entries
 * @param {{pgp: string, pgpFingerprint: string, name?: string}} key
 * @param {number} slot
 * @param {string} [when]
 * @returns {object[]}
 */
export function seen(entries: object[], key: {
    pgp: string;
    pgpFingerprint: string;
    name?: string;
}, slot: number, when?: string): object[];
/**
 * A composite certificate's facts, or null when the text is not a composite (+PQC) public key.
 * @param {object} openpgp the vendored PQC openpgp.js
 * @param {string} pgp armored public key
 * @returns {Promise<{pgpFingerprint: string, name: string, eccPublicKey: Uint8Array}|null>}
 */
export function certificate(openpgp: object, pgp: string): Promise<{
    pgpFingerprint: string;
    name: string;
    eccPublicKey: Uint8Array;
} | null>;
/**
 * Prove that `slot` holds the private half of this certificate, and return its Key Chain entry. One press.
 * @param {{composite_sign: Function}} okcrypto
 * @param {object} openpgp
 * @param {{slot: number, pgp: string, randomBytes: (n: number) => Uint8Array, opts?: object, when?: string}} args
 * @returns {Promise<object>} the entry (merge it into the list)
 */
export function adopt(okcrypto: {
    composite_sign: Function;
}, openpgp: object, { slot, pgp, randomBytes, opts, when }: {
    slot: number;
    pgp: string;
    randomBytes: (n: number) => Uint8Array;
    opts?: object;
    when?: string;
}): Promise<object>;
