/**
 * THE PINNING RULE (GUEST-BOOK-SPEC.md, "Auto-update and trust rules"): "a contact's key stays
 * current without you re-finding it, and a key never changes behind your back."
 *
 * The primary fingerprint is the pin. A fetched copy with the SAME fingerprint is a newer copy of
 * the same key and merges by itself; a DIFFERENT one never applies - it waits for the person.
 *
 *   same     nothing new
 *   updated  same key, more in it: a new subkey, a later expiry, new user ids - merged
 *   revoked  same key, now carrying its revocation - merged (ignoring a revocation would be worse)
 *   changed  another key - held as pending, never applied
 *
 * Only OpenPGP has "a newer copy of the same key"; for age, SSH and raw keys the fingerprint is the
 * whole key, so the answer is same or changed.
 */
/**
 * @param {{format: string, text: string, fingerprint: string}} pinned
 * @param {{format: string, text: string, fingerprint: string}} fetched - a formats.js find
 * @param {{openpgp?: any}} [opts]
 * @returns {Promise<{result: 'same' | 'updated' | 'revoked' | 'changed', text?: string}>}
 */
export function classify(pinned: {
    format: string;
    text: string;
    fingerprint: string;
}, fetched: {
    format: string;
    text: string;
    fingerprint: string;
}, { openpgp }?: {
    openpgp?: any;
}): Promise<{
    result: "same" | "updated" | "revoked" | "changed";
    text?: string;
}>;
