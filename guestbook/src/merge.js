'use strict';

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
async function classify(pinned, fetched, { openpgp } = {}) {
  if (pinned.format !== fetched.format || pinned.fingerprint !== fetched.fingerprint) return { result: 'changed' };
  if (pinned.format !== 'openpgp') return { result: 'same' };
  if (!openpgp) throw new Error('merging a PGP key needs the openpgp library');
  const mine = await openpgp.readKey({ armoredKey: pinned.text });
  const theirs = await openpgp.readKey({ armoredKey: fetched.text });
  const wasRevoked = await mine.isRevoked().catch(() => false);
  /* the fork's Key.update: same fingerprint only (it throws otherwise), keeps what verifies */
  const merged = await mine.update(theirs);
  const text = merged.armor();
  if (!wasRevoked && (await merged.isRevoked().catch(() => false))) return { result: 'revoked', text };
  return text === mine.armor() ? { result: 'same' } : { result: 'updated', text };
}

module.exports = { classify };
