'use strict';

/**
 * The composite post-quantum PGP identity, kept in Key Chain.
 *
 * One OpenPGP v6 key whose signatures are ML-DSA-65 + Ed25519 and whose
 * encryption is ML-KEM-768 + X25519: safe while either half holds, so a
 * future quantum computer breaking X25519/Ed25519 does not open it. The
 * firmware (3.0.5+) holds the four private seeds in an RSA slot (key type
 * 0x67) and answers decrypt and sign there; nothing else of it is on the key.
 *
 * WHY KEY CHAIN KEEPS THE CERTIFICATE. The device cannot give the public
 * certificate back - the slot holds 160 bytes of seeds, not the packets and
 * self-signatures a PGP certificate is made of. The phone makes the key, so
 * the phone is the only place the certificate ever exists; lose it and the
 * key in the slot still decrypts, but nobody can encrypt to it any more. So
 * the entry carries it (`pgp`), and it is backed up and exported with the
 * rest of the list.
 *
 * THE PRIVATE HALF exists once, in memory, between make() and load(): the
 * blob is zeroed the moment the device has it, and discard() zeroes one
 * that is never loaded. It is never in an entry - createEntry refuses one.
 *
 * openpgp is passed in (the vendored PQC fork), as pgp-import and cert take
 * it: this module stays plain.
 */

const compositePgp = require('../../src/crypto/composite_pgp');
const list = require('./list');

/**
 * Make a composite key on the host. The blob is the private half: load() it
 * into a slot, or discard() it.
 * @param {object} openpgp the vendored PQC openpgp.js
 * @param {{name?: string, email?: string}} [who] the user ID on the certificate
 * @returns {Promise<{blob: Uint8Array, pgp: string, pgpFingerprint: string, userId: string}>}
 */
async function make(openpgp, { name, email } = {}) {
  const who = {};
  if (name) who.name = name;
  if (email) who.email = email;
  const { armoredPublicKey, blob } = await compositePgp.generateCompositeKey(openpgp, {
    userId: Object.keys(who).length ? who : undefined,
  });
  const key = await openpgp.readKey({ armoredKey: armoredPublicKey });
  const userId = key.getUserIDs()[0] || '';
  return { blob, pgp: armoredPublicKey, pgpFingerprint: key.getFingerprint(), userId };
}

/** Zero a made key's private half; it can no longer be loaded. */
function discard(made) {
  if (made && made.blob) made.blob.fill(0);
  if (made) made.blob = null;
}

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
async function load(device, slot, made, opts = {}) {
  if (!made || !made.blob) throw new Error('this composite key was already loaded or discarded');
  if (!Number.isInteger(slot) || slot < 1 || slot > 4) throw new Error(`a composite key goes in an RSA slot (1-4); got ${slot}`);
  await device.loadKey(slot, { type: compositePgp.PQC_KEY_TYPE_BYTE, key: made.blob }, opts);
  discard(made);
  return entry({ slot, pgp: made.pgp, pgpFingerprint: made.pgpFingerprint, name: made.userId });
}

/**
 * The Key Chain entry for a composite key in a slot: its certificate, its
 * fingerprint (what tells two composite keys in one slot apart - there is no
 * raw public key to hash), no public key bytes.
 */
function entry({ slot, pgp, pgpFingerprint, name, ...rest }) {
  if (!pgpFingerprint) throw new Error('a composite entry needs its PGP fingerprint');
  return list.createEntry({
    ...rest,
    kind: 'slot',
    slot,
    /* as a PGP key made in the App records them: Remove on the slot finds this entry */
    slots: [slot],
    type: 'composite',
    publicKey: new Uint8Array(0),
    pgp,
    pgpFingerprint,
    ...(name ? { name } : {}),
  });
}

module.exports = { make, discard, load, entry };
