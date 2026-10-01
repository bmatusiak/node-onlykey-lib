'use strict';

/**
 * Key Chain's encrypted private copies - the owner's "option to encrypt a
 * copy", in BOTH formats, for a key made on the host (the device's own keys
 * never leave it, so they have no copy to make).
 *
 *   pgp  an armored OpenPGP private key, protected by OpenPGP's own
 *        passphrase encryption (the fork's encryptKey). gpg reads it, and so
 *        does every OnlyKey app's "load a key" - so it is also the way back
 *        onto a key.
 *   pem  an encrypted PKCS#8 file (src/crypto/pkcs8.js) for openssl, Java
 *        keystores and servers.
 *
 * One passphrase rule for both: the backup passphrase's (at least 25
 * characters, asked twice) - the owner's decision, and the same check
 * (keys.validateBackupPassphrase) refuses before anything is written.
 */

const { validateBackupPassphrase } = require('../device/keys');
const pkcs8 = require('../crypto/pkcs8');

/**
 * @param {import('../vendor/openpgp/openpgp').PrivateKey} privateKey a DECRYPTED openpgp key
 * @param {string} passphrase
 * @param {{confirm?: string|null, openpgp: any}} opts the openpgp module (src/crypto/pgp),
 *   passed in so a caller that never exports PGP never loads it (1.2 MB)
 * @returns {Promise<string>} armored
 */
async function encryptedPgp(privateKey, passphrase, { confirm = null, openpgp } = /** @type {any} */ ({})) {
  const problems = validateBackupPassphrase(passphrase, confirm);
  if (problems.length) throw new Error(problems.join(' '));
  if (!openpgp) throw new Error('encryptedPgp needs { openpgp } (require("node-onlykey-lib/crypto/pgp"))');
  if (!privateKey || typeof privateKey.isDecrypted !== 'function' || !privateKey.isDecrypted()) {
    throw new Error('encryptedPgp takes a decrypted private key - one that is already protected needs no copy made');
  }
  const locked = await openpgp.encryptKey({ privateKey, passphrase: String(passphrase) });
  return locked.armor();
}

module.exports = { encryptedPgp, encryptedPem: pkcs8.encryptedPem };
