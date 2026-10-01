'use strict';

/**
 * Every shareable form of a public key, in one place - so a slot key, a
 * host-made key and a DERIVED key all offer the same things to copy, and no
 * screen builds its own.
 *
 *   hex, base64   always
 *   ssh           Ed25519, P-256, RSA (an authorized_keys line)
 *   age           X25519 (classic "age1..."), X-Wing ("age1onlykey..." - the
 *                 post-quantum recipient the OnlyKey apps use)
 *
 * A PGP certificate is not here: it needs self-signatures, which only the key
 * holder can make (the device, through crypto.pgpCert), so it is built by the
 * caller that can ask for them and kept in the Key Chain list.
 */

const { toHex, toBase64 } = require('../bytes');
const ssh = require('../crypto/ssh-pub');
const pqc = require('../crypto/age_pqc');

/**
 * @param {{type: string, publicKey: Uint8Array, comment?: string}} key
 *   type: ed25519 | x25519 | p256 | secp256k1 | rsa | mlkem768 | xwing
 * @returns {{hex: string, base64: string, ssh?: string, age?: string}}
 */
function forKey({ type, publicKey, comment }) {
  const out = { hex: toHex(publicKey), base64: toBase64(publicKey) };
  if (type === 'ed25519') out.ssh = ssh.publicKeyLine('ed25519', publicKey, comment);
  else if (type === 'p256') out.ssh = ssh.publicKeyLine('nist256p1', publicKey, comment);
  else if (type === 'rsa') out.ssh = ssh.rsaPublicKeyLine(publicKey, comment);
  else if (type === 'x25519') out.age = pqc.encodeX25519Recipient(publicKey);
  else if (type === 'xwing') out.age = pqc.encodeRecipient(publicKey);
  return out;
}

module.exports = { forKey };
