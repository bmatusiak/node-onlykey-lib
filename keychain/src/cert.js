'use strict';
/**
 * The PGP certificate of a derived gpg identity, made by the OnlyKey (spec
 * session, 2026-10-03: `keychain cert`). Certificate, renewal (a new expiry)
 * and revocation are self-signatures by the derived key - and each one is a
 * PHYSICAL PRESS: a certificate vouches for the key itself; a person decides
 * that, not a budget. An ordinary press is not Edge and owes nothing (R16, spec
 * session 2026-10-06), so Key Chain needs no Edge here (step 3a).
 *
 * Public data only comes back: the armored certificate, its fingerprint, the
 * public keys. A derived key has nothing private to export.
 */
const pgpCert = require('../../src/crypto/pgp-cert');

const ED25519 = 1;
const X25519 = 4;

/* "gpg://Name <email>" or "Name <email>" -> the user ID */
function uidOf(label) {
  const uid = String(label || '').replace(/^gpg:\/\//, '');
  if (!uid.trim()) throw new Error('a gpg label names a user ID: gpg://Name <email>');
  return uid;
}

function signerFor(okcrypto, identity, version, onPress) {
  return (digest) => okcrypto.agent.sign(identity, digest, { keyType: ED25519, version, ...(onPress ? { confirm: onPress } : {}) });
}

/**
 * Build (or renew - the same `created` keeps the fingerprint) the certificate.
 * Two presses: the user ID certification and the subkey binding.
 * @param {object} okcrypto  the app's okcrypto service
 * @param {object} openpgp   the fork (node-onlykey-lib/crypto/pgp)
 * @param {{label: string, version?: number, created?: number, expires?: number, onPress?: Function}} o
 *   expires: seconds after `created` (0 / absent: never)
 * @returns {Promise<{uid: string, armored: string, fingerprint: string, created: number, expires: number, signPublic: Uint8Array}>}
 */
async function makeCertificate(okcrypto, openpgp, { label, version = 2, created, expires = 0, onPress } = {}) {
  const uid = uidOf(label);
  const identity = { gpg: uid };
  const signPublic = await okcrypto.agent.publicKey(identity, { keyType: ED25519, version });
  const ecdhPublic = await okcrypto.agent.publicKey(identity, { keyType: X25519, version });
  const when = Number.isInteger(created) && created > 0 ? created : Math.floor(Date.now() / 1000);
  const cert = await pgpCert.buildCertificate(openpgp, {
    userId: uid, curve: 'ed25519', created: when, signPublic, ecdhPublic,
    ...(expires ? { expires } : {}),
    sign: signerFor(okcrypto, identity, version, onPress),
  });
  return { uid, armored: cert.armored, fingerprint: cert.fingerprint, created: when, expires: expires || 0, signPublic };
}

/**
 * A revocation certificate for the key (one press).
 * @param {{label: string, version?: number, created: number, reason?: number, text?: string, onPress?: Function}} o
 *   created: the certificate's creation time - it is in the fingerprint being revoked
 */
async function makeRevocation(okcrypto, openpgp, { label, version = 2, created, reason = 0, text = '', onPress } = {}) {
  const uid = uidOf(label);
  if (!Number.isInteger(created) || created <= 0) throw new Error('a revocation needs the certificate\'s creation time (make the certificate first)');
  const identity = { gpg: uid };
  const signPublic = await okcrypto.agent.publicKey(identity, { keyType: ED25519, version });
  const r = await pgpCert.buildRevocation(openpgp, {
    signPublic, curve: 'ed25519', created, reason, text, sign: signerFor(okcrypto, identity, version, onPress),
  });
  return { uid, armored: r.armored, fingerprint: r.fingerprint };
}

module.exports = { makeCertificate, makeRevocation, uidOf };
