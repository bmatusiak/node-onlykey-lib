'use strict';
/**
 * The PGP certificate of a derived gpg identity, made by the OnlyKey (spec
 * session, 2026-10-03: `keychain cert`). Certificate, renewal (a new expiry)
 * and revocation are self-signatures by the derived key - and each one is a
 * PHYSICAL PRESS, never paid by an Edge budget, even when a live budget covers
 * that label: these calls never ARM (src/edge/client.js is the only thing that
 * does), so the key does what it does for any unarmed sign and waits for the
 * button. A certificate vouches for the key itself; a person decides that, not
 * a budget.
 *
 * Public data only comes back: the armored certificate, its fingerprint, the
 * public keys. A derived key has nothing private to export.
 *
 * Under R16 such a press with a key a live budget covers owes a ticket (the
 * key's rule, not this file's) - the agent's `okedge status` names it.
 */
const pgpCert = require('../crypto/pgp-cert');

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

/**
 * Before a certificate (spec session, 2026-10-03, no firmware exemption):
 * refuse while the key owes anything - R18 would hold every budget anyway, and
 * our own presses would join an unexplained list. -> the seq to ticket after.
 * @param {object|null} edge the key's Edge plugin, or null (no Edge: nothing to do)
 * @returns {Promise<number|null>}
 */
async function guardOwed(edge) {
  if (!edge) return null;
  const h = await edge.head();
  if (h.owed || h.overflow) {
    throw Object.assign(new Error(`the key owes ${h.owed} ticket(s)${h.overflow ? ' and more' : ''} - ticket or waive them before a certificate (okedge status names them)`), { code: 'EEDGE_KEY_OWED' });
  }
  return h.seq === null ? -1 : h.seq;
}

/**
 * After the presses: under R16 a press with a key a live budget covers owes a
 * ticket. File ours at once - code OK, "cert self-signature <fingerprint>".
 * @returns {Promise<number[]>} the seqs ticketed
 */
async function ticketOwnPresses(edge, startSeq, fingerprint) {
  if (!edge || startSeq === null) return [];
  const { tickets, codes } = require('../edge');
  const h = await edge.head();
  if (!h.owed || h.seq === null || h.oldest === null) return [];
  const rows = await edge.pickup(h.oldest, h.seq - h.oldest + 1);
  const done = [];
  for (const seq of tickets.keyDebts(rows).owed.filter((q) => q > startSeq)) {
    await edge.ticket(seq, codes.ticketCode('OK'), tickets.messageHash(`cert self-signature ${fingerprint}`));
    done.push(seq);
  }
  return done;
}

module.exports = { makeCertificate, makeRevocation, uidOf, guardOwed, ticketOwnPresses };
