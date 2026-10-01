/*
 * cli/gpg-key.js - the OpenPGP key an OnlyKey-derived GPG identity is, and
 * the keygrips gpg knows its parts by.
 *
 * WHAT IT REPLACES. lib-agent's gpg/protocol.py + encode.py: `onlykey-gpg
 * init` asks the device for two public keys derived from "gpg://<user id>" -
 * a signing key and an ECDH key - and wraps them in an OpenPGP certificate
 * whose self-signatures the DEVICE makes. gpg imports that certificate and
 * from then on believes it has a key; the private halves never exist
 * anywhere but inside the OnlyKey, and cli/gpg-agent.js does their work.
 *
 * THE BUILDER IS src/crypto/pgp-cert.js. It lived here until Key Chain needed
 * the same certificate from a phone (Hermes: no Node crypto, no Buffer); it
 * moved there byte for byte, and this file is the CLI's face of it - the
 * vendored openpgp fork bound in, and Buffer back on the byte helpers the
 * agent and its tests read with Buffer methods. No encoding is decided here
 * any more: the WHY of every byte is in src/crypto/pgp-cert.js.
 *
 * WHAT STAYS HERE: reading a keyring back (readDerivedKeys), which only the
 * desktop agent does - it starts from a pubkey.asc on disk.
 */
'use strict';

const openpgp = require('../src/vendor/openpgp/openpgp.js');
const pgpCert = require('../src/crypto/pgp-cert.js');

const { ALGO, OID, CURVES, keygrip, verifyDigest, kindOf } = pgpCert;

const buf = (u8) => Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength);

/** pgpCert.openpgpPoint, as a Buffer. */
const openpgpPoint = (raw) => buf(pgpCert.openpgpPoint(raw));

/** pgpCert.keyPacketBody, as a Buffer. */
const keyPacketBody = (kind, raw, created) => buf(pgpCert.keyPacketBody(kind, raw, created));

/**
 * pgpCert.buildCertificate with the vendored fork - see it for the options
 * (userId or userIds, curve, created, expires, signPublic, ecdhPublic, sign).
 */
const buildCertificate = (opts) => pgpCert.buildCertificate(openpgp, opts);

/* ------------------------------------------------------------ reading them back */

/**
 * Every derived key in an armored (or binary) keyring export, as the agent
 * needs it: which device key it is, and its keygrip. Anything else in the
 * keyring (an RSA key, a key on another curve) is not a derived key and is
 * skipped (pgpCert.kindOf).
 *
 * WHICH USER ID. lib-agent's agent.py get_identity(): "We assume the first
 * user ID is used to generate Agent-based GPG keys." The derivation is keyed
 * by that string, so it is the one the device is asked about.
 *
 * @param {string|Uint8Array} data
 * @returns {Promise<Array<{userId: string, curve: string, role: 'sign'|'ecdh',
 *   keyType: number, raw: Buffer, keygrip: string, fingerprint: string, created: number}>>}
 */
async function readDerivedKeys(data) {
  const keys = typeof data === 'string'
    ? await openpgp.readKeys({ armoredKeys: data })
    : await openpgp.readKeys({ binaryKeys: Uint8Array.from(data) });
  const out = [];
  for (const key of keys) {
    const user = key.users.find((u) => u.userID);
    if (!user) continue;
    const userId = user.userID.userID;
    for (const packet of [key.keyPacket, ...key.subkeys.map((s) => s.keyPacket)]) {
      const { oid, Q } = packet.publicParams || {};
      if (!oid || !Q) continue;
      const kind = kindOf(packet.algorithm, Buffer.from(oid.write()).subarray(1));
      if (!kind) continue;
      const raw = Buffer.from(Q).subarray(1);
      out.push({
        userId,
        curve: kind.curve,
        role: kind.role,
        keyType: kind.keyType,
        raw,
        keygrip: keygrip(kind.grip, raw),
        fingerprint: packet.getFingerprint().toUpperCase(),
        created: Math.floor(packet.created.getTime() / 1000),
      });
    }
  }
  return out;
}

module.exports = {
  ALGO,
  OID,
  CURVES,
  openpgpPoint,
  keyPacketBody,
  keygrip,
  verifyDigest,
  buildCertificate,
  readDerivedKeys,
};
