'use strict';

/*
 * A SELF-SIGNED X.509 CERTIFICATE FOR A KEY THE ONLYKEY HOLDS (RFC 5280; Brad, 2026-11-04: the release APK signed by
 * red-key's "RSA3 Code Signing" slot). Android's APK signature schemes carry the signer's X.509 certificate and check
 * only that an app's certificate never changes - so the certificate is made once, from the slot's public key read off the
 * key (no press) and signed by the slot itself (one press), and kept beside the source.
 *
 * Only what that needs: an RSA subject public key (the modulus the key answers OKGETPUBKEY with, and its exponent -
 * 65537 on every OnlyKey RSA key), a v3 certificate with no extensions, issuer = subject, the signature
 * sha256WithRSAEncryption or - for a key over 3072 bits, as apksigner signs with one - sha512WithRSAEncryption. The sign
 * is the caller's: it is handed the DIGEST of the to-be-signed bytes, which is what the key's PKCS#1 v1.5 RSA sign takes
 * (it picks the hash by the digest's length - okcrypto.sign(slot, digest)).
 */
const { sha256, sha512 } = require('../vendor/exports/@noble/hashes/sha2.js');
const { randomBytes } = require('../vendor/exports/@noble/ciphers/utils.js');
const { concat, utf8ToBytes, toBase64 } = require('../bytes');
const { tlv, sequence, NULL, integer, oid } = require('./der');

const OID = {
  rsaEncryption: '1.2.840.113549.1.1.1',
  sha256WithRSAEncryption: '1.2.840.113549.1.1.11',
  sha512WithRSAEncryption: '1.2.840.113549.1.1.13',
  countryName: '2.5.4.6',
  organizationName: '2.5.4.10',
  organizationalUnitName: '2.5.4.11',
  commonName: '2.5.4.3',
};
const HASHES = {
  sha256: { digest: sha256, algorithm: OID.sha256WithRSAEncryption },
  sha512: { digest: sha512, algorithm: OID.sha512WithRSAEncryption },
};

const bitString = (bytes) => tlv(0x03, concat([Uint8Array.of(0), bytes]));
/* the modulus as the key gives it, without a leading zero: its length is the signature's */
const unsigned = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; return b.subarray(i); };

/*
 * A Name: C (PrintableString, two letters), O, OU, CN (UTF8String), one attribute each, in that order. At least a CN.
 * @param {{CN: string, O?: string, OU?: string, C?: string}} n
 */
function name(n) {
  if (!n || !String(n.CN || '').trim()) throw new TypeError('x509: a certificate names its subject (CN at least)');
  const rdn = (type, value) => tlv(0x31, sequence(oid(type), value));
  const parts = [];
  if (n.C !== undefined) {
    if (!/^[A-Z]{2}$/.test(String(n.C))) throw new TypeError('x509: C is a two-letter country code');
    parts.push(rdn(OID.countryName, tlv(0x13, utf8ToBytes(n.C))));
  }
  if (n.O !== undefined) parts.push(rdn(OID.organizationName, tlv(0x0c, utf8ToBytes(String(n.O)))));
  if (n.OU !== undefined) parts.push(rdn(OID.organizationalUnitName, tlv(0x0c, utf8ToBytes(String(n.OU)))));
  parts.push(rdn(OID.commonName, tlv(0x0c, utf8ToBytes(String(n.CN)))));
  return sequence(...parts);
}

/* RFC 5280 4.1.2.5: UTCTime through 2049, GeneralizedTime from 2050; seconds, Z */
function time(d) {
  const p = (n) => String(n).padStart(2, '0');
  const y = d.getUTCFullYear();
  const rest = `${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return y < 2050 ? tlv(0x17, utf8ToBytes(`${p(y % 100)}${rest}`)) : tlv(0x18, utf8ToBytes(`${y}${rest}`));
}

/** SubjectPublicKeyInfo for an RSA key: {rsaEncryption, NULL} and RSAPublicKey {n, e} */
function rsaPublicKeyInfo(modulus, exponent = 65537) {
  return sequence(sequence(oid(OID.rsaEncryption), NULL), bitString(sequence(integer(unsigned(modulus)), integer(exponent))));
}

/**
 * The certificate, signed: DER bytes.
 * @param {object} o
 * @param {Uint8Array} o.modulus      the RSA key's modulus (big-endian), as the key answers it
 * @param {number} [o.exponent]       65537
 * @param {{CN: string, O?: string, OU?: string, C?: string}} o.subject  also its issuer (self-signed)
 * @param {Date} [o.notBefore]        now
 * @param {number} [o.days]           how long it is valid: 30 years (Google Play asks an app's key to outlast 2033)
 * @param {'sha256'|'sha512'} [o.hash] sha512 for a key over 3072 bits, else sha256
 * @param {Uint8Array} [o.serial]     16 random bytes
 * @param {(digest: Uint8Array) => Promise<Uint8Array>|Uint8Array} o.sign  the key's PKCS#1 v1.5 signature over this digest
 * @returns {Promise<Uint8Array>}
 */
async function selfSigned({ modulus, exponent = 65537, subject, notBefore = new Date(), days = 365 * 30, hash, serial, sign }) {
  const n = unsigned(Uint8Array.from(modulus || []));
  if (n.length < 128 || n.length > 512) throw new TypeError(`x509: an RSA modulus of 1024 to 4096 bits, not ${n.length * 8}`);
  const h = HASHES[hash || (n.length > 384 ? 'sha512' : 'sha256')];
  if (!h) throw new TypeError(`x509: hash sha256 or sha512, not ${JSON.stringify(hash)}`);
  if (!Number.isInteger(days) || days < 1) throw new TypeError('x509: days is a whole number, 1 or more');
  /* a positive serial (its top bit clear), never zero */
  const sn = Uint8Array.from(serial || randomBytes(16));
  sn[0] = (sn[0] & 0x7f) | 0x01;
  const algorithm = sequence(oid(h.algorithm), NULL);
  const subjectName = name(subject);
  const notAfter = new Date(notBefore.getTime() + days * 86400000);
  const tbs = sequence(
    tlv(0xa0, integer(2)), /* v3 */
    integer(sn),
    algorithm,
    subjectName,
    sequence(time(notBefore), time(notAfter)),
    subjectName,
    rsaPublicKeyInfo(n, exponent),
  );
  const signature = Uint8Array.from(await sign(h.digest(tbs)));
  if (signature.length !== n.length) throw new Error(`x509: the key's signature is ${signature.length} bytes, not ${n.length} (its modulus)`);
  return sequence(tbs, algorithm, bitString(signature));
}

/** DER -> PEM ("CERTIFICATE"), 64 characters a line */
function toPem(der) {
  const b64 = toBase64(der);
  return `-----BEGIN CERTIFICATE-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
}

module.exports = { selfSigned, toPem, rsaPublicKeyInfo, name, OID };
