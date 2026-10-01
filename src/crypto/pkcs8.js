'use strict';

/**
 * An ENCRYPTED PEM private key (PKCS#8), for a Key Chain key the owner wants
 * to keep a copy of, or to use somewhere that is not an OnlyKey.
 *
 * ## Why this exists (owner, 2026-10-01)
 *
 * Key Chain makes a key on the OnlyKey where the firmware can - and then no
 * copy exists anywhere, which is the point. A key made on the HOST (RSA, which
 * the device cannot generate; the composite post-quantum key; any key the
 * owner wants outside the OnlyKey) exists in memory for a moment, and the
 * owner asked for an option to keep it: encrypted, in both the PGP format and
 * this one - the format openssl, Java keystores and most servers read.
 *
 * ## What is written
 *
 *   -----BEGIN ENCRYPTED PRIVATE KEY-----   EncryptedPrivateKeyInfo (RFC 5958)
 *     PBES2 (RFC 8018): PBKDF2-HMAC-SHA256, 16-byte salt, AES-256-CBC
 *     around a PrivateKeyInfo:
 *       RSA        rsaEncryption + RSAPrivateKey (RFC 8017 A.1.2)
 *       Ed25519    id-Ed25519 (RFC 8410), the 32-byte seed
 *       X25519     id-X25519 (RFC 8410), the 32-byte scalar
 *       P-256      id-ecPublicKey + prime256v1, ECPrivateKey (RFC 5915)
 *       secp256k1  id-ecPublicKey + secp256k1,  ECPrivateKey
 *
 * Post-quantum keys are not written here: their PKCS#8 encodings are not
 * settled across tools, so they leave as an armored PGP copy only.
 *
 * The passphrase follows the backup passphrase's rules (owner's decision):
 * at least 25 characters, checked by keys.validateBackupPassphrase, hashed as
 * UTF-8 - what openssl does with the bytes it is given.
 *
 * Only src/ things: @noble for PBKDF2/AES/curves, BigInt for RSA's CRT
 * values, bytes.js for base64 - no Node built-ins, so this runs under Hermes.
 */

const { pbkdf2Sha256 } = require('./pbkdf2');
const { cbc } = require('../vendor/exports/@noble/ciphers/aes.js');
const { randomBytes } = require('../vendor/exports/@noble/ciphers/utils.js');
const { p256 } = require('../vendor/exports/@noble/curves/nist.js');
const { secp256k1 } = require('../vendor/exports/@noble/curves/secp256k1.js');
const { concat, toBase64, utf8ToBytes } = require('../bytes');
const { validateBackupPassphrase } = require('../device/keys');
const rsa = require('./rsa');

/* PBKDF2 rounds: OWASP's 2023 figure for PBKDF2-HMAC-SHA256. */
const DEFAULT_ITERATIONS = 600000;

/* ------------------------------------------------------------ DER */

function derLength(n) {
  if (n < 0x80) return Uint8Array.of(n);
  const out = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) out.unshift(v & 0xff);
  return Uint8Array.of(0x80 | out.length, ...out);
}
const tlv = (tag, content) => concat([Uint8Array.of(tag), derLength(content.length), content]);
const sequence = (...items) => tlv(0x30, concat(items));
const octets = (bytes) => tlv(0x04, bytes);
const NULL = Uint8Array.of(0x05, 0x00);

/** A non-negative INTEGER from big-endian bytes, a number or a BigInt. */
function integer(value) {
  let bytes;
  if (typeof value === 'bigint' || typeof value === 'number') {
    let v = BigInt(value);
    const out = [];
    do { out.unshift(Number(v & 0xffn)); v >>= 8n; } while (v > 0n);
    bytes = Uint8Array.from(out);
  } else {
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) start++;
    bytes = value.subarray(start);
  }
  /* A set high bit would read as negative: DER says lead with a zero. */
  if (bytes[0] & 0x80) bytes = concat([Uint8Array.of(0), bytes]);
  return tlv(0x02, bytes);
}

function oid(dotted) {
  const parts = dotted.split('.').map(Number);
  const out = [40 * parts[0] + parts[1]];
  for (const part of parts.slice(2)) {
    const groups = [];
    let v = part;
    do { groups.unshift(v & 0x7f); v = Math.floor(v / 128); } while (v > 0);
    for (let i = 0; i < groups.length - 1; i++) groups[i] |= 0x80;
    out.push(...groups);
  }
  return tlv(0x06, Uint8Array.from(out));
}

const OID = {
  rsaEncryption: '1.2.840.113549.1.1.1',
  ecPublicKey: '1.2.840.10045.2.1',
  prime256v1: '1.2.840.10045.3.1.7',
  secp256k1: '1.3.132.0.10',
  ed25519: '1.3.101.112',
  x25519: '1.3.101.110',
  pbes2: '1.2.840.113549.1.5.13',
  pbkdf2: '1.2.840.113549.1.5.12',
  hmacWithSHA256: '1.2.840.113549.2.9',
  aes256cbc: '2.16.840.1.101.3.4.1.42',
};

/* ------------------------------------------------------------ PrivateKeyInfo */

/**
 * RSAPrivateKey (RFC 8017 A.1.2) from the primes alone - which is all an
 * OnlyKey keeps (p || q) and all a generator must hand over; rsa.fromPrimes
 * works out the rest.
 */
function rsaPrivateKey({ p, q, e = 65537 }) {
  const k = rsa.fromPrimes({ p, q, e });
  return sequence(
    integer(0), integer(k.n), integer(k.e), integer(k.d), integer(k.p), integer(k.q),
    integer(k.dp), integer(k.dq), integer(k.qi),
  );
}

/**
 * The unencrypted PrivateKeyInfo for one key. Never written out by itself -
 * encryptedPem() wraps it - but exported for tests and for a caller that has
 * its own envelope.
 *
 * @param {{type: 'rsa', p: Uint8Array, q: Uint8Array, e?: number}
 *   | {type: 'ed25519'|'x25519'|'p256'|'secp256k1', secret: Uint8Array}} key
 * @returns {Uint8Array}
 */
function privateKeyInfo(key) {
  switch (key.type) {
    case 'rsa':
      return sequence(integer(0), sequence(oid(OID.rsaEncryption), NULL), octets(rsaPrivateKey(key)));
    case 'ed25519':
    case 'x25519':
      if (!key.secret || key.secret.length !== 32) throw new Error(`a ${key.type} key is 32 bytes`);
      return sequence(integer(0), sequence(oid(OID[key.type])), octets(octets(key.secret)));
    case 'p256':
    case 'secp256k1': {
      if (!key.secret || key.secret.length !== 32) throw new Error(`a ${key.type} key is 32 bytes`);
      const curve = key.type === 'p256' ? p256 : secp256k1;
      const pub = curve.getPublicKey(key.secret, false);
      const ecPrivateKey = sequence(
        integer(1), octets(key.secret),
        tlv(0xa1, tlv(0x03, concat([Uint8Array.of(0), pub]))),
      );
      const named = key.type === 'p256' ? OID.prime256v1 : OID.secp256k1;
      return sequence(integer(0), sequence(oid(OID.ecPublicKey), oid(named)), octets(ecPrivateKey));
    }
    default:
      throw new Error(
        `no PKCS#8 form for "${key.type}" here - post-quantum keys leave as an armored PGP copy`,
      );
  }
}

/* ------------------------------------------------------------ the envelope */

function pem(label, der) {
  const b64 = toBase64(der);
  const lines = [];
  for (let at = 0; at < b64.length; at += 64) lines.push(b64.slice(at, at + 64));
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

/**
 * The encrypted PEM. The passphrase is asked for twice by the caller and
 * passed as `confirm`, so the same check refuses a mismatch here too.
 *
 * @param {Parameters<typeof privateKeyInfo>[0]} key
 * @param {string} passphrase at least 25 characters (the backup passphrase's rule)
 * @param {{confirm?: string, iterations?: number, salt?: Uint8Array, iv?: Uint8Array,
 *   onProgress?: ((fraction: number) => void) | null}} [opts]
 *   salt/iv are for frozen test vectors only; onProgress follows the passphrase
 *   stretching (0..1) - the slow part where no native PBKDF2 is lent
 * @returns {Promise<string>}
 */
async function encryptedPem(key, passphrase, { confirm = null, iterations = DEFAULT_ITERATIONS, salt, iv, onProgress = null } = {}) {
  const problems = validateBackupPassphrase(passphrase, confirm);
  if (problems.length) throw new Error(problems.join(' '));
  const info = privateKeyInfo(key);
  const s = salt || randomBytes(16);
  const v = iv || randomBytes(16);
  const kek = await pbkdf2Sha256(utf8ToBytes(String(passphrase)), s, iterations, 32, { onProgress });
  const encrypted = cbc(kek, v).encrypt(info);
  kek.fill(0);
  info.fill(0);
  const der = sequence(
    sequence(
      oid(OID.pbes2),
      sequence(
        sequence(oid(OID.pbkdf2), sequence(octets(s), integer(iterations), sequence(oid(OID.hmacWithSHA256), NULL))),
        sequence(oid(OID.aes256cbc), octets(v)),
      ),
    ),
    octets(encrypted),
  );
  return pem('ENCRYPTED PRIVATE KEY', der);
}

module.exports = { DEFAULT_ITERATIONS, privateKeyInfo, encryptedPem };
