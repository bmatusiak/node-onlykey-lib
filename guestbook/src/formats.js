'use strict';

/**
 * GUEST BOOK KEY FORMATS (onlykey-edge/features/GUEST-BOOK-SPEC.md, "Supported key formats").
 *
 * Guest Book holds other people's PUBLIC keys in every form OnlyKey uses. Each detector takes the
 * text a person pasted or scanned and returns what it found, with the fingerprint that format is
 * known by - the pin the refresh rule compares:
 *
 *   openpgp  armored PUBLIC KEY BLOCK      the primary key's fingerprint (upper-case hex)
 *   age      age1... / age1onlykey...      SHA-256 of the recipient string, first 16 hex
 *   ssh      one authorized_keys line      SHA256:<base64>, as `ssh-keygen -l` prints it
 *   raw-*    hex or base64 bytes + a curve SHA-256 of the bytes, first 16 hex
 *
 * PUBLIC ONLY (Brad, 2026-10-12: "guest book is only for public output, it should not contain or
 * show any private keys"): every way in runs refusePublicOnly first - private key text, or a PGP
 * block that turns out to hold secret key material, is refused with a reason and nothing is kept.
 *
 * A raw key carries no type tag (the firmware's reply has none), so its curve is chosen by the
 * person; the length only says which curves it could be, never which one it is.
 */

const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { utf8ToBytes, bytesToUtf8, toHex, fromHex, toBase64, fromBase64 } = require('../../src/bytes');
const { isPrivateText } = require('../../src/crypto/public-only');
const age = require('../../src/crypto/age_pqc');

const FORMATS = ['openpgp', 'age', 'ssh', 'raw-p256', 'raw-secp256k1', 'raw-ed25519', 'raw-x25519', 'raw-mlkem768', 'raw-xwing'];

/* raw keys: the byte lengths each curve's public key comes in */
const RAW_LENGTHS = {
  'raw-ed25519': [32],
  'raw-x25519': [32],
  'raw-p256': [33, 64, 65],
  'raw-secp256k1': [33, 64, 65],
  'raw-mlkem768': [age.MLKEM_PK],
  'raw-xwing': [age.XWING_PK],
};

const SSH_TYPES = ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-rsa'];
/* a pasted body is never more than this; a hostile URL cannot stall the PGP parser with it */
const MAX_TEXT = 1024 * 1024;

class PrivateKeyError extends Error {
  constructor() {
    super('this is a private key - Guest Book holds only public keys. Nothing was saved.');
    this.name = 'PrivateKeyError';
  }
}

/** Throws PrivateKeyError when the text carries private key material. */
function refusePublicOnly(text) {
  if (isPrivateText(String(text || ''))) throw new PrivateKeyError();
}

const shortHash = (bytes) => toHex(sha256(bytes)).slice(0, 16);

/* ---- OpenSSH: one authorized_keys line -------------------------------------------------- */

/** Reads the SSH wire string at `at` -> {value, next}. */
function sshString(blob, at) {
  if (at + 4 > blob.length) throw new Error('the SSH key is cut short');
  const n = ((blob[at] << 24) | (blob[at + 1] << 16) | (blob[at + 2] << 8) | blob[at + 3]) >>> 0;
  if (at + 4 + n > blob.length) throw new Error('the SSH key is cut short');
  return { value: blob.subarray(at + 4, at + 4 + n), next: at + 4 + n };
}

/**
 * One authorized_keys line ([options] type base64 [comment]) -> the key, or null when the line is
 * not an SSH public key. The blob's own type string must match the line's (a mislabelled blob is
 * refused, not trusted).
 */
function readSshLine(line) {
  const words = String(line).trim().split(/\s+/);
  const at = words.findIndex((w) => SSH_TYPES.includes(w));
  if (at < 0 || !words[at + 1]) return null;
  const type = words[at];
  let blob;
  try {
    blob = fromBase64(words[at + 1]);
  } catch {
    throw new Error(`the ${type} key's base64 does not decode`);
  }
  const inner = bytesToUtf8(sshString(blob, 0).value);
  if (inner !== type) throw new Error(`the line says ${type} but the key inside is ${inner || 'unreadable'}`);
  const comment = words.slice(at + 2).join(' ');
  const text = `${type} ${words[at + 1]}${comment ? ` ${comment}` : ''}`;
  return {
    format: 'ssh',
    text,
    fingerprint: `SHA256:${toBase64(sha256(blob)).replace(/=+$/, '')}`,
    label: comment || type,
    info: { type, comment },
  };
}

/* ---- age recipients ---------------------------------------------------------------------- */

/** age1... (X25519) or age1onlykey... (X-Wing, 1216 bytes) -> the key, or null. */
function readAgeRecipient(word) {
  const text = String(word).trim();
  if (!/^age1/.test(text)) return null;
  if (/^age1onlykey1/i.test(text)) {
    const data = age.decodeRecipient(text);
    if (data.length !== age.XWING_PK) throw new Error(`an age1onlykey recipient is ${age.XWING_PK} bytes, this one is ${data.length}`);
    return { format: 'age', text: text.toLowerCase(), fingerprint: shortHash(utf8ToBytes(text.toLowerCase())), label: 'age (X-Wing)', info: { kind: 'xwing' } };
  }
  age.decodeX25519Recipient(text);
  return { format: 'age', text, fingerprint: shortHash(utf8ToBytes(text)), label: 'age (X25519)', info: { kind: 'x25519' } };
}

/* ---- OpenPGP ------------------------------------------------------------------------------ */

const PGP_BLOCK = /-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----/g;

/** One armored public block -> the key. openpgp is passed in (the vendored fork, lazy on Hermes). */
async function readPgpBlock(openpgp, armored) {
  if (!openpgp) throw new Error('reading a PGP key needs the openpgp library (node-onlykey-lib/crypto/pgp)');
  let key;
  try {
    key = await openpgp.readKey({ armoredKey: armored });
  } catch (e) {
    throw new Error(`not a PGP public key: ${e.message || e}`);
  }
  /* an armored PUBLIC label on a block that holds secret key packets is still a private key */
  if (key.isPrivate()) throw new PrivateKeyError();
  const users = key.getUserIDs() || [];
  const created = key.keyPacket?.created instanceof Date ? key.keyPacket.created.toISOString() : '';
  let expires = '';
  try {
    const t = await key.getExpirationTime();
    if (t instanceof Date) expires = t.toISOString();
  } catch {
    /* no valid self-signature to read an expiry from: shown as unknown */
  }
  let revoked = false;
  try {
    revoked = await key.isRevoked();
  } catch {
    revoked = false;
  }
  const info = key.getAlgorithmInfo ? key.getAlgorithmInfo() : {};
  return {
    format: 'openpgp',
    text: key.armor(),
    fingerprint: key.getFingerprint().toUpperCase(),
    label: users[0] || 'PGP key',
    info: { users, algorithm: info.algorithm || '', curve: info.curve || '', created, expires, revoked },
  };
}

/* ---- raw keys ----------------------------------------------------------------------------- */

/** Hex or base64 text -> bytes, or null when it is neither. */
function rawBytes(text) {
  const t = String(text).trim().replace(/\s+/g, '');
  if (/^(0x)?[0-9a-fA-F]+$/.test(t) && t.replace(/^0x/, '').length % 2 === 0) return fromHex(t.replace(/^0x/, ''));
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(t)) {
    try {
      return fromBase64(t);
    } catch {
      return null;
    }
  }
  return null;
}

/** The raw formats whose public keys come in this length (the person picks one). */
function rawCandidates(length) {
  return Object.keys(RAW_LENGTHS).filter((f) => RAW_LENGTHS[f].includes(length));
}

/** A raw key with its curve chosen -> the key. */
function readRaw(text, format) {
  if (!RAW_LENGTHS[format]) throw new Error(`not a raw key format: ${format}`);
  const bytes = rawBytes(text);
  if (!bytes) throw new Error('a raw key is hex or base64');
  if (!RAW_LENGTHS[format].includes(bytes.length)) {
    throw new Error(`a ${format.slice(4)} public key is ${RAW_LENGTHS[format].join(' or ')} bytes, this is ${bytes.length}`);
  }
  return { format, text: toHex(bytes), fingerprint: shortHash(bytes), label: format.slice(4), info: { bytes: bytes.length } };
}

/* ---- everything in a paste --------------------------------------------------------------- */

/**
 * Every public key in the text (a paste, a QR, a fetched page), each format's detector in turn.
 * Private material anywhere in it refuses the whole text. A bare run of hex/base64 that could only
 * be a raw key comes back as {needsCurve: [formats]} - the person picks the curve, then readRaw.
 * @param {string} text
 * @param {{openpgp?: any}} [opts]
 * @returns {Promise<{found: object[], needsCurve: string[] | null, errors: string[]}>}
 */
async function detectAll(text, { openpgp } = {}) {
  const body = String(text || '');
  if (body.length > MAX_TEXT) throw new Error('that is more than 1 MB - not a key');
  refusePublicOnly(body);
  const found = [];
  const errors = [];
  for (const block of body.match(PGP_BLOCK) || []) {
    try {
      found.push(await readPgpBlock(openpgp, block));
    } catch (e) {
      if (e instanceof PrivateKeyError) throw e;
      errors.push(e.message);
    }
  }
  const rest = body.replace(PGP_BLOCK, '\n');
  for (const line of rest.split(/\r?\n/)) {
    try {
      const ssh = readSshLine(line);
      if (ssh) {
        found.push(ssh);
        continue;
      }
      for (const word of line.trim().split(/\s+/)) {
        const a = readAgeRecipient(word);
        if (a) found.push(a);
      }
    } catch (e) {
      errors.push(e.message);
    }
  }
  let needsCurve = null;
  if (!found.length && !errors.length) {
    const bytes = rawBytes(body);
    if (bytes) {
      const candidates = rawCandidates(bytes.length);
      if (candidates.length) needsCurve = candidates;
      else errors.push(`${bytes.length} bytes is not the length of any public key OnlyKey uses`);
    }
  }
  /* one key, once: the same fingerprint pasted twice is one find */
  const seen = new Set();
  const unique = found.filter((k) => (seen.has(`${k.format}:${k.fingerprint}`) ? false : seen.add(`${k.format}:${k.fingerprint}`)));
  return { found: unique, needsCurve, errors };
}

module.exports = {
  FORMATS,
  RAW_LENGTHS,
  MAX_TEXT,
  PrivateKeyError,
  refusePublicOnly,
  readSshLine,
  readAgeRecipient,
  readPgpBlock,
  rawCandidates,
  readRaw,
  detectAll,
};
