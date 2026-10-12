'use strict';

/**
 * A PER-ENTRY KEY, when an entry wants one (PASSWORD-MANAGER-SPEC.md "One key for identity,
 * per-entry keys when wanted"; Brad). The manager key opens the list; an entry may seal its
 * secret fields (password, its history, notes) a second time, under:
 *
 *  - entry-derive: the vault key of the entry's own derive label (`vault:entry:<id>`, the caller
 *    gets it from the key with entryLabel()) - one more touch each time that entry opens;
 *  - entry-passphrase: a key from a passphrase the person gives and nothing stores -
 *    PBKDF2-SHA-256, 600,000 rounds, then HKDF (info okrn-entry-v1) together with the manager key,
 *    so neither the OnlyKey nor the passphrase alone opens it.
 */

const vault = require('../../src/crypto/vault');
const { pbkdf2Sha256 } = require('../../src/crypto/pbkdf2');
const { hkdf } = require('../../src/vendor/exports/@noble/hashes/hkdf.js');
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { utf8ToBytes, toHex, fromHex } = require('../../src/bytes');

const ROUNDS = 600000;
const INFO = utf8ToBytes('okrn-entry-v1');
/* what moves inside: the secrets, an authenticator's setup key included (spec: password, TOTP secret, notes) */
const SECRET_FIELDS = ['password', 'history', 'notes', 'totp'];

/**
 * The derive label of an entry's own key (deviceVault adds `vault:`). `ref` is the entry's own
 * random reference, kept in `inner.ref` - not the record id, so a new entry is sealed before the
 * store has given it one, and the label never changes.
 */
const entryLabel = (ref) => `entry:${ref}`;

/**
 * A passphrase entry's key: PBKDF2 (600k) of the passphrase, combined with the manager key by HKDF.
 * `pbkdf2(password, salt, rounds, dkLen)`: the host's own, when it has one - ok-rn passes OkSSL's
 * (NativeKdf), so the 600k rounds run in OpenSSL, not through WebCrypto or JS. Without it, the
 * lib's pbkdf2Sha256.
 *
 * @param {{passphrase: string, salt: Uint8Array, managerKey: Uint8Array,
 *   onProgress?: ((done: number) => void) | null,
 *   pbkdf2?: ((password: Uint8Array, salt: Uint8Array, rounds: number, dkLen: number) => Promise<Uint8Array>) | null}} o
 */
async function passphraseKey({ passphrase, salt, managerKey, onProgress = null, pbkdf2 = null }) {
  if (typeof passphrase !== 'string' || !passphrase) throw new TypeError('passwords: a passphrase is required');
  if (!(salt instanceof Uint8Array) || salt.length !== 16) throw new TypeError('passwords: the salt is 16 bytes');
  if (!(managerKey instanceof Uint8Array) || managerKey.length !== 32) throw new TypeError('passwords: the manager key is 32 bytes');
  const stretched = pbkdf2
    ? await pbkdf2(utf8ToBytes(passphrase), salt, ROUNDS, 32)
    : await pbkdf2Sha256(utf8ToBytes(passphrase), salt, ROUNDS, 32, { onProgress });
  if (!(stretched instanceof Uint8Array) || stretched.length !== 32) throw new TypeError('passwords: pbkdf2 gave no 32-byte key');
  const ikm = new Uint8Array(64);
  ikm.set(stretched, 0);
  ikm.set(managerKey, 32);
  const key = hkdf(sha256, ikm, salt, INFO, 32);
  stretched.fill(0);
  ikm.fill(0);
  return key;
}

/**
 * The entry with its secret fields moved into `inner`, sealed under `innerKey`.
 * @param {object} entry
 * @param {Uint8Array} innerKey
 * @param {(n: number) => Uint8Array} randomBytes
 * @param {{seal: string, salt?: Uint8Array | null, ref?: string | null}} opts
 */
function sealInner(entry, innerKey, randomBytes, { seal, salt = null, ref = null }) {
  if (!['entry-derive', 'entry-passphrase'].includes(seal)) throw new TypeError('passwords: seal is entry-derive or entry-passphrase');
  if (seal === 'entry-passphrase' && !(salt instanceof Uint8Array)) throw new TypeError('passwords: a passphrase entry keeps its salt');
  if (seal === 'entry-derive' && !/^[0-9a-f]{32}$/.test(String(ref))) throw new TypeError('passwords: a key-sealed entry keeps its ref (16 random bytes, hex)');
  const secrets = {};
  const out = { ...entry };
  for (const f of SECRET_FIELDS) {
    if (out[f] !== undefined) secrets[f] = out[f];
    delete out[f];
  }
  out.inner = {
    seal,
    blob: vault.seal(innerKey, JSON.stringify(secrets), randomBytes),
    ...(salt ? { salt: toHex(salt) } : {}),
    ...(seal === 'entry-derive' ? { ref } : {}),
  };
  return out;
}

/** The entry with its secret fields back, opened with `innerKey`; throws when the key is wrong. */
function openInner(entry, innerKey) {
  if (!entry || !entry.inner) return entry;
  const secrets = JSON.parse(vault.open(innerKey, entry.inner.blob));
  const out = { ...entry, ...secrets };
  delete out.inner;
  return out;
}

/** a new key-sealed entry's ref: 16 random bytes, hex */
const newRef = (randomBytes) => toHex(randomBytes(16));

/** the salt a passphrase entry was sealed with */
const saltOf = (entry) => (entry && entry.inner && entry.inner.salt ? fromHex(entry.inner.salt) : null);

module.exports = { ROUNDS, entryLabel, newRef, passphraseKey, sealInner, openInner, saltOf };
