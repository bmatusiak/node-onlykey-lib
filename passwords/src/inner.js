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
const SECRET_FIELDS = ['password', 'history', 'notes'];

/** the derive label of an entry's own key (deviceVault adds `vault:`) */
const entryLabel = (id) => `entry:${id}`;

/** A passphrase entry's key: PBKDF2 (600k) of the passphrase, combined with the manager key by HKDF. */
async function passphraseKey({ passphrase, salt, managerKey, onProgress = null }) {
  if (typeof passphrase !== 'string' || !passphrase) throw new TypeError('passwords: a passphrase is required');
  if (!(salt instanceof Uint8Array) || salt.length !== 16) throw new TypeError('passwords: the salt is 16 bytes');
  if (!(managerKey instanceof Uint8Array) || managerKey.length !== 32) throw new TypeError('passwords: the manager key is 32 bytes');
  const stretched = await pbkdf2Sha256(utf8ToBytes(passphrase), salt, ROUNDS, 32, { onProgress });
  const ikm = new Uint8Array(64);
  ikm.set(stretched, 0);
  ikm.set(managerKey, 32);
  const key = hkdf(sha256, ikm, salt, INFO, 32);
  stretched.fill(0);
  ikm.fill(0);
  return key;
}

/** The entry with its secret fields moved into `inner`, sealed under `innerKey`. */
function sealInner(entry, innerKey, randomBytes, { seal, salt = null }) {
  if (!['entry-derive', 'entry-passphrase'].includes(seal)) throw new TypeError('passwords: seal is entry-derive or entry-passphrase');
  if (seal === 'entry-passphrase' && !(salt instanceof Uint8Array)) throw new TypeError('passwords: a passphrase entry keeps its salt');
  const secrets = {};
  const out = { ...entry };
  for (const f of SECRET_FIELDS) {
    if (out[f] !== undefined) secrets[f] = out[f];
    delete out[f];
  }
  out.inner = { seal, blob: vault.seal(innerKey, JSON.stringify(secrets), randomBytes), ...(salt ? { salt: toHex(salt) } : {}) };
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

/** the salt a passphrase entry was sealed with */
const saltOf = (entry) => (entry && entry.inner && entry.inner.salt ? fromHex(entry.inner.salt) : null);

module.exports = { ROUNDS, entryLabel, passphraseKey, sealInner, openInner, saltOf };
