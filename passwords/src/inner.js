'use strict';

/**
 * EVERY SECRET COSTS A PRESS (PROPOSAL-derived-keys.md, tier 2; Brad, 2026-10-27: "the secret in
 * password do now need to require a press"; "no passphrase as an option to secure a password,
 * press decrypt only"). An entry's secret fields - its password, the earlier ones, its notes, an
 * authenticator's setup key - are never stored beside its labels: they are sealed under a key of
 * their own, the OnlyKey's TOUCH derived secret (firmware plugin derive_secret, okcrypto.deriveSecret
 * with touch) of one label per entry. The touch secret is another key than the touchless one for
 * the same label, so no request without a press ever reaches it, whatever a host asks; a press
 * opens one entry, once.
 *
 * The labels (title, username, sites, folder, tags) stay outside, in the identity's sealed bucket,
 * so the list shows with no press at all (memory: the bucket holds labels, not secrets).
 *
 * THE ENTRY'S REF IS ITS ID. The key comes from `okedge/passwords/v1/<scope>/<ref>`, so a seal
 * opens only for its own ref; and an entry is stored under that same id, so a seal moved onto
 * another entry (another title, another site) is refused - openInner checks the two agree.
 * No passphrase seal and no plain one: there is one way to keep a secret.
 */

const vault = require('../../src/crypto/vault');
const { toHex } = require('../../src/bytes');
const { shapeTotp } = require('./totp');

const SEAL = 'entry-touch';
/* what moves inside: the secrets, an authenticator's setup key included (spec: password, TOTP secret, notes) */
const SECRET_FIELDS = ['password', 'history', 'notes', 'totp'];
const REF = /^[0-9a-f]{32}$/;

/**
 * The derive label of an entry's key. `scope`: the store's owner (the bucket identity), so two
 * identities on one key never share an entry key; `ref`: the entry's id.
 */
function entryLabel(scope, ref) {
  if (typeof scope !== 'string' || !/^[0-9a-z]+$/i.test(scope)) throw new TypeError('passwords: the scope is the bucket identity');
  if (!REF.test(String(ref))) throw new TypeError('passwords: an entry ref is 16 random bytes, hex');
  return `okedge/passwords/v1/${scope.toLowerCase()}/${ref}`;
}

/**
 * The entry's key from the OnlyKey: its touch derived secret - always a press.
 * @param {{deriveSecret: (label: string, opts: object) => Promise<Uint8Array>}} okcrypto
 * @param {string} scope
 * @param {string} ref
 * @param {object} [opts] passed to deriveSecret (confirm, timeoutMs); `touch` is always true
 */
async function entryKey(okcrypto, scope, ref, opts = {}) {
  const k = await okcrypto.deriveSecret(entryLabel(scope, ref), { ...opts, touch: true });
  if (!(k instanceof Uint8Array) || k.length !== 32) throw new Error('passwords: the key gave no 32-byte entry key');
  return k;
}

/** Does this entry carry any secret field outside a seal? */
const hasPlainSecret = (entry) => SECRET_FIELDS.some((f) => entry && entry[f] !== undefined);

/**
 * The entry with its secret fields moved into `inner`, sealed under `innerKey` (entryKey of `ref`).
 * @param {object} entry
 * @param {Uint8Array} innerKey
 * @param {(n: number) => Uint8Array} randomBytes
 * @param {{ref: string}} opts
 */
function sealInner(entry, innerKey, randomBytes, { ref }) {
  if (!REF.test(String(ref))) throw new TypeError('passwords: a sealed entry keeps its ref (16 random bytes, hex)');
  const secrets = { ref };
  const out = { ...entry };
  for (const f of SECRET_FIELDS) {
    if (out[f] !== undefined) secrets[f] = out[f];
    delete out[f];
  }
  /* checked before it goes where nothing can check it without a press */
  for (const f of ['password', 'notes']) {
    if (secrets[f] !== undefined && (typeof secrets[f] !== 'string' || secrets[f].length > 4096)) throw new TypeError('passwords: ' + f + ' must be text of at most 4096 characters');
  }
  if (secrets.history !== undefined && (!Array.isArray(secrets.history) || secrets.history.length > 5)) throw new TypeError('passwords: history is a list of at most 5');
  if (secrets.totp !== undefined) secrets.totp = shapeTotp(secrets.totp);
  out.inner = { seal: SEAL, ref, blob: vault.seal(innerKey, JSON.stringify(secrets), randomBytes) };
  return out;
}

/**
 * The entry with its secret fields back, opened with `innerKey`. Throws when the key is wrong, and
 * when the seal is not this entry's (its ref, inside and out, must be the entry's id).
 */
function openInner(entry, innerKey) {
  if (!entry || !entry.inner) return entry;
  const { ref, ...secrets } = JSON.parse(vault.open(innerKey, entry.inner.blob));
  if (ref !== entry.inner.ref || (entry.id !== undefined && entry.id !== ref)) throw new Error('passwords: this seal belongs to another entry');
  const out = { ...entry, ...secrets };
  delete out.inner;
  return out;
}

/** a new entry's ref (and id): 16 random bytes, hex */
const newRef = (randomBytes) => toHex(randomBytes(16));

module.exports = { SEAL, SECRET_FIELDS, entryLabel, entryKey, hasPlainSecret, newRef, sealInner, openInner };
