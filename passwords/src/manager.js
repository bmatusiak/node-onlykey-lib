'use strict';

/**
 * The Password Manager's core (onlykey-edge features/PASSWORD-MANAGER-SPEC.md): entries sealed
 * by the OnlyKey, stored as ciphertext only, opened with ONE manager key per session.
 *
 * THE MANAGER KEY is the vault key of one fixed derive label (LABEL, `vault:ok-rn-manager`): the
 * caller gets it from the key (okcrypto.deviceVault.key, which also keeps it in its session
 * cache) and hands the 32 bytes in here. This module never talks to a device.
 *
 * THE STORE IS NAMED AFTER THE KEY (Brad, 2026-10-11: "password storage is encrypted to the keys
 * identity, so multiple keys can use the app at the same time"; "they should produce the same
 * store" for a key restored from the same backup). storeIdOf(public key of that derive) names
 * it - asking the public key needs no press - and prefixedStore() keeps each store under its own
 * prefix: two keys from one backup give one id and share one store; a key with other seeds never
 * sees another's entries.
 *
 * WHAT IS SEALED: each entry is JSON (kind, title, username, password, urls, notes, ...) sealed
 * AES-256-GCM under the manager key (lib src/crypto/vault.js), kept by src/crypto/vault_store.js
 * under a random record id, so the stored index names no site. AES-GCM here has no associated
 * data, so a blob would open under any record of the same key: every entry carries its own id,
 * and an entry whose id is not its record's is refused (a swapped blob).
 */

const vault = require('../../src/crypto/vault');
const { createVaultStore } = require('../../src/crypto/vault_store');
const { sha256 } = require('../../src/crypto/provider');
const { toHex } = require('../../src/bytes');

/** the derive label the manager key comes from (deviceVault adds `vault:`) */
const LABEL = 'ok-rn-manager';
/** the entry kinds this release writes; later ones (totp, mnemonic, derived) are refused until built */
const KINDS = ['login', 'note', 'card'];
const HISTORY = 5;
const TEXT_MAX = 4096;

/** The store id: SHA-256 of the manager label's derive public key, hex. Public by design. */
function storeIdOf(publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length < 32) throw new TypeError('passwords: storeIdOf needs the derive public key');
  return toHex(sha256(publicKey));
}

/** A key/value store (getItem/setItem/removeItem) with every key under `prefix`. */
function prefixedStore(store, prefix) {
  if (!store || typeof store.getItem !== 'function' || typeof store.setItem !== 'function' || typeof store.removeItem !== 'function') {
    throw new TypeError('passwords: prefixedStore needs getItem/setItem/removeItem');
  }
  return {
    getItem: (k) => store.getItem(prefix + k),
    setItem: (k, v) => store.setItem(prefix + k, v),
    removeItem: (k) => store.removeItem(prefix + k),
  };
}

const str = (v, name, { required = false } = {}) => {
  if (v === undefined || v === null) {
    if (required) throw new TypeError(`passwords: ${name} is required`);
    return undefined;
  }
  if (typeof v !== 'string' || v.length > TEXT_MAX) throw new TypeError(`passwords: ${name} must be text of at most ${TEXT_MAX} characters`);
  return v;
};
const strings = (v, name) => {
  if (v === undefined || v === null) return undefined;
  if (!Array.isArray(v) || v.length > 64) throw new TypeError(`passwords: ${name} must be a list of at most 64`);
  return v.map((x, i) => str(x, `${name}[${i}]`, { required: true }));
};

/** The entry's fields as stored, checked; unknown fields are dropped. */
function shapeEntry(e) {
  if (!e || typeof e !== 'object') throw new TypeError('passwords: an entry is an object');
  if (!KINDS.includes(e.kind)) throw new TypeError(`passwords: kind must be one of ${KINDS.join(', ')}`);
  const out = { v: 1, kind: e.kind, title: str(e.title, 'title', { required: true }).trim() };
  if (!out.title) throw new TypeError('passwords: title is required');
  for (const f of ['username', 'password', 'notes', 'folder']) {
    const x = str(e[f], f);
    if (x !== undefined) out[f] = x;
  }
  for (const f of ['urls', 'tags']) {
    const x = strings(e[f], f);
    if (x !== undefined) out[f] = x;
  }
  if (e.reconfirm === true) out.reconfirm = true;
  if (e.inner !== undefined) {
    const i = e.inner;
    if (!i || typeof i !== 'object' || !['entry-derive', 'entry-passphrase'].includes(i.seal) || typeof i.blob !== 'string') throw new TypeError('passwords: inner is {seal, blob, salt?}');
    out.inner = { seal: i.seal, blob: i.blob, ...(typeof i.salt === 'string' ? { salt: i.salt } : {}) };
  }
  return out;
}

/**
 * Open one store under its manager key. -> the manager: list / get / put / remove / exportJSON /
 * importJSON / lock. `store`: getItem/setItem/removeItem (already prefixed with prefixedStore);
 * `key`: the 32-byte manager key; `randomBytes(n)`: the host's CSPRNG.
 *
 * Every record is opened here once; a record that does not open under this key, or whose entry
 * names another record, is NOT listed and is reported in `refused` - never shown as an entry.
 */
async function openManager({ store, key, randomBytes, now = () => new Date() }) {
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new TypeError('passwords: the manager key is 32 bytes');
  if (typeof randomBytes !== 'function') throw new TypeError('passwords: randomBytes is required');
  let k = Uint8Array.from(key);
  const vs = createVaultStore({ store });
  const entries = new Map();
  const refused = [];
  const live = () => { if (!k) throw new Error('passwords: the manager is locked'); return k; };

  for (const rec of await vs.list()) {
    try {
      const e = JSON.parse(vault.open(live(), rec.encrypted));
      if (!e || e.id !== rec.serviceId) { refused.push({ id: rec.serviceId, reason: 'id-mismatch' }); continue; }
      entries.set(rec.serviceId, e);
    } catch {
      refused.push({ id: rec.serviceId, reason: 'does-not-open' });
    }
  }

  const sealAndKeep = async (e) => {
    await vs.put({ serviceId: e.id, encrypted: vault.seal(live(), JSON.stringify(e), randomBytes) });
    entries.set(e.id, e);
    return e;
  };

  return {
    /** entries, title order; with their secrets - the caller decides what is drawn */
    list() {
      live();
      return [...entries.values()].sort((a, b) => a.title.localeCompare(b.title));
    },
    get(id) {
      live();
      return entries.get(id) ?? null;
    },
    /** new (no id) or an update; a changed password goes to the history (last 5) */
    async put(input) {
      live();
      const shaped = shapeEntry(input);
      const at = now().toISOString();
      const was = input.id ? entries.get(input.id) : null;
      if (input.id && !was) throw new Error('passwords: no entry with that id');
      const id = was ? was.id : toHex(randomBytes(16));
      const history = was ? [...(was.history || [])] : [];
      if (was && was.password && shaped.password !== was.password) history.unshift({ password: was.password, changedAt: at });
      const e = { ...shaped, id, createdAt: was ? was.createdAt : at, updatedAt: at, ...(history.length ? { history: history.slice(0, HISTORY) } : {}) };
      return sealAndKeep(e);
    },
    async remove(id) {
      live();
      await vs.remove(id);
      entries.delete(id);
    },
    /** the sealed envelope (src/crypto/vault_store v1): every entry still sealed, ids random */
    exportJSON: () => vs.exportJSON(),
    /** a sealed envelope from this key; an entry that does not open under it is skipped and counted */
    async importJSON(json, { force = false } = {}) {
      live();
      const env = typeof json === 'string' ? JSON.parse(json) : json;
      const good = [];
      let unreadable = 0;
      for (const c of (env && env.credentials) || []) {
        try {
          const e = JSON.parse(vault.open(live(), c.encrypted));
          if (e && e.id === c.serviceId) good.push({ c, e }); else unreadable += 1;
        } catch { unreadable += 1; }
      }
      const r = await vs.importJSON(JSON.stringify({ ...env, credentials: good.map((g) => g.c) }), { force });
      for (const g of good) if (force || !entries.has(g.e.id)) entries.set(g.e.id, g.e);
      return { ...r, unreadable };
    },
    /** records that did not open under this key (wrong key, swapped, damaged) */
    refused: () => refused.slice(),
    get size() { return entries.size; },
    get locked() { return !k; },
    /** forget the entries and wipe this copy of the key (the caller locks its session cache) */
    lock() {
      entries.clear();
      if (k) k.fill(0);
      k = null;
    },
  };
}

module.exports = { LABEL, KINDS, storeIdOf, prefixedStore, shapeEntry, openManager };
