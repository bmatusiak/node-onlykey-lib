'use strict';

/**
 * The Password Manager's core (onlykey-edge features/PASSWORD-MANAGER-SPEC.md), in the derived-key
 * format (PROPOSAL-derived-keys.md; Brad, 2026-10-27: "change Passwords vault format to use the new
 * style"). This module never talks to a device.
 *
 * A BUCKET IN THE BUCKET (Brad, 2026-10-27: "app bucket -> password bucket protected by derive key,
 * password contains labels to derive the decryptions for the secret"). Three layers:
 *   - the app's bucket (the identity's, sealed by the key's touchless derive) holds this store;
 *   - THE STORE: every record sealed under the store key - the key's TOUCHLESS derive of
 *     storeLabel(identity), asked once when the list opens (the derive setting, field 30, decides
 *     whether that asks the code) and held until the key locks. So the labels are sealed even where
 *     the app's bucket is kept opened (the desktop's CLI file);
 *   - inside a record: the labels - kind, title, username, sites, folder, tags, a recipe - and the
 *     entry's own seal of its SECRETS (a password, the earlier ones, notes, an authenticator's
 *     setup key): inner.js, the TOUCH derive of the entry's id, a press each time. put() refuses an
 *     entry with a secret outside that seal, so no host can keep one under the store key alone.
 *
 * ONE RECORD PER ENTRY, under `entries/<id>`, with `entries/index` naming them (random ids: the
 * index names no site) - so the bucket merges entry by entry without the key (bucket/src/rules.js
 * passwords). AES-GCM here has no associated data, so a record would open under any id of the same
 * key: every entry carries its id, and one whose id is not its record's is refused (a moved record).
 */

const vault = require('../../src/crypto/vault');
const { toHex } = require('../../src/bytes');
const { shapeRecipe } = require('./mnemonic');
const { shapeRecipe: shapePasswordRecipe } = require('./derived');
const { SEAL, hasPlainSecret, entryLabel } = require('./inner');

/**
 * the entry kinds this release writes. A mnemonic or a derived entry is a RECIPE (mnemonic.js,
 * derived.js): the phrase or the password itself is never stored.
 */
const KINDS = ['login', 'note', 'card', 'mnemonic', 'totp', 'derived'];
const TEXT_MAX = 4096;
const INDEX = 'entries/index';
const RECORD = 'entries/';
/* the export's version (exportJSON) */
const EXPORT_V = 2;

/**
 * The store key's derive label (touchless): one per identity. Not an entry's (an entry's ends in
 * its 32-hex id), so the store key never opens a secret.
 */
const storeLabel = (scope) => entryLabel(scope, '0'.repeat(32)).replace(/[0-9a-f]{32}$/, 'list');

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

/** The entry's fields as stored, checked; unknown fields are dropped. A secret outside its seal is refused. */
function shapeEntry(e) {
  if (!e || typeof e !== 'object') throw new TypeError('passwords: an entry is an object');
  if (!KINDS.includes(e.kind)) throw new TypeError(`passwords: kind must be one of ${KINDS.join(', ')}`);
  if (hasPlainSecret(e)) {
    if (e.kind === 'mnemonic' || e.kind === 'derived') throw new TypeError('passwords: a phrase or derived entry stores no secret, only its recipe');
    throw new TypeError('passwords: a secret is stored only inside the entry\'s seal (a press opens it)');
  }
  const out = { v: 2, kind: e.kind, title: str(e.title, 'title', { required: true }).trim() };
  if (!out.title) throw new TypeError('passwords: title is required');
  for (const f of ['username', 'folder']) {
    const x = str(e[f], f);
    if (x !== undefined) out[f] = x;
  }
  for (const f of ['urls', 'tags']) {
    const x = strings(e[f], f);
    if (x !== undefined) out[f] = x;
  }
  /*
   * The apps a login fills, each by its package AND its signing certificate's SHA-256 (spec
   * "Matching, the anti-phishing part"): an app that only took the package name gets nothing.
   */
  if (e.androidApps !== undefined) {
    if (!Array.isArray(e.androidApps) || e.androidApps.length > 16) throw new TypeError('passwords: androidApps is a list of at most 16');
    out.androidApps = e.androidApps.map((a, i) => {
      const pkg = str(a && a.package, `androidApps[${i}].package`, { required: true });
      const cert = String(a && a.cert).toLowerCase();
      if (!/^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/i.test(pkg)) throw new TypeError(`passwords: androidApps[${i}].package is not a package name`);
      if (!/^[0-9a-f]{64}$/.test(cert)) throw new TypeError(`passwords: androidApps[${i}].cert is a SHA-256, 64 hex`);
      return { package: pkg, cert };
    });
  }
  if (out.kind === 'mnemonic' || out.kind === 'derived') {
    if (e.inner !== undefined) throw new TypeError('passwords: a phrase or derived entry stores no secret, only its recipe');
    out.recipe = out.kind === 'mnemonic' ? shapeRecipe(e.recipe) : shapePasswordRecipe(e.recipe);
  } else if (e.recipe !== undefined) {
    throw new TypeError('passwords: only a phrase or a derived entry has a recipe');
  }
  /* an authenticator is its setup key: there is none without a seal */
  if (out.kind === 'totp' && e.inner === undefined) throw new TypeError('passwords: an authenticator\'s setup key is sealed (inner)');
  if (e.inner !== undefined) {
    const i = e.inner;
    if (!i || typeof i !== 'object' || i.seal !== SEAL || typeof i.blob !== 'string' || !/^[0-9a-f]{32}$/.test(String(i.ref))) {
      throw new TypeError(`passwords: inner is {seal: '${SEAL}', ref, blob}`);
    }
    out.inner = { seal: SEAL, ref: i.ref, blob: i.blob };
  }
  return out;
}

/**
 * Open one store under its store key. -> list / get / put / remove / exportJSON / importJSON / lock.
 * `store`: getItem/setItem/removeItem (already prefixed with prefixedStore); `key`: the 32-byte
 * store key (the touchless derive of storeLabel); `randomBytes(n)`: the host's CSPRNG.
 *
 * Every record is opened here once; a record that does not open under this key, or whose entry
 * names another record, is NOT listed and is reported in `refused` - never shown as an entry.
 */
async function openStore({ store, key, randomBytes, now = () => new Date() }) {
  if (!store || typeof store.getItem !== 'function') throw new TypeError('passwords: a store is required');
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new TypeError('passwords: the store key is 32 bytes');
  if (typeof randomBytes !== 'function') throw new TypeError('passwords: randomBytes is required');
  let k = Uint8Array.from(key);
  const live = () => { if (!k) throw new Error('passwords: the store is locked'); return k; };
  const entries = new Map();
  const refused = [];

  const readIndex = async () => {
    try {
      const ids = JSON.parse((await store.getItem(INDEX)) || '[]');
      return Array.isArray(ids) ? ids.filter((id) => typeof id === 'string') : [];
    } catch {
      return [];
    }
  };
  /* every record the index names, opened again with the key held - at the open, and after a sync brought more */
  const readAll = async () => {
    entries.clear();
    refused.length = 0;
    for (const id of await readIndex()) {
      try {
        const raw = await store.getItem(RECORD + id);
        if (!raw) continue;
        let e;
        try { e = JSON.parse(vault.open(live(), raw)); } catch { refused.push({ id, reason: 'does-not-open' }); continue; }
        if (!e || e.id !== id || (e.inner && e.inner.ref !== id)) { refused.push({ id, reason: 'id-mismatch' }); continue; }
        entries.set(id, e);
      } catch {
        refused.push({ id, reason: 'damaged' });
      }
    }
  };
  await readAll();

  const keep = async (e) => {
    await store.setItem(RECORD + e.id, vault.seal(live(), JSON.stringify(e), randomBytes));
    const ids = await readIndex();
    if (!ids.includes(e.id)) await store.setItem(INDEX, JSON.stringify([...ids, e.id]));
    entries.set(e.id, e);
    return e;
  };

  return {
    /** entries, title order: labels, and each one's seal - the secrets need its press */
    list() {
      live();
      return [...entries.values()].sort((a, b) => a.title.localeCompare(b.title));
    },
    get(id) {
      live();
      return entries.get(id) ?? null;
    },
    /**
     * New (no id) or an update. A sealed entry's id is its seal's ref (inner.newRef, chosen before
     * sealing): a new sealed entry brings it, as `inner.ref`; an entry without a seal gets a random one.
     */
    async put(input) {
      live();
      const shaped = shapeEntry(input);
      const at = now().toISOString();
      const was = input.id ? entries.get(input.id) : null;
      if (input.id && !was) throw new Error('passwords: no entry with that id');
      const id = was ? was.id : shaped.inner ? shaped.inner.ref : toHex(randomBytes(16));
      if (entries.has(id) && !was) throw new Error('passwords: that seal is already another entry\'s');
      if (shaped.inner && shaped.inner.ref !== id) throw new Error('passwords: an entry keeps its seal\'s ref as its id');
      return keep({ ...shaped, id, createdAt: was ? was.createdAt : at, updatedAt: at });
    },
    async remove(id) {
      live();
      await store.removeItem(RECORD + id);
      await store.setItem(INDEX, JSON.stringify((await readIndex()).filter((x) => x !== id)));
      entries.delete(id);
    },
    /**
     * A copy to keep or move: the whole list sealed under the store key, each entry's secrets still
     * in their own seal inside it - it opens only with this key (or one restored from its backup).
     */
    exportJSON() {
      return JSON.stringify({ v: EXPORT_V, sealed: vault.seal(live(), JSON.stringify([...entries.values()]), randomBytes) });
    },
    /** A copy from exportJSON, opened with this store's key: new entries added, the ones here kept. */
    async importJSON(json) {
      const env = typeof json === 'string' ? JSON.parse(json) : json;
      if (!env || env.v !== EXPORT_V || typeof env.sealed !== 'string') throw new Error('passwords: not a sealed passwords file');
      let list;
      try {
        list = JSON.parse(vault.open(live(), env.sealed));
      } catch {
        throw new Error('passwords: this key does not open that file');
      }
      let imported = 0;
      let skipped = 0;
      let unreadable = 0;
      for (const e of Array.isArray(list) ? list : []) {
        try {
          if (entries.has(e.id)) { skipped += 1; continue; }
          const shaped = shapeEntry(e);
          if (shaped.inner && shaped.inner.ref !== e.id) { unreadable += 1; continue; }
          await keep({ ...shaped, id: e.id, createdAt: e.createdAt, updatedAt: e.updatedAt });
          imported += 1;
        } catch {
          unreadable += 1;
        }
      }
      return { imported, skipped, unreadable };
    },
    /** records that did not open under this key (another key, moved onto another record, damaged) */
    refused: () => refused.slice(),
    /** read the store again with the key it holds: entries a sync brought show, with no derive */
    async reload() {
      live();
      await readAll();
    },
    get size() { return entries.size; },
    get locked() { return !k; },
    /** forget the entries and wipe this copy of the store key */
    lock() {
      entries.clear();
      if (k) k.fill(0);
      k = null;
    },
  };
}

module.exports = { KINDS, storeLabel, prefixedStore, shapeEntry, openStore };
