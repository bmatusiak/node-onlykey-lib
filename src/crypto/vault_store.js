/**
 * Where sealed vault blobs live between launches.
 *
 * The library holds no storage of its own - the host passes one in, exactly as
 * it passes `randomBytes`. That keeps this file the same on a phone
 * (AsyncStorage), in a browser (localStorage or IndexedDB) and in Node (a Map),
 * which is the point of one library for any GUI.
 *
 * ## Only ciphertext goes in
 *
 * A record's `encrypted` field is a sealed blob - `base64(nonce(12) ‖ ct+tag)`
 * from vault.seal - and the key that opens it is derived from the device and
 * never stored anywhere. Losing the phone loses the blobs; losing the KEY loses
 * the ability to open them at all, which is the property the whole design is
 * for. Nothing here can decrypt anything.
 *
 * ## The record shape is the web app's, deliberately
 *
 * `{ serviceId, encrypted, policy, createdAt, updatedAt }`, and the export is
 * `{ version: 1, exportedAt, credentials: [...] }` -
 * onlykey.github.io/src/plugins/vault/vault.js:81-152. An export written here
 * imports there and the other way round. Inventing a tidier shape would make
 * this app the only client that can read its own backups.
 *
 * ## Why there is an index rather than a key scan
 *
 * The store contract is three methods - getItem, setItem, removeItem - because
 * that is the intersection of what every platform offers. AsyncStorage does
 * have getAllKeys, but it returns EVERY key the app has stored, so listing
 * would mean filtering someone else's data by prefix and hoping the prefix is
 * unique.
 *
 * So an index key holds the list of service ids. That can drift from the
 * records if a write is interrupted between the two, and `list()` is written to
 * survive it: an index entry with no record is dropped rather than returned as
 * a null, and the index is rewritten when that happens. A record with no index
 * entry is genuinely unreachable, which is why the RECORD is written first -
 * the worst case is then a forgotten record rather than a phantom one.
 */
'use strict';

/** Namespaced so a host storing other things cannot collide. */
const PREFIX = 'onlyagent-vault';
const INDEX_KEY = `${PREFIX}/index`;
const RECORD_PREFIX = `${PREFIX}/credentials/`;

/** The export envelope's version. Matches the web app's. */
const EXPORT_VERSION = 1;

/**
 * The three methods a store must have.
 *
 * Checked up front rather than at the first write, because a host that wired
 * this wrong should find out when it starts rather than the first time someone
 * saves a credential.
 */
const REQUIRED = ['getItem', 'setItem', 'removeItem'];

function assertStore(store) {
  if (!store || typeof store !== 'object') {
    throw new Error('vault store: no store supplied by the host');
  }
  const missing = REQUIRED.filter((m) => typeof store[m] !== 'function');
  if (missing.length) {
    throw new Error(`vault store: the store is missing ${missing.join(', ')}`);
  }
}

/**
 * A vault store over a host-supplied key/value store.
 *
 * @param {object} opts
 * @param {{getItem: function, setItem: function, removeItem: function}} opts.store
 * @param {function} [opts.now] injectable clock, so a test can pin timestamps
 */
function createVaultStore({ store, now = () => Date.now() } = {}) {
  assertStore(store);

  const recordKey = (serviceId) => `${RECORD_PREFIX}${serviceId}`;

  async function readIndex() {
    const raw = await store.getItem(INDEX_KEY);
    if (!raw) return [];
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed.filter((id) => typeof id === 'string') : [];
    } catch {
      /*
       * A corrupt index is recoverable and a thrown error is not: the records
       * are still there, and a later put() rebuilds the index around whatever
       * is written next. Refusing to start would strand them.
       */
      return [];
    }
  }

  async function writeIndex(ids) {
    await store.setItem(INDEX_KEY, JSON.stringify(ids));
  }

  async function readRecord(serviceId) {
    const raw = await store.getItem(recordKey(serviceId));
    if (!raw) return null;
    try {
      const record = JSON.parse(raw);
      return record && record.serviceId ? record : null;
    } catch {
      // A record that will not parse is not a record. Reporting it as absent
      // lets a caller overwrite it; reporting it as an error would not.
      return null;
    }
  }

  const api = {
    /**
     * Save one credential.
     *
     * `createdAt` survives an update and `updatedAt` does not, which is what
     * makes "when did I first store this" answerable after an edit.
     */
    async put(entry) {
      if (!entry || !entry.serviceId) throw new Error('a vault record needs a serviceId');
      if (!entry.encrypted) throw new Error('a vault record needs its sealed blob');

      const existing = await readRecord(entry.serviceId);
      const at = now();
      const record = {
        ...entry,
        createdAt: entry.createdAt || (existing && existing.createdAt) || at,
        updatedAt: at,
      };

      // RECORD FIRST, then the index - see the note at the top of this file.
      await store.setItem(recordKey(record.serviceId), JSON.stringify(record));

      const ids = await readIndex();
      if (!ids.includes(record.serviceId)) {
        await writeIndex([...ids, record.serviceId]);
      }
      return record;
    },

    /** One credential, or null. */
    get(serviceId) {
      return readRecord(serviceId);
    },

    /** Forget one. The blob is unreadable without the device either way. */
    async remove(serviceId) {
      await store.removeItem(recordKey(serviceId));
      const ids = await readIndex();
      const left = ids.filter((id) => id !== serviceId);
      if (left.length !== ids.length) await writeIndex(left);
    },

    /**
     * Every credential, oldest first.
     *
     * Self-healing: an index entry whose record has gone is dropped and the
     * index rewritten, so a half-finished delete does not leave a name in the
     * list forever.
     */
    async list() {
      const ids = await readIndex();
      const records = [];
      const alive = [];
      for (const id of ids) {
        const record = await readRecord(id);
        if (record) {
          records.push(record);
          alive.push(id);
        }
      }
      if (alive.length !== ids.length) await writeIndex(alive);
      records.sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));
      return records;
    },

    /** Just the names, for a list screen that does not need the blobs. */
    async serviceIds() {
      return (await api.list()).map((r) => r.serviceId);
    },

    /**
     * Everything, as the web app's export envelope.
     *
     * Safe to hand to anyone in the sense that matters - every `encrypted`
     * field is still sealed, and the key is on a device. It is NOT safe in the
     * sense of privacy: the service ids are in the clear, so an export says
     * which sites someone has accounts on.
     */
    async exportJSON() {
      return JSON.stringify({
        version: EXPORT_VERSION,
        exportedAt: new Date(now()).toISOString(),
        credentials: await api.list(),
      }, null, 2);
    },

    /**
     * Import an export.
     *
     * Existing ids are SKIPPED unless `force`, so importing a backup over a
     * live vault cannot quietly replace a newer credential with an older one.
     * The count of skipped entries is returned rather than hidden, because
     * "imported 0 of 12" is the answer a caller needs to see.
     */
    async importJSON(json, { force = false } = {}) {
      let data;
      try {
        data = JSON.parse(json);
      } catch (e) {
        throw new Error(`vault import: not JSON (${e.message})`);
      }
      if (!data || !Array.isArray(data.credentials)) {
        throw new Error('vault import: no credentials array - is this a vault export?');
      }
      if (data.version !== undefined && data.version !== EXPORT_VERSION) {
        throw new Error(
          `vault import: export version ${data.version}, this build reads ${EXPORT_VERSION}`,
        );
      }

      const existing = new Set(await api.serviceIds());
      let imported = 0;
      let skipped = 0;

      for (const entry of data.credentials) {
        if (!entry || !entry.serviceId || !entry.encrypted) { skipped++; continue; }
        if (existing.has(entry.serviceId) && !force) { skipped++; continue; }
        await api.put(entry);
        existing.add(entry.serviceId);
        imported++;
      }
      return { imported, skipped, total: data.credentials.length };
    },

    /**
     * Remove every credential this store knows about.
     *
     * Only what the INDEX names, so a host storing other things under other
     * keys keeps them. That also means a record orphaned by a corrupt index
     * survives a clear - which is the safer failure, since the alternative is
     * deleting keys this store did not write.
     */
    async clear() {
      const ids = await readIndex();
      for (const id of ids) await store.removeItem(recordKey(id));
      await store.removeItem(INDEX_KEY);
      return ids.length;
    },
  };

  return api;
}

/**
 * A store backed by a Map, for tests and for a host with nothing better.
 *
 * NOT persistence. It is here so the library's own tests do not need a
 * platform, and so a host can exercise a flow before wiring real storage.
 */
function memoryStore() {
  const map = new Map();
  return {
    async getItem(key) { return map.has(key) ? map.get(key) : null; },
    async setItem(key, value) { map.set(key, String(value)); },
    async removeItem(key) { map.delete(key); },
    /** For assertions; not part of the contract. */
    _map: map,
  };
}

module.exports = {
  createVaultStore,
  memoryStore,
  PREFIX,
  INDEX_KEY,
  RECORD_PREFIX,
  EXPORT_VERSION,
};
