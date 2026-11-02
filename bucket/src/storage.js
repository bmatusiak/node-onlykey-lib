'use strict';

/**
 * WHERE A HOST KEEPS AN IDENTITY'S BUCKET - one contract, every host (the structure track S3, 2026-11-02; PROPOSAL-
 * rectify-ok-edge.md R1, PROPOSAL-one-sync.md). The bucket in memory is the same everywhere (bucket.js); how it is kept
 * differs, and only that is a host's: an adapter hands its few calls in, and everything above them - which rows changed,
 * sealing, the merge into a shared file - is here, tested once (bucket/test/matrix.test.js) for every host.
 *
 *   rowsStorage({rows, rules, randomBytes})        the bucket kept as SEALED ROWS - the same rows the server's sealed copy
 *                                                  keeps: the phone (rows in AsyncStorage) and the web app (IndexedDB)
 *   sharedFileStorage({side, net, rules})          the bucket kept OPENED in the CLI's folder and shared with the CLI
 *                                                  (~/.onlykey-js/buckets/<net>/<id>.json): the desktop's page (side =
 *                                                  its IPC calls) and the CLI itself (side = bucket/cli/file-side.js)
 *   memoryRows()                                   a row store in memory (tests; the fake every row adapter must match)
 *
 * The contract (what the app's screens and the sync see):
 *   BucketStorage {needsKey, state(identity) -> 'kept'|'sealed'|'none', open(identity, key, prove) -> Opened|null,
 *                  create(identity, key) -> Opened}
 *     needsKey   the bucket is sealed here and the key's secret opens it (rows); false where it is kept opened
 *     prove      (rows) -> bucket: turns sealed rows into the bucket, proving the key is the identity's (the caller's)
 *   Opened {bucket, write(), refresh() -> records taken}
 *     write      keep what changed (rows: only the changed units, each sealed; the shared file: merged in, newer wins)
 *     refresh    take in what another program wrote meanwhile (the shared file); rows: nothing else writes them
 *   RowStore {table() -> {id: tag}, get(ids) -> {id: blob}, put({id: {tag, blob}}), all() -> {id: blob}, clear()}
 *   FileSide {has(identity, net), read(identity, net) -> text|null, keep(identity, net, text), mergeIn(identity, net, text)}
 *
 * Pure: no Node built-ins - the phone, the web app and the CLI take it alike.
 */
const bucketLib = require('./bucket');
const sealedCopy = require('./sealedcopy');

/**
 * The bucket as sealed rows. rows(identity) -> this identity's RowStore on this host (the adapter decides the net).
 * Every write puts only the units that changed, each sealed under keys from the key's secret, and the owner row once -
 * a write of one record is one row, and needs no key and no press.
 * @param {{rows: (identity: string) => any, rules?: object, randomBytes: (n: number) => Uint8Array}} o
 */
function rowsStorage({ rows, rules = {}, randomBytes }) {
  function kept(identity, bucket, key, tags) {
    const store = rows(identity);
    const keys = sealedCopy.keysOf({ secretKey: key });
    /* one write at a time, so the last stored is the newest bucket (writes arrive back to back) */
    let writes = Promise.resolve();
    return {
      bucket,
      write() {
        const run = writes.then(async () => {
          const t = sealedCopy.table(bucket, keys, { rules });
          const ids = Object.keys(t.rows).filter((id) => tags[id] !== t.rows[id]);
          const out = ids.length ? sealedCopy.sealRows(bucket, keys, ids, { rules, randomBytes }) : {};
          const o = sealedCopy.sealOwner(identity, keys, randomBytes);
          if (tags[o.id] !== o.tag) out[o.id] = { tag: o.tag, blob: o.blob };
          if (!Object.keys(out).length) return;
          await store.put(out);
          for (const [id, r] of Object.entries(out)) tags[id] = r.tag;
        });
        writes = run.catch(() => {});
        return run;
      },
      /* nothing else writes these rows: what is in memory is what is kept */
      refresh: async () => 0,
    };
  }
  return {
    needsKey: true,
    async state(identity) {
      return Object.keys(await rows(identity).table()).length ? 'sealed' : 'none';
    },
    async open(identity, key, prove) {
      if (!key) throw new Error('the bucket is sealed here: the key\'s secret opens it');
      const store = rows(identity);
      const all = await store.all();
      if (!Object.keys(all).length) return null;
      const bucket = prove(all);
      return kept(identity, bucket, key, await store.table());
    },
    async create(identity, key) {
      if (!key) throw new Error('the bucket is sealed here: a new one needs the key\'s secret');
      const bucket = bucketLib.create({ owner: identity });
      const opened = kept(identity, bucket, key, {});
      await opened.write();
      return opened;
    },
  };
}

/**
 * The bucket kept opened in a file another program shares (the CLI). One bucket in memory, as on every host: read once,
 * written by handing the whole bucket to be MERGED into the file inside its lock (the store rules, newer wins - a write
 * the other program made meanwhile is never lost), and refreshed by the same merge the other way. net() -> 'live'|'test'.
 * @param {{side: {has: Function, read: Function, keep: Function, mergeIn: Function}, net: () => string, rules?: object}} o
 */
function sharedFileStorage({ side, net, rules = {} }) {
  function kept(identity, n, bucket) {
    let writes = Promise.resolve();
    return {
      bucket,
      write() {
        const run = writes.then(() => side.mergeIn(identity, n, bucketLib.serialize(bucket)));
        writes = run.catch(() => {});
        return run.then(() => {});
      },
      async refresh() {
        const text = await side.read(identity, n);
        if (!text) return 0;
        const { bucket: merged, report } = bucketLib.merge(bucket, bucketLib.parse(text), { rules });
        bucket.stores = merged.stores;
        /* the clock moves past every stamp taken in (merge), so this host's next write is later than all of them */
        bucket.clock = merged.clock;
        return Object.values(report.taken).reduce((a, b) => a + b, 0);
      },
    };
  }
  return {
    needsKey: false,
    async state(identity) {
      return (await side.has(identity, net())) ? 'kept' : 'none';
    },
    async open(identity) {
      const n = net();
      const text = await side.read(identity, n);
      return text ? kept(identity, n, bucketLib.parse(text)) : null;
    },
    async create(identity) {
      const n = net();
      const bucket = bucketLib.create({ owner: identity });
      await side.keep(identity, n, bucketLib.serialize(bucket));
      return kept(identity, n, bucket);
    },
  };
}

/** A row store in memory - the contract every row adapter (AsyncStorage, IndexedDB) keeps. */
function memoryRows() {
  const m = new Map();
  return {
    async table() { return Object.fromEntries([...m].map(([id, r]) => [id, r.tag])); },
    async all() { return Object.fromEntries([...m].map(([id, r]) => [id, r.blob])); },
    async get(ids) { return Object.fromEntries(ids.filter((id) => m.has(id)).map((id) => [id, m.get(id).blob])); },
    async put(rows) { for (const [id, r] of Object.entries(rows)) m.set(id, { tag: r.tag, blob: r.blob }); },
    async clear() { m.clear(); },
  };
}

module.exports = { rowsStorage, sharedFileStorage, memoryRows };
