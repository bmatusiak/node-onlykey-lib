/*
 * THE MATRIX (the structure track S3, 2026-11-02; PROPOSAL-one-sync.md "The matrix test"; Brad, 2026-10-30: "you test 1
 * path, you break the other"): every store a host keeps its bucket in x every carrier that reaches the room, composed
 * from the lib's own pieces - bucket/src/storage.js, room-client, sealedcopy - so a change that breaks one road fails
 * here, before a device.
 *
 *   stores:   rows (the phone's AsyncStorage and the web app's IndexedDB - both a RowStore; memoryRows is the contract)
 *             shared file (the desktop and the CLI: bucket/cli/file-side.js over a tmp home)
 *   carriers: the room over a websocket, and over a Bluetooth socket (src/transport/ble-socket.js, the phone's end, to a
 *             server end that opens the same room socket)
 *
 * Each case: device A writes in two features' stores, keeps them, and syncs through the room's sealed copy; device B -
 * another store, another carrier - syncs, keeps, and is opened again from what it kept: the records are A's. Then B
 * writes and A takes it: both converge.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const bucketLib = require('../src/bucket');
const sealedCopy = require('../src/sealedcopy');
const { connectRoom } = require('../src/room-client');
const { rowsStorage, sharedFileStorage, memoryRows } = require('../src/storage');
const { fileSide } = require('../cli/file-side');

const { rnd, HOST, RULES, identity, fakeServer, CARRIERS } = require('./helpers/room-harness');

/* a store: a fresh BucketStorage for one device */
const tmpHomes = [];
const STORES = {
  rows: () => { const rows = memoryRows(); return rowsStorage({ rows: () => rows, rules: RULES, randomBytes: rnd }); },
  'shared file': () => {
    const home = require('../cli/home');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'okjs-matrix-'));
    tmpHomes.push(dir);
    /* each device its own folder: the home module is one per process, so its root is set around each call */
    const side = fileSide(home);
    const at = (fn) => (...args) => { home.setRoot(dir); try { return fn(...args); } finally { home.setRoot(null); } };
    return sharedFileStorage({ side: { has: at(side.has), read: at(side.read), keep: at(side.keep), mergeIn: at(side.mergeIn) }, net: () => 'test', rules: RULES });
  },
};

/* the room's device kind for each store: rows are the phone's and the web app's, the shared file the desktop's and the CLI's */
const KIND = { rows: 'android', 'shared file': 'desktop' };

/* one device: its storage opened (or made), its room joined over its carrier, a sync through the sealed copy */
async function device(me, storage, carrier, name, kind) {
  const prove = (rows) => sealedCopy.bucketFromRows(rows, sealedCopy.keysOf(me.bucketKey), { owner: me.id, rules: RULES });
  const opened = (await storage.open(me.id, me.bucketKey.secretKey, prove)) || (await storage.create(me.id, me.bucketKey.secretKey));
  const sync = async () => {
    const r = await connectRoom({ url: carrier.url, me, device: { id: crypto.randomBytes(8).toString('hex'), name, kind }, WebSocket: carrier.WebSocket, randomBytes: rnd });
    try {
      const res = await sealedCopy.syncWith(opened.bucket, sealedCopy.keysOf(me.bucketKey), r.sealedStore(), { rules: RULES, randomBytes: rnd });
      await opened.write();
      return res;
    } finally { r.close(); }
  };
  return { opened, sync, reopen: () => storage.open(me.id, me.bucketKey.secretKey, prove) };
}

const recordsOf = (bucket, store) => Object.fromEntries(bucketLib.kv(bucket, store).keys().map((k) => [k, bucketLib.kv(bucket, store).getItem(k)]));

for (const a of Object.keys(STORES)) {
  for (const b of Object.keys(STORES)) {
    for (const [ca, cb] of [['websocket', 'websocket'], ['bluetooth', 'websocket'], ['websocket', 'bluetooth']]) {
      test(`${a} over ${ca} -> ${b} over ${cb}: B takes A's records from the room, keeps them, and A takes B's back`, async () => {
        const me = await identity(`matrix-${a}-${b}-${ca}-${cb}`);
        const server = fakeServer();
        const A = await device(me, STORES[a](), CARRIERS[ca](server), 'device A', KIND[a]);
        bucketLib.kv(A.opened.bucket, 'guestbook-test').setItem('contact:1', JSON.stringify({ name: 'Ada' }));
        bucketLib.kv(A.opened.bucket, 'passwords-test').setItem('entry:mail', 'v1');
        await A.opened.write();
        await A.sync();

        const B = await device(me, STORES[b](), CARRIERS[cb](server), 'device B', KIND[b]);
        await B.sync();
        /* what B kept, read back from its own store - not only what it holds in memory */
        const kept = await B.reopen();
        assert.ok(kept, 'B kept a bucket');
        assert.deepEqual(recordsOf(kept.bucket, 'guestbook-test'), { 'contact:1': JSON.stringify({ name: 'Ada' }) });
        assert.deepEqual(recordsOf(kept.bucket, 'passwords-test'), { 'entry:mail': 'v1' });

        bucketLib.kv(B.opened.bucket, 'passwords-test').setItem('entry:bank', 'v2');
        await B.opened.write();
        await B.sync();
        await A.sync();
        assert.deepEqual(recordsOf(A.opened.bucket, 'passwords-test'), { 'entry:mail': 'v1', 'entry:bank': 'v2' });
        assert.deepEqual(recordsOf(A.opened.bucket, 'passwords-test'), recordsOf(B.opened.bucket, 'passwords-test'), 'both converge');
      });
    }
  }
}

test.after(() => { for (const d of tmpHomes) fs.rmSync(d, { recursive: true, force: true }); });
