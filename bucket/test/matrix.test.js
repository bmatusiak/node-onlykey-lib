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
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { ed25519, x25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');
const bucketLib = require('../src/bucket');
const bid = require('../src/bucket-identity');
const room = require('../src/room');
const sealedCopy = require('../src/sealedcopy');
const { connectRoom } = require('../src/room-client');
const { rowsStorage, sharedFileStorage, memoryRows } = require('../src/storage');
const { storeRules } = require('../src/store-rules');
const { fileSide } = require('../cli/file-side');
const bleSocket = require('../../src/transport/ble-socket');

const rnd = (n) => new Uint8Array(crypto.randomBytes(n));
const HOST = 'ok-edge.example.workers.dev';
const RULES = storeRules();

async function identity(seed) {
  const secretOf = (label, keyType) => sha256(new Uint8Array([...new TextEncoder().encode(seed), ...label, keyType]));
  const key = {
    deriveSecret: async (label, { rpId } = {}) => sha256(new TextEncoder().encode(`${seed}|${label}|${rpId}`)),
    keySite: async () => ({ on: true, site: 'okt.example' }),
    agent: {
      publicKey: async (label, { keyType }) => (keyType === 1 ? ed25519.getPublicKey(secretOf(label, 1)) : x25519.getPublicKey(secretOf(label, 4))),
      ecdh: async (label, peer) => x25519.getSharedSecret(secretOf(label, 4), peer),
      sign: async (label, message) => ed25519.sign(message, secretOf(label, 1)),
    },
  };
  const { publicKey, id } = await bid.readIdentity(key);
  const bucketKey = await bid.deriveBucketKeyAt(key, publicKey, 'okt.example');
  const certificate = await bid.certify(key, publicKey, bucketKey.publicKey);
  return { id, identityPublicKey: publicKey, bucketKey, certificate };
}

/* the room as the mcp-server keeps it, in memory: the join, and the identity's sealed copy (rows by id) */
function fakeServer() {
  const sealed = new Map();
  const rowsOf = (r) => { if (!sealed.has(r)) sealed.set(r, new Map()); return sealed.get(r); };
  /* one room socket: deliver(message) is the server's word to the device; text() what the device sent */
  function roomSocket(roomId, deliver, onClose) {
    const { nonce, message } = room.challenge(rnd);
    let device = null;
    setImmediate(() => deliver(message));
    return {
      text(raw) {
        const m = JSON.parse(raw);
        if (!device) {
          const c = room.checkJoin(roomId, m, { nonce, host: HOST });
          if (!c.ok) { deliver({ t: 'refused' }); onClose(); return; }
          device = c.device;
          deliver({ t: 'joined', you: device.id, peers: [] });
          return;
        }
        if (m.t === 'ping') return deliver({ t: 'pong' });
        if (m.t === 'sealed') {
          const rows = rowsOf(roomId);
          if (m.op === 'table') return deliver({ t: 'sealed', re: m.re, on: true, rows: Object.fromEntries([...rows].map(([id, r]) => [id, r.tag])) });
          if (m.op === 'get') return deliver({ t: 'sealed', re: m.re, rows: Object.fromEntries((m.ids || []).filter((id) => rows.has(id)).map((id) => [id, rows.get(id).blob])) });
          if (m.op === 'put') { for (const [id, r] of Object.entries(m.rows || {})) rows.set(id, { tag: r.tag, blob: r.blob }); return deliver({ t: 'sealed', re: m.re, ok: true, n: Object.keys(m.rows || {}).length }); }
          return deliver({ t: 'sealed', re: m.re, ok: false, why: 'no such op' });
        }
        return undefined;
      },
    };
  }
  /* the room over a websocket: a WebSocket-shaped class, as Node's or the browser's */
  class FakeWS {
    constructor(url) {
      this.readyState = 1;
      const roomId = new URL(url).pathname.split('/').pop();
      this.side = roomSocket(roomId, (m) => this.onmessage && this.onmessage({ data: JSON.stringify(m) }), () => this.close());
      setImmediate(() => this.onopen && this.onopen({}));
    }
    send(text) { this.side.text(text); }
    close() { if (this.readyState === 3) return; this.readyState = 3; setImmediate(() => this.onclose && this.onclose({ code: 1000 })); }
  }
  /*
   * the room over Bluetooth: the phone's end (createSocketLink) sends 0x86 payloads; this server end decodes them, opens
   * the same room socket on OPEN and answers with OPENED / TEXT - the frames a real link carries, fragments aside
   */
  function bleLink() {
    const dec = bleSocket.createDecoder();
    let side = null;
    let phone = null;
    const toPhone = (payload) => setImmediate(() => phone.push(payload));
    const link = bleSocket.createSocketLink({
      sendFrame: (payload) => {
        const ev = dec.push(payload);
        if (!ev) return;
        if (ev.kind === 'open') {
          side = roomSocket(ev.room, (m) => { for (const p of bleSocket.encodeText(JSON.stringify(m))) toPhone(p); }, () => toPhone(bleSocket.encodeClose({ code: 1000 })));
          toPhone(bleSocket.encodeOpened({ host: HOST }));
        } else if (ev.kind === 'text' && side) side.text(ev.text);
      },
    });
    phone = link;
    toPhone(bleSocket.encodeHere({ host: HOST }));
    return link;
  }
  return { FakeWS, bleLink, sealed };
}

/* a carrier: how a device reaches the identity's room - the url and the WebSocket class room-client dials */
const CARRIERS = {
  websocket: (server) => ({ url: `https://${HOST}`, WebSocket: server.FakeWS }),
  bluetooth: (server) => { const l = server.bleLink(); return { url: `ble://${HOST}`, WebSocket: l.WebSocket }; },
};

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
