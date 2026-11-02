'use strict';

/*
 * A host's bucket sync in a joined room (bucket/src/roomsync.js; the structure track S5): two devices of one identity,
 * each with its bucket, each WIRED into the room through createRoomSync - nothing calls a sync by hand. Joining runs a
 * round with the server's sealed copy; a change here (changed()) runs another. Device A's records reach device B, and
 * B's come back to A. One round at a time (the queue), the host told through its hooks: syncing, then synced, and what
 * was taken.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const bucketLib = require('../src/bucket');
const { connectRoom } = require('../src/room-client');
const { createRoomSync } = require('../src/roomsync');
const { rnd, RULES, identity, fakeServer, CARRIERS } = require('./helpers/room-harness');

const recordsOf = (bucket, store) => Object.fromEntries(bucketLib.kv(bucket, store).keys().map((k) => [k, bucketLib.kv(bucket, store).getItem(k)]));

/* one device: a bucket, its room joined over a carrier, wired - and a promise for its next 'synced' */
async function device(me, carrier, name) {
  const bucket = bucketLib.create(me.id);
  const news = [];
  let waiting = [];
  const synced = () => new Promise((resolve) => waiting.push(resolve));
  let saves = 0;
  const sync = createRoomSync({
    open: () => ({ bucket, identity: me.id }),
    me: async () => me,
    save: async () => { saves += 1; },
    handleTrade: async () => ({ ok: false }),
    rules: RULES,
    randomBytes: rnd,
    tell: { items: (b) => Object.fromEntries(Object.keys(b.stores).map((s) => [s, bucketLib.kv(b, s).keys().length])) },
  });
  const r = await connectRoom({ url: carrier.url, me, device: { id: crypto.randomBytes(8).toString('hex'), name, kind: 'android' }, WebSocket: carrier.WebSocket, randomBytes: rnd });
  sync.wire(r, {
    tag: `[${name}]`,
    peers: () => {},
    sealed: (s) => {
      news.push(s.status);
      if (s.status === 'synced' || s.status === 'error') { const w = waiting; waiting = []; for (const f of w) f(s); }
    },
    newer: () => {},
  }, me);
  return { bucket, sync, room: r, news, synced, saves: () => saves };
}

for (const carrier of ['websocket', 'bluetooth']) {
  test(`over ${carrier}: wired devices converge through the room's sealed copy - a join and a change each run one round`, async () => {
    const me = await identity(`roomsync-${carrier}`);
    const server = fakeServer();
    const A = await device(me, CARRIERS[carrier](server), 'A');
    const joinedA = await A.synced();
    assert.equal(joinedA.status, 'synced', 'the join ran a round');
    bucketLib.kv(A.bucket, 'passwords-test').setItem('entry:mail', 'v1');
    const changedA = A.synced();
    A.sync.changed();
    assert.equal((await changedA).status, 'synced', 'the change ran a round');

    const B = await device(me, CARRIERS[carrier](server), 'B');
    const joinedB = await B.synced();
    assert.equal(joinedB.status, 'synced');
    assert.deepEqual(recordsOf(B.bucket, 'passwords-test'), { 'entry:mail': 'v1' }, 'B took A\'s record from the room');
    assert.ok(B.saves() >= 1, 'what B took was saved');

    bucketLib.kv(B.bucket, 'passwords-test').setItem('entry:bank', 'v2');
    const changedB = B.synced();
    B.sync.changed();
    await changedB;
    const back = A.synced();
    A.sync.changed();
    await back;
    assert.deepEqual(recordsOf(A.bucket, 'passwords-test'), { 'entry:mail': 'v1', 'entry:bank': 'v2' }, 'A took B\'s back');
    assert.deepEqual(A.news.filter((s) => s === 'syncing').length, A.news.filter((s) => s === 'synced').length, 'every round said syncing, then synced');
    assert.equal(A.sync.rooms().size, 1);
    A.room.close();
    B.room.close();
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(A.sync.rooms().size, 0, 'a closed room is dropped when its close comes');
  });
}

test('createRoomSync names what it needs', () => {
  assert.throws(() => createRoomSync({}), /open is a function/);
});
