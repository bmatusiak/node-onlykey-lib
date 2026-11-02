'use strict';

/*
 * The CLI's member in the room (bucket/cli/roomservice.js; S5b): this computer's kept bucket file, served in the room
 * by the lib's room sync - what another writer puts in the file (the desktop app, a command) reaches another device of
 * the identity, and what that device has comes back into the file. A second join of this computer's device id (the
 * desktop app took over) stands the service by: it is told, and it does not join again.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const bucketLib = require('../src/bucket');
const home = require('../cli/home');
const { connectRoom } = require('../src/room-client');
const { createRoomSync } = require('../src/roomsync');
const { createRoomService } = require('../cli/roomservice');
const { rnd, RULES, identity, fakeServer, CARRIERS } = require('./helpers/room-harness');

const until = async (what, cond, ms = 5000) => {
  const end = Date.now() + ms;
  while (!(await cond())) {
    if (Date.now() > end) throw new Error(`timed out: ${what}`);
    await new Promise((r) => setTimeout(r, 20));
  }
};

/* another device of the identity (an app's bucket in memory), wired as the app is */
async function otherDevice(me, carrier) {
  const bucket = bucketLib.create(me.id);
  const sync = createRoomSync({
    open: () => ({ bucket, identity: me.id }), me: async () => me, save: async () => {}, handleTrade: async () => ({ ok: false }),
    rules: RULES, randomBytes: rnd,
  });
  const r = await connectRoom({ url: carrier.url, me, device: { id: crypto.randomBytes(8).toString('hex'), name: 'phone', kind: 'android' }, WebSocket: carrier.WebSocket, randomBytes: rnd });
  let synced = 0;
  sync.wire(r, { tag: '[phone]', peers: () => {}, sealed: (s) => { if (s.status === 'synced') synced += 1; }, newer: () => {} }, r && me);
  return { bucket, sync, room: r, synced: () => synced };
}

test('the service serves the computer\'s file in the room: another writer\'s change reaches a device, and back', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'okroomsvc-'));
  home.setRoot(root);
  t.after(() => home.setRoot(null));
  const me = await identity('roomservice');
  const server = fakeServer();
  const carrier = CARRIERS.websocket(server);
  let fire = null;
  const svc = createRoomService({
    proof: me, net: 'test', url: async () => carrier.url, WebSocket: carrier.WebSocket, randomBytes: rnd,
    device: { id: 'aa'.repeat(8), name: 'box' }, watch: (d, cb) => { fire = cb; return { close() {} }; }, debounceMs: 10,
  });
  await svc.start();
  assert.equal(svc.state.status, 'joined');
  const file = home.identityFile(me.id, 'test');

  /* another writer on this computer (the desktop app, a command) adds a record to the file */
  home.update(file, (b) => { bucketLib.kv(b, 'passwords-test').setItem('entry:mail', 'v1'); });
  fire();
  /* the phone joins later: the server's sealed copy has it */
  await until('the service put it in the sealed copy', () => [...(server.sealed.values())].some((rows) => rows.size > 0));
  const phone = await otherDevice(me, CARRIERS.websocket(server));
  await until('the phone took it', () => bucketLib.kv(phone.bucket, 'passwords-test').getItem('entry:mail') === 'v1');

  /* the phone adds one; the server says the copy changed only through a round - the service's next round takes it */
  bucketLib.kv(phone.bucket, 'passwords-test').setItem('entry:bank', 'v2');
  phone.sync.changed();
  await until('the phone put it', async () => phone.synced() >= 2);
  home.update(file, (b) => { bucketLib.kv(b, 'passwords-test').setItem('entry:note', 'v3'); });
  fire();
  await until('the file has the phone\'s record', () => bucketLib.kv(home.read(file), 'passwords-test').getItem('entry:bank') === 'v2');
  phone.room.close();
  await svc.stop();
});

test('a second join of this computer (the desktop app took over) stands the service by - it does not join again', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'okroomsvc-'));
  home.setRoot(root);
  t.after(() => home.setRoot(null));
  const me = await identity('roomservice-replaced');
  const server = fakeServer();
  const carrier = CARRIERS.websocket(server);
  let replaced = 0;
  const device = { id: 'bb'.repeat(8), name: 'box' };
  const svc = createRoomService({
    proof: me, net: 'test', url: async () => carrier.url, WebSocket: carrier.WebSocket, randomBytes: rnd, device,
    watch: () => ({ close() {} }), onReplaced: () => { replaced += 1; },
  });
  await svc.start();
  /* the desktop app joins with the same device id */
  const app = await connectRoom({ url: carrier.url, me, device: { ...device, kind: 'desktop' }, WebSocket: carrier.WebSocket, randomBytes: rnd });
  await until('the service was told', () => replaced === 1);
  assert.equal(svc.state.status, 'replaced');
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(replaced, 1, 'it did not join again (no second replacement)');
  app.close();
  await svc.stop();
});
