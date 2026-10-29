'use strict';
/*
 * The CLI's kept bucket and the server's sealed copy (bucket/cli/sealed.js): a computer's bucket file catches up from
 * the rows another device put, under the file's lock, and puts back only what the server lacks.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const home = require('../cli/home');
const bucket = require('../src');
const sealed = require('../src/sealedcopy');
const { syncKept } = require('../cli/sealed');

const rnd = (n) => new Uint8Array(crypto.randomBytes(n));
const me = { bucketKey: { secretKey: new Uint8Array(32).fill(9) } };
const keys = sealed.keysOf(me.bucketKey);
const ID = 'a'.repeat(32);
function rowStore() {
  const rows = {};
  return {
    rows,
    async table() { return Object.fromEntries(Object.entries(rows).map(([id, r]) => [id, r.tag])); },
    async get(ids) { return Object.fromEntries(ids.filter((id) => rows[id]).map((id) => [id, rows[id].blob])); },
    async put(r) { Object.assign(rows, r); },
  };
}
test.afterEach(() => home.setRoot(null));

test('a computer\'s bucket file catches up from the sealed copy, and puts back only what the server lacks', async () => {
  home.setRoot(fs.mkdtempSync(path.join(os.tmpdir(), 'okbucket-sealed-')));
  const server = rowStore();
  const phone = bucket.create({ owner: ID });
  bucket.kv(phone, 'guestbook').setItem('myname', 'Pixel Tester');
  await sealed.syncWith(phone, keys, server, { randomBytes: rnd });
  home.keepIdentityBucket(ID, 'live', bucket.create({ owner: ID }));
  home.kv(home.identityAt(ID, 'live', 'keychain')).setItem('list', '{"format":"onlykey-keychain","version":1,"entries":[]}');
  const r = await syncKept({ id: ID, net: 'live', me, store: server, rules: {}, randomBytes: rnd, heads: () => ({ bbbbbbbbbbbbbbbb: 3 }) });
  assert.deepEqual([r.on, r.got, r.put], [true, 1, 2], 'got the phone\'s record; put its own and the heads row');
  assert.equal(home.kv(home.identityAt(ID, 'live', 'guestbook')).getItem('myname'), 'Pixel Tester');
  const again = await syncKept({ id: ID, net: 'live', me, store: server, rules: {}, randomBytes: rnd, heads: () => ({ bbbbbbbbbbbbbbbb: 3 }) });
  assert.deepEqual([again.got, again.put], [0, 0]);
  assert.deepEqual(await syncKept({ id: ID, net: 'live', me, store: { ...server, on: async () => false }, rules: {}, randomBytes: rnd }), { on: false });
});
