'use strict';
/*
 * The server's sealed copy (bucket/src/sealedcopy.js; Phase 3): a fresh device catches up from rows it cannot be told
 * apart from, moving only what differs; the server's table names no store and no record and holds no plain hash; a blob
 * moved to another row is refused; the heads row says each Edge log's newest link; a second sync moves nothing.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const bucket = require('../src');
const sealed = require('../src/sealedcopy');
const replicate = require('../src/replicate');

const rnd = (n) => new Uint8Array(crypto.randomBytes(n));
const keys = sealed.keysOf({ secretKey: new Uint8Array(32).fill(5) });
/* the server's room, as rows it keeps and cannot read */
function rowStore() {
  const rows = {};
  let puts = 0;
  return {
    rows,
    get puts() { return puts; },
    async table() { return Object.fromEntries(Object.entries(rows).map(([id, r]) => [id, r.tag])); },
    async get(ids) { return Object.fromEntries(ids.filter((id) => rows[id]).map((id) => [id, rows[id].blob])); },
    async put(r) { puts += Object.keys(r).length; Object.assign(rows, r); },
  };
}
const filled = () => {
  const b = bucket.create({ owner: 'abc' });
  bucket.kv(b, 'guestbook').setItem('myname', 'Pixel Tester');
  bucket.kv(b, 'keychain').setItem('list', '{"format":"onlykey-keychain","version":1,"entries":[]}');
  return b;
};

test('a fresh device catches up from the server: the same bucket, and a second sync moves nothing', async () => {
  const server = rowStore();
  const phone = filled();
  const up = await sealed.syncWith(phone, keys, server, { randomBytes: rnd });
  assert.equal(up.put, 2);
  const fresh = bucket.create({ owner: 'abc' });
  const down = await sealed.syncWith(fresh, keys, server, { randomBytes: rnd });
  assert.equal(down.got, 2);
  assert.equal(bucket.kv(fresh, 'guestbook').getItem('myname'), 'Pixel Tester');
  assert.equal(replicate.stateOf(fresh).hash, replicate.stateOf(phone).hash, 'not the same bucket');
  const again = await sealed.syncWith(fresh, keys, server, { randomBytes: rnd });
  assert.deepEqual([again.got, again.put], [0, 0], 'a second sync moved rows');
  /* one change on the phone: one row up, one row down */
  bucket.kv(phone, 'guestbook').setItem('myname', 'Pixel 6a');
  assert.equal((await sealed.syncWith(phone, keys, server, { randomBytes: rnd })).put, 1);
  assert.equal((await sealed.syncWith(fresh, keys, server, { randomBytes: rnd })).got, 1);
  assert.equal(bucket.kv(fresh, 'guestbook').getItem('myname'), 'Pixel 6a');
});

test('the server holds no name and no plain hash: its table is keyed ids and keyed tags', async () => {
  const server = rowStore();
  const b = filled();
  await sealed.syncWith(b, keys, server, { randomBytes: rnd });
  const text = JSON.stringify(server.rows);
  for (const word of ['guestbook', 'keychain', 'myname', 'Pixel']) assert.ok(!text.includes(word), `the server can read "${word}"`);
  const plain = Object.values(replicate.summarize(b)).flatMap((u) => Object.values(u).map((x) => x.h.slice(0, 32)));
  for (const h of plain) assert.ok(!text.includes(h), 'a plain unit hash is on the server');
  /* another bucket key: other ids for the same records */
  const other = sealed.keysOf({ secretKey: new Uint8Array(32).fill(6) });
  assert.notDeepEqual(Object.keys(sealed.table(b, other).rows).sort(), Object.keys(server.rows).sort());
});

test('a blob the server moved to another row is refused, never taken', async () => {
  const server = rowStore();
  await sealed.syncWith(filled(), keys, server, { randomBytes: rnd });
  const [a, b] = Object.keys(server.rows);
  server.rows[a] = { ...server.rows[a], blob: server.rows[b].blob };
  const fresh = bucket.create({ owner: 'abc' });
  const r = await sealed.syncWith(fresh, keys, server, { randomBytes: rnd });
  assert.equal(r.refused.length, 1);
  assert.match(r.refused[0], /not this row's unit/);
});

test('the heads row: each Edge log\'s newest link, sealed; put again only when it changed', async () => {
  const server = rowStore();
  const b = filled();
  await sealed.syncWith(b, keys, server, { randomBytes: rnd, heads: { aaaaaaaaaaaaaaaa: 124 } });
  const id = sealed.headsId(keys);
  assert.deepEqual(sealed.openHeads(server.rows[id].blob, keys), { aaaaaaaaaaaaaaaa: 124 });
  assert.equal((await sealed.syncWith(b, keys, server, { randomBytes: rnd, heads: { aaaaaaaaaaaaaaaa: 124 } })).put, 0, 'the same heads put again');
  assert.equal((await sealed.syncWith(b, keys, server, { randomBytes: rnd, heads: { aaaaaaaaaaaaaaaa: 130 } })).put, 1);
  assert.deepEqual(sealed.openHeads(server.rows[id].blob, sealed.keysOf({ secretKey: new Uint8Array(32).fill(6) })), {}, 'another bucket key read the heads');
  /* a fresh device never takes the heads row as a unit */
  const fresh = bucket.create({ owner: 'abc' });
  const r = await sealed.syncWith(fresh, keys, server, { randomBytes: rnd });
  assert.deepEqual(r.refused, []);
});
