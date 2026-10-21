'use strict';

/*
 * The bucket (PROPOSAL-one-gui.md): every store a front end keeps, in one file that is sealed by the
 * key and moves between the phone, the desktop, the web page and the CLI. Written one way, read
 * every way: a real lib store over the bucket's seam, sealed and opened, two diverged copies merged.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

const bucket = require('../src');
const { createPointerStore } = require('../../edge/src/store');

const KEY = new Uint8Array(32).fill(7);
const OTHER = new Uint8Array(32).fill(9);
const rnd = (n) => new Uint8Array(crypto.randomBytes(n));
let tick = 0;
const clock = () => `2026-10-21T00:00:${String(tick++).padStart(2, '0')}.000Z`;

test('a store over the bucket: get, set, remove; an unchanged write keeps its date; a removal stays as a dated marker', () => {
  const b = bucket.create({ owner: 'k1' });
  const s = bucket.kv(b, 'settings', { now: clock });
  assert.equal(s.getItem('theme'), null);
  s.setItem('theme', 'dark');
  const first = b.stores.settings.theme.at;
  s.setItem('theme', 'dark');
  assert.equal(b.stores.settings.theme.at, first, 'same value, same date: the date is when it changed');
  s.setItem('theme', 'light');
  assert.notEqual(b.stores.settings.theme.at, first);
  s.removeItem('theme');
  assert.equal(s.getItem('theme'), null);
  assert.deepEqual(s.keys(), []);
  assert.equal(b.stores.settings.theme.v, null, 'kept as a removal, with its date');
});

test('a lib store runs unchanged on the bucket: Edge budget pointers written, serialized, read back', async () => {
  const b = bucket.create({ owner: 'k1' });
  const pointers = createPointerStore(bucket.kv(b, 'edge.pointers'));
  await pointers.setBudget('ab'.repeat(16), 21);
  const back = bucket.parse(bucket.serialize(b));
  assert.equal(await createPointerStore(bucket.kv(back, 'edge.pointers')).budget('ab'.repeat(16)), 21, 'a number stays a number');
  assert.equal(bucket.serialize(back), bucket.serialize(b), 'the same bucket is the same text');
});

test('sealed by the key: opens with it; another key, no key, a changed byte - each refused with its reason', () => {
  const b = bucket.create({ owner: 'k1' });
  bucket.kv(b, 'keychain').setItem('list', '{"entries":[]}');
  const file = bucket.seal(b, KEY, rnd);
  assert.doesNotMatch(file, /entries/, 'nothing readable outside the seal');

  const opened = bucket.open(file, { key: KEY });
  assert.equal(opened.sealed, true);
  assert.equal(bucket.kv(opened.bucket, 'keychain').getItem('list'), '{"entries":[]}');

  assert.throws(() => bucket.open(file, { key: OTHER }), { code: 'EBUCKET_NOT_YOURS' });
  assert.throws(() => bucket.open(file), { code: 'EBUCKET_KEY' });
  const outer = JSON.parse(file);
  const raw = Buffer.from(outer.blob, 'base64');
  raw[raw.length - 1] ^= 1;
  assert.throws(() => bucket.open(JSON.stringify({ ...outer, blob: raw.toString('base64') }), { key: KEY }), { code: 'EBUCKET_NOT_YOURS' });
  assert.throws(() => bucket.open(JSON.stringify({ ...outer, owner: 'k2' }), { key: KEY }), { code: 'EBUCKET_FORMAT' }, 'the owner label cannot be swapped');
});

test('unsealed (development): refused unless the host allows it, and then it says so', () => {
  const b = bucket.create();
  bucket.kv(b, 'settings').setItem('x', '1');
  const text = bucket.serialize(b);
  assert.throws(() => bucket.open(text, { key: KEY }), { code: 'EBUCKET_UNSEALED' });
  const r = bucket.open(text, { allowUnsealed: true });
  assert.equal(r.sealed, false);
  assert.throws(() => bucket.parse('{"format":"other"}'), { code: 'EBUCKET_FORMAT' });
  assert.throws(() => bucket.parse('{"format":"onlykey-bucket","v":9,"stores":{}}'), { code: 'EBUCKET_VERSION' });
  assert.throws(() => bucket.parse('{"format":"onlykey-bucket","v":1,"stores":{"s":{"k":{"v":1}}}}'), { code: 'EBUCKET_FORMAT' });
});

test('two copies changed apart merge: what one lacks is taken, a value both changed (or one removed) is a conflict with both dates; the pick is the person\'s', () => {
  const phone = bucket.create({ owner: 'k1' });
  bucket.kv(phone, 'settings', { now: clock }).setItem('theme', 'dark');
  const web = bucket.parse(bucket.serialize(phone));

  const p = bucket.kv(phone, 'settings', { now: clock });
  const w = bucket.kv(web, 'settings', { now: clock });
  p.setItem('lang', 'en');
  w.setItem('font', 'large');
  p.setItem('theme', 'light');
  w.removeItem('theme');

  const { bucket: merged, report } = bucket.merge(phone, web);
  const m = bucket.kv(merged, 'settings');
  assert.equal(m.getItem('lang'), 'en');
  assert.equal(m.getItem('font'), 'large', 'taken from the other copy');
  assert.equal(report.taken.settings, 1);
  assert.equal(report.conflicts.length, 1);
  const [c] = report.conflicts;
  assert.equal(c.store, 'settings');
  assert.equal(c.key, 'theme');
  assert.deepEqual([c.into.v, c.from.v], ['light', null], 'a removal is a value too');
  assert.ok(c.into.at && c.from.at, 'both dates, to decide by');
  assert.equal(m.getItem('theme'), 'light', 'unchanged until the person picks');

  bucket.resolve(merged, c, 'from');
  assert.equal(bucket.kv(merged, 'settings').getItem('theme'), null);
});

test('a store can bring its own merge rule; buckets of two keys do not merge', () => {
  const a = bucket.create({ owner: 'k1' });
  const b = bucket.create({ owner: 'k1' });
  bucket.kv(a, 'log').setItem('1', 'x');
  bucket.kv(b, 'log').setItem('2', 'y');
  let called = 0;
  const { bucket: m } = bucket.merge(a, b, { rules: { log: (into, from) => { called += 1; return bucket.mergeKeys(into, from); } } });
  assert.equal(called, 1);
  assert.deepEqual(bucket.kv(m, 'log').keys().sort(), ['1', '2']);
  assert.throws(() => bucket.merge(a, bucket.create({ owner: 'k2' })), { code: 'EBUCKET_OWNER' });
});
