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

test('a store over the bucket: get, set, remove; an unchanged write keeps its date; a removal archives the value, never deletes it', () => {
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
  assert.deepEqual(s.archivedKeys(), ['theme']);
  assert.equal(b.stores.settings.theme.v, 'light', 'the value is kept, flagged archived (Brad: never deleted)');
  assert.equal(b.stores.settings.theme.archived, true);
  s.setItem('theme', 'dark');
  assert.equal(s.getItem('theme'), 'dark', 'set again, live again');
  assert.equal(bucket.purgeArchived(b, { before: '2099-01-01T00:00:00.000Z' }), 0, 'nothing archived now');
  s.removeItem('theme');
  assert.equal(bucket.purgeArchived(b, { before: '2099-01-01T00:00:00.000Z' }), 1, 'archived values can be purged later');
  assert.equal(b.stores.settings.theme, undefined);
});

test('the clock never goes back: a write is stamped after the newest stamp the bucket has seen, even from a slow clock', () => {
  const b = bucket.create({ owner: 'k1' });
  bucket.kv(b, 'settings', { now: () => '2026-10-25T12:00:00.000Z' }).setItem('lock', '5m');
  /* a device whose clock is an hour behind writes after what it already holds */
  bucket.kv(b, 'settings', { now: () => '2026-10-25T11:00:00.000Z' }).setItem('lock', '1m');
  assert.equal(b.stores.settings.lock.at, '2026-10-25T12:00:00.001Z');
  /* and after what it took in from another copy */
  const other = bucket.create({ owner: 'k1' });
  bucket.kv(other, 'settings', { now: () => '2026-10-25T13:00:00.000Z' }).setItem('font', 'large');
  const merged = bucket.merge(b, other).bucket;
  bucket.kv(merged, 'settings', { now: () => '2026-10-25T11:30:00.000Z' }).setItem('lock', '30m');
  assert.ok(merged.stores.settings.lock.at > '2026-10-25T13:00:00.000Z');
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

test('two copies changed apart merge into the open one: what one lacks is taken, the newer value wins, a later removal wins as archived - nothing asked, either order the same', () => {
  const phone = bucket.create({ owner: 'k1' });
  bucket.kv(phone, 'settings', { now: clock }).setItem('theme', 'dark');
  const web = bucket.parse(bucket.serialize(phone));

  const p = bucket.kv(phone, 'settings', { now: clock });
  const w = bucket.kv(web, 'settings', { now: clock });
  p.setItem('lang', 'en');
  w.setItem('font', 'large');
  p.setItem('theme', 'light');
  w.removeItem('theme'); /* later than the phone's change */
  p.setItem('size', 's');
  w.setItem('size', 'm'); /* later */

  const { bucket: merged, report } = bucket.merge(phone, web);
  const m = bucket.kv(merged, 'settings');
  assert.equal(m.getItem('lang'), 'en');
  assert.equal(m.getItem('font'), 'large', 'taken from the other copy');
  assert.equal(m.getItem('size'), 'm', 'the newer value wins');
  assert.equal(m.getItem('theme'), null, 'the later removal wins');
  assert.deepEqual(m.archivedKeys(), ['theme'], 'kept, archived');
  assert.deepEqual(report.conflicts, [], 'nothing is asked');
  const other = bucket.merge(web, phone).bucket;
  assert.equal(bucket.serialize(other), bucket.serialize(merged), 'imported either way round, the same bucket');
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

/*
 * SEALED TO THE KEY (sealToKey / openWithKey): deviceAge's encrypt and decrypt are handed in - stand-ins here
 * (the X-Wing paths are okcrypto's, tested there). The key is asked only for a bucket of THIS identity.
 */
const fakeAge = () => {
  const asked = [];
  const encrypt = (plain, recipient) => Uint8Array.from([...Buffer.from(String(recipient)), 0, ...plain]);
  const decrypt = async (age, label) => {
    asked.push(label);
    const i = age.indexOf(0);
    if (Buffer.from(age.subarray(0, i)).toString() !== 'R1') throw new Error('not this key');
    return age.subarray(i + 1);
  };
  return { encrypt, decrypt, asked };
};

test('bucket: sealed to the key opens with the key, owner and stores intact', async () => {
  const b = bucket.create({ owner: '51fcbaf7' });
  bucket.kv(b, 'keychain').setItem('list', '[1,2]');
  const { encrypt, decrypt, asked } = fakeAge();
  const text = bucket.sealToKey(b, 'R1', encrypt);
  assert.equal(JSON.parse(text).format, bucket.AGE_FORMAT);
  assert.ok(!text.includes('[1,2]'), 'the stores are not readable in the file');
  const { bucket: back } = await bucket.openWithKey(text, { decrypt, owner: '51fcbaf7' });
  assert.equal(bucket.kv(back, 'keychain').getItem('list'), '[1,2]');
  assert.deepEqual(asked, [bucket.AGE_LABEL]);
});

test('bucket: another identity\'s bucket is refused before the key is asked (no press)', async () => {
  const { encrypt, decrypt, asked } = fakeAge();
  const text = bucket.sealToKey(bucket.create({ owner: '0a87b456' }), 'R1', encrypt);
  await assert.rejects(bucket.openWithKey(text, { decrypt, owner: '51fcbaf7' }), (e) => e.code === 'EBUCKET_NOT_YOURS');
  assert.deepEqual(asked, [], 'the key was never asked');
});

test('bucket: one the key does not open is refused, never read another way', async () => {
  const { encrypt, decrypt } = fakeAge();
  const text = bucket.sealToKey(bucket.create({ owner: '51fcbaf7' }), 'R2', encrypt);
  await assert.rejects(bucket.openWithKey(text, { decrypt, owner: '51fcbaf7' }), (e) => e.code === 'EBUCKET_NOT_OPENED');
});
