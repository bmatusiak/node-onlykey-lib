'use strict';

/*
 * The merge rule of each store (PROPOSAL-one-gui.md, "Merge: one rule, per store"): the real store
 * writes through the bucket's seam on two copies that then go apart, and importing one into the
 * other takes what it lacks, reports what both changed, and drops nothing.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

const bucket = require('../src');
const list = require('../../keychain/src/list');
const { createVaultStore } = require('../../src/crypto/vault_store');
const { createGuestBook } = require('../../guestbook/src/store');

const rnd = (n) => new Uint8Array(crypto.randomBytes(n));
const copy = (b) => bucket.parse(bucket.serialize(b));
const entry = (label, fill) => list.createEntry({ kind: 'derived', scheme: 'gpg', label, type: 'ed25519', publicKey: new Uint8Array(32).fill(fill) });

test('Key Chain: entries from both copies, by the list\'s own merge; no conflicts - two records of one key combine', () => {
  const phone = bucket.create({ owner: 'k1' });
  bucket.kv(phone, 'keychain').setItem('list', list.serialize([entry('A <a@x>', 1)]));
  const web = copy(phone);
  bucket.kv(phone, 'keychain').setItem('list', list.serialize([entry('A <a@x>', 1), entry('B <b@x>', 2)]));
  bucket.kv(web, 'keychain').setItem('list', list.serialize([entry('A <a@x>', 1), entry('C <c@x>', 3)]));
  const { bucket: m, report } = bucket.merge(phone, web, { rules: { keychain: bucket.rules.keychain(list) } });
  const labels = list.parse(bucket.kv(m, 'keychain').getItem('list')).map((e) => e.label).sort();
  assert.deepEqual(labels, ['A <a@x>', 'B <b@x>', 'C <c@x>']);
  assert.equal(report.taken.keychain, 1);
  assert.equal(report.conflicts.length, 0);
});

test('Passwords: credentials merge one by one - the same entry changed on both sides, the newer wins; the index is the union of the live ones', async () => {
  let t = 0;
  const now = () => `2026-10-25T00:00:${String(t++).padStart(2, '0')}.000Z`;
  const phone = bucket.create({ owner: 'k1' });
  const v = (b) => createVaultStore({ store: bucket.kv(b, 'passwords', { now }) });
  await v(phone).put({ serviceId: 'mail', encrypted: 'sealed-1' });
  const web = copy(phone);
  await v(phone).put({ serviceId: 'bank', encrypted: 'sealed-2' });
  await v(web).put({ serviceId: 'shop', encrypted: 'sealed-3' });
  await v(phone).put({ serviceId: 'mail', encrypted: 'sealed-1-phone' });
  await v(web).put({ serviceId: 'mail', encrypted: 'sealed-1-web' });

  const { bucket: m, report } = bucket.merge(phone, web, { rules: { passwords: bucket.rules.passwords() } });
  const ids = (await v(m).list()).map((r) => r.serviceId).sort();
  assert.deepEqual(ids, ['bank', 'mail', 'shop'], 'nothing lost, the index lists all three');
  assert.deepEqual(report.conflicts, []);
  assert.equal((await v(m).list()).find((r) => r.serviceId === 'mail').encrypted, 'sealed-1-web', 'the later edit wins');
});

test('Guest Book: contacts by id - new ones added from both copies, one changed on both sides taken from the later copy, inside the blob', async () => {
  let t = 0;
  const now = () => `2026-10-25T00:01:${String(t++).padStart(2, '0')}.000Z`;
  const phone = bucket.create({ owner: 'k1' });
  const gb = (b) => createGuestBook({ storage: bucket.kv(b, 'guestbook', { now }), randomBytes: rnd });
  await gb(phone).save([{ id: 'c1', name: 'Ann' }]);
  const web = copy(phone);
  await gb(phone).save([{ id: 'c1', name: 'Ann B' }, { id: 'c2', name: 'Bob' }]);
  await gb(web).save([{ id: 'c1', name: 'Annie' }, { id: 'c3', name: 'Cy' }]); /* later */

  const rules = { guestbook: bucket.rules.guestbook() };
  const { bucket: m, report } = bucket.merge(phone, web, { rules });
  const { contacts } = await gb(m).load();
  assert.deepEqual(contacts.map((c) => c.id).sort(), ['c1', 'c2', 'c3'], 'an entry added on one device is never lost');
  assert.equal(contacts.find((c) => c.id === 'c1').name, 'Annie', 'the later edit of the same contact wins');
  assert.deepEqual(report.conflicts, []);
  const back = bucket.merge(web, phone, { rules }).bucket;
  assert.deepEqual((await gb(back).load()).contacts.map((c) => [c.id, c.name]).sort(), contacts.map((c) => [c.id, c.name]).sort());
});

test('Settings: the generic rule - a setting both changed takes the later value, nothing asked', () => {
  const a = bucket.create({ owner: 'k1' });
  bucket.kv(a, 'settings', { now: () => '2026-10-20T10:00:00.000Z' }).setItem('lock', '5m');
  const b = copy(a);
  bucket.kv(a, 'settings', { now: () => '2026-10-21T09:00:00.000Z' }).setItem('lock', '1m');
  bucket.kv(b, 'settings', { now: () => '2026-10-21T11:00:00.000Z' }).setItem('lock', '30m');
  const { bucket: m, report } = bucket.merge(a, b, { rules: { settings: bucket.rules.settings } });
  assert.deepEqual(report.conflicts, []);
  assert.equal(bucket.kv(m, 'settings').getItem('lock'), '30m');
});

/*
 * The Cryptobox: messages written on two devices join; one removed on either side stays removed; both sides end with
 * the same value, whichever merges (the bucket states match).
 */
test('cryptobox: messages join by id, a removal stays, both sides end the same', () => {
  const blob = (messages) => JSON.stringify({ v: 1, messages });
  const msg = (id, at, extra = {}) => ({ id, contact: 'me', dir: 'out', armored: '-----BEGIN PGP MESSAGE-----\nx\n-----END PGP MESSAGE-----', kind: 'encrypted', signed: false, at, ...extra });
  const phone = { 'cryptobox:v1': { v: blob([msg('a', '2026-10-25T01:00:00Z'), msg('p', '2026-10-25T03:00:00Z')]), at: '2026-10-25T03:00:00.000Z' } };
  const desk = { 'cryptobox:v1': { v: blob([msg('a', '2026-10-25T01:00:00Z', { archived: true, archivedAt: '2026-10-25T02:30:00Z' }), msg('d', '2026-10-25T02:00:00Z')]), at: '2026-10-25T02:30:00.000Z' } };
  const rule = bucket.rules.cryptobox();
  const onPhone = rule(phone, desk).store['cryptobox:v1'];
  const onDesk = rule(desk, phone).store['cryptobox:v1'];
  assert.equal(onPhone.v, onDesk.v, 'the same value on both');
  const ids = JSON.parse(onPhone.v).messages.map((m) => `${m.id}${m.archived ? '-' : ''}`);
  assert.deepEqual(ids, ['a-', 'd', 'p']);
});
