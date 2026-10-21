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

test('Passwords: credentials merge one by one - the same entry changed on both sides is a conflict; the index is the union, not a choice', async () => {
  const phone = bucket.create({ owner: 'k1' });
  const v = (b) => createVaultStore({ store: bucket.kv(b, 'passwords') });
  await v(phone).put({ serviceId: 'mail', encrypted: 'sealed-1' });
  const web = copy(phone);
  await v(phone).put({ serviceId: 'bank', encrypted: 'sealed-2' });
  await v(web).put({ serviceId: 'shop', encrypted: 'sealed-3' });
  await v(phone).put({ serviceId: 'mail', encrypted: 'sealed-1-phone' });
  await v(web).put({ serviceId: 'mail', encrypted: 'sealed-1-web' });

  const { bucket: m, report } = bucket.merge(phone, web, { rules: { passwords: bucket.rules.passwords() } });
  const ids = (await v(m).list()).map((r) => r.serviceId).sort();
  assert.deepEqual(ids, ['bank', 'mail', 'shop'], 'nothing lost, the index lists all three');
  assert.equal(report.conflicts.length, 1);
  assert.match(report.conflicts[0].key, /credentials\/mail$/);
  bucket.resolve(m, report.conflicts[0], 'from');
  assert.equal((await v(m).list()).find((r) => r.serviceId === 'mail').encrypted, 'sealed-1-web');
});

test('Guest Book: contacts by id - new ones added, one changed on both sides is a conflict the person picks, applied inside the blob', async () => {
  const phone = bucket.create({ owner: 'k1' });
  const gb = (b) => createGuestBook({ storage: bucket.kv(b, 'guestbook'), randomBytes: rnd });
  await gb(phone).save([{ id: 'c1', name: 'Ann' }]);
  const web = copy(phone);
  await gb(phone).save([{ id: 'c1', name: 'Ann B' }, { id: 'c2', name: 'Bob' }]);
  await gb(web).save([{ id: 'c1', name: 'Annie' }, { id: 'c3', name: 'Cy' }]);

  const { bucket: m, report } = bucket.merge(phone, web, { rules: { guestbook: bucket.rules.guestbook() } });
  let { contacts } = await gb(m).load();
  assert.deepEqual(contacts.map((c) => c.id).sort(), ['c1', 'c2', 'c3']);
  assert.equal(contacts.find((c) => c.id === 'c1').name, 'Ann B', 'this copy stays until the pick');
  assert.equal(report.conflicts.length, 1);
  bucket.resolve(m, report.conflicts[0], 'from');
  ({ contacts } = await gb(m).load());
  assert.equal(contacts.find((c) => c.id === 'c1').name, 'Annie');
  assert.equal(contacts.length, 3, 'the pick replaced one contact, nothing else');
});

test('Settings: the generic rule - a setting both changed comes back with both values and dates', () => {
  const a = bucket.create({ owner: 'k1' });
  bucket.kv(a, 'settings', { now: () => '2026-10-20T10:00:00.000Z' }).setItem('lock', '5m');
  const b = copy(a);
  bucket.kv(a, 'settings', { now: () => '2026-10-21T09:00:00.000Z' }).setItem('lock', '1m');
  bucket.kv(b, 'settings', { now: () => '2026-10-21T11:00:00.000Z' }).setItem('lock', '30m');
  const { report } = bucket.merge(a, b, { rules: { settings: bucket.rules.settings } });
  assert.deepEqual(report.conflicts.map((c) => [c.key, c.into.v, c.into.at, c.from.v, c.from.at]),
    [['lock', '1m', '2026-10-21T09:00:00.000Z', '30m', '2026-10-21T11:00:00.000Z']]);
});
