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
const { manager: pm } = require('../../passwords/src');
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

test('Passwords: entries merge one by one, sealed - the same entry changed on both sides, the newer wins; the index is the union of the live ones', async () => {
  let t = 0;
  const now = () => `2026-10-25T00:00:${String(t++).padStart(2, '0')}.000Z`;
  const KEY = new Uint8Array(32).fill(7);
  const rnd = (n) => new Uint8Array(crypto.randomBytes(n));
  const phone = bucket.create({ owner: 'k1' });
  const v = (b) => pm.openStore({ store: pm.prefixedStore(bucket.kv(b, 'passwords', { now }), 's1/'), key: KEY, randomBytes: rnd });
  const mail = await (await v(phone)).put({ kind: 'login', title: 'Mail', username: 'a' });
  const web = copy(phone);
  await (await v(phone)).put({ kind: 'login', title: 'Bank', username: 'b' });
  await (await v(web)).put({ kind: 'login', title: 'Shop', username: 'c' });
  await (await v(phone)).put({ ...mail, username: 'phone' });
  await (await v(web)).put({ ...mail, username: 'web' });

  const { bucket: m, report } = bucket.merge(phone, web, { rules: { passwords: bucket.rules.passwords() } });
  const merged = await v(m);
  assert.deepEqual(merged.list().map((e) => e.title), ['Bank', 'Mail', 'Shop'], 'nothing lost, the index lists all three');
  assert.deepEqual(report.conflicts, []);
  assert.equal(merged.get(mail.id).username, 'web', 'the later edit wins');
  assert.equal(merged.refused().length, 0);
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

/*
 * An edit that is not a key (a note, a name, a phone) changes no key's updatedAt - only the contact's history. The rule
 * read keys alone: a note added on the Windows desktop lost to the A13's copy whenever the A13's blob was written later,
 * and the store never settled (2026-10-25).
 */
test('Guest Book: a details edit (history only) wins over an older copy, on both sides, whatever the blob dates', () => {
  const key = { id: 'k1', format: 'age', text: 'age1x', updatedAt: '2026-10-20T00:00:00.000Z' };
  const base = { id: 'c1', name: 'Qtest', note: 'zz old', keys: [key], history: [{ at: '2026-10-20T00:00:00.000Z', what: 'added from paste' }] };
  const edited = { ...base, note: 'retest', history: [{ at: '2026-10-25T23:42:00.000Z', what: 'details edited' }, ...base.history] };
  const blob = (contacts) => JSON.stringify({ v: 1, contacts });
  /* the phone's blob is the LATER one (written for another contact), the desk's holds the newer edit */
  const phone = { 'guestbook:v1': { v: blob([base]), at: '2026-10-25T23:50:00.000Z' } };
  const desk = { 'guestbook:v1': { v: blob([edited]), at: '2026-10-25T23:42:00.000Z' } };
  const rule = bucket.rules.guestbook();
  const onPhone = JSON.parse(rule(phone, desk).store['guestbook:v1'].v).contacts[0];
  const onDesk = JSON.parse((rule(desk, phone).store['guestbook:v1'] || desk['guestbook:v1']).v).contacts[0];
  assert.equal(onPhone.note, 'retest', 'the phone takes the edit');
  assert.equal(onDesk.note, 'retest', 'the desk keeps it');
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
