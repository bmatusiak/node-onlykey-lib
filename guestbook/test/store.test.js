'use strict';

/*
 * The Guest Book store: a round trip through the storage the host passes in, a damaged blob kept
 * aside (never thrown away), keys merged by fingerprint, and PUBLIC ONLY on every save.
 */

const test = require('node:test');
const assert = require('node:assert');
const nodeCrypto = require('crypto');

const age = require('../../src/crypto/age_pqc');
const { store, formats } = require('../src');

function memoryStorage() {
  const map = new Map();
  return {
    map,
    getItem: async (k) => (map.has(k) ? map.get(k) : null),
    setItem: async (k, v) => {
      map.set(k, v);
    },
  };
}

const book = (storage) =>
  store.createGuestBook({ storage, randomBytes: (n) => new Uint8Array(nodeCrypto.randomBytes(n)), now: () => new Date('2026-10-12T12:00:00Z') });

const recipient = (fill) => age.encodeX25519Recipient(Uint8Array.from({ length: 32 }, (_, i) => (i + fill) & 0xff));

test('a contact round-trips through the storage', async () => {
  const storage = memoryStorage();
  const gb = book(storage);
  assert.deepEqual(await gb.load(), { contacts: [], recovered: false });
  const { found } = await formats.detectAll(recipient(1));
  const bob = gb.newContact({ name: 'Bob', found, source: { kind: 'paste', handle: '' } });
  await gb.save([bob]);
  const again = await book(storage).load();
  assert.equal(again.recovered, false);
  assert.equal(again.contacts.length, 1);
  assert.equal(again.contacts[0].name, 'Bob');
  assert.equal(again.contacts[0].keys[0].fingerprint, found[0].fingerprint);
  assert.equal(again.contacts[0].keys[0].verified, false);
  assert.equal(again.contacts[0].history[0].what, 'added from paste');
});

test('a damaged blob is kept aside and the list starts empty, saying so', async () => {
  const storage = memoryStorage();
  storage.map.set(store.KEY, '{not json');
  const r = await book(storage).load();
  assert.equal(r.recovered, true);
  assert.deepEqual(r.contacts, []);
  const kept = [...storage.map.keys()].find((k) => k.startsWith(`${store.KEY}:damaged:`));
  assert.ok(kept, 'the damaged blob was not kept');
  assert.equal(storage.map.get(kept), '{not json');
  /* a version this code does not know is kept the same way */
  storage.map.set(store.KEY, JSON.stringify({ v: 99, contacts: [] }));
  assert.equal((await book(storage).load()).recovered, true);
});

test('more keys: the same fingerprint only gains a source, a new key is added', async () => {
  const gb = book(memoryStorage());
  const first = (await formats.detectAll(recipient(2))).found;
  let c = gb.newContact({ name: 'Carol', found: first, source: { kind: 'paste', handle: '' } });
  c = gb.addKeys(c, first, { kind: 'url', handle: 'https://carol.example/keys' });
  assert.equal(c.keys.length, 1);
  assert.deepEqual(c.keys[0].sources.map((s) => s.kind), ['paste', 'url']);
  c = gb.addKeys(c, (await formats.detectAll(recipient(3))).found, { kind: 'qr', handle: '' });
  assert.equal(c.keys.length, 2);
  c = gb.setVerified(c, c.keys[0].id, true);
  assert.equal(c.keys[0].verified, true);
  assert.equal(c.history[0].what, 'fingerprint verified');
});

test('PUBLIC ONLY: a contact carrying a private field or private text is never saved', async () => {
  const storage = memoryStorage();
  const gb = book(storage);
  const { found } = await formats.detectAll(recipient(4));
  const c = gb.newContact({ name: 'Dave', found, source: { kind: 'paste', handle: '' } });
  await assert.rejects(gb.save([{ ...c, keys: [{ ...c.keys[0], privateKey: 'x' }] }]), /Guest Book holds public data only/);
  await assert.rejects(gb.save([{ ...c, note: '-----BEGIN OPENSSH PRIVATE KEY-----' }]), /Guest Book holds public data only/);
  await assert.rejects(gb.save([{ ...c, keys: [{ ...c.keys[0], text: 'AGE-SECRET-KEY-1ABC' }] }]), /Guest Book holds public data only/);
  assert.equal(storage.map.get(store.KEY), undefined, 'something was written');
});

test('IN PERSON IS VERIFIED: keys from the Bluetooth swap are kept verified; every other way in is not', async () => {
  const gb = book(memoryStorage());
  const swapped = (await formats.detectAll(recipient(4))).found;
  const c = gb.newContact({ name: 'Dan', found: swapped, source: { kind: 'connect', handle: 'peer-id' } });
  assert.equal(c.keys[0].verified, true);
  /* a key pasted first, then handed over in person: the same fingerprint becomes verified */
  const pasted = (await formats.detectAll(recipient(5))).found;
  let e = gb.newContact({ name: 'Eve', found: pasted, source: { kind: 'paste', handle: '' } });
  assert.equal(e.keys[0].verified, false);
  e = gb.addKeys(e, (await formats.detectAll(recipient(6))).found, { kind: 'qr', handle: '' });
  assert.equal(e.keys[1].verified, false, 'a scanned QR of a key is a link, not in person');
  e = gb.addKeys(e, pasted, { kind: 'connect', handle: 'peer-id' });
  assert.equal(e.keys[0].verified, true);
});
