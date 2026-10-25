'use strict';

/*
 * The Cryptobox store: only encrypted or signed PGP blocks get in - never a decrypted or unsigned
 * text - threads by contact, newest first, and a damaged blob kept aside.
 */

const test = require('node:test');
const assert = require('node:assert');
const nodeCrypto = require('crypto');

const { store } = require('../src');

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

let clock = 0;
const box = (storage) =>
  store.createCryptobox({
    storage,
    randomBytes: (n) => new Uint8Array(nodeCrypto.randomBytes(n)),
    now: () => new Date(Date.UTC(2026, 9, 18, 12, 0, clock++)),
  });

const ENC = '-----BEGIN PGP MESSAGE-----\n\nwcBMA0xyz\n=abcd\n-----END PGP MESSAGE-----\n';
const SIG = '-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nhello\n-----BEGIN PGP SIGNATURE-----\n\nwsBc\n=efgh\n-----END PGP SIGNATURE-----';

test('keeps encrypted and signed blocks, refuses anything else', async () => {
  const b = box(memoryStorage());
  const a = await b.add({ contact: 'c1', dir: 'out', armored: ENC, signed: true });
  assert.strictEqual(a.kind, 'encrypted');
  assert.strictEqual(a.signed, true);
  const s = await b.add({ contact: 'c1', dir: 'in', armored: SIG });
  assert.strictEqual(s.kind, 'signed');
  assert.strictEqual(s.signed, true);
  await assert.rejects(b.add({ contact: 'c1', dir: 'in', armored: 'hello in the clear' }), /never a decrypted or unsigned text/);
  await assert.rejects(b.add({ contact: 'c1', dir: 'in', armored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxyz\n-----END PGP PUBLIC KEY BLOCK-----' }), /only encrypted or signed/);
  await assert.rejects(b.add({ contact: 'c1', dir: 'in', armored: ENC + ENC }), /only encrypted or signed/);
  await assert.rejects(b.add({ contact: '', dir: 'in', armored: ENC }), /belongs to a thread/);
  await assert.rejects(b.add({ contact: 'c1', dir: 'sideways', armored: ENC }), /'out' or 'in'/);
  assert.strictEqual((await b.load()).messages.length, 2);
});

test('threads: one per contact, newest first; remove and move', async () => {
  const b = box(memoryStorage());
  await b.add({ contact: 'alice', dir: 'out', armored: ENC });
  await b.add({ contact: 'me', dir: 'out', armored: ENC });
  const last = await b.add({ contact: 'alice', dir: 'in', armored: ENC });
  let t = store.threads((await b.load()).messages);
  assert.deepStrictEqual(t.map((x) => [x.contact, x.count]), [['alice', 2], ['me', 1]]);
  assert.strictEqual(t[0].last.id, last.id);
  await b.remove(last.id);
  await b.moveThread('alice', 'alice2');
  await b.removeThread('me');
  t = store.threads((await b.load()).messages);
  assert.deepStrictEqual(t.map((x) => [x.contact, x.count]), [['alice2', 1]]);
});

test('a damaged blob is kept aside and the box starts empty', async () => {
  const storage = memoryStorage();
  storage.map.set(store.KEY, '{not json');
  const r = await box(storage).load();
  assert.strictEqual(r.recovered, true);
  assert.deepStrictEqual(r.messages, []);
  assert.ok([...storage.map.keys()].some((k) => k.startsWith(`${store.KEY}:damaged:`)));
});

test('a removed message is kept, archived - hidden from the list, there for a sync to carry the removal', async () => {
  const s = memoryStorage();
  const b = box(s);
  const m = await b.add({ contact: 'alice', dir: 'out', armored: ENC });
  await b.add({ contact: 'alice', dir: 'out', armored: ENC });
  await b.remove(m.id);
  assert.strictEqual((await b.load()).messages.length, 1, 'the list shows one');
  const raw = JSON.parse(await s.getItem(store.KEY)).messages;
  assert.strictEqual(raw.length, 2, 'the removed one is kept');
  assert.ok(raw.find((x) => x.id === m.id).archived);
  /* a save of the list as shown keeps the archived one too */
  await b.save((await b.load()).messages);
  assert.strictEqual(JSON.parse(await s.getItem(store.KEY)).messages.length, 2);
});
