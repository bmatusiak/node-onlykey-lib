/*
 * keychain/composite - the composite post-quantum PGP identity: made on the
 * host, loaded into an RSA slot, its certificate kept in the list because the
 * device cannot give it back.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const openpgp = require('../../src/vendor/openpgp/openpgp.js');
const composite = require('../src/composite');
const list = require('../src/list');

const WHO = { name: 'Alice', email: 'alice@example.com' };
const USER = 'Alice <alice@example.com>';

/** The lib's device service, as far as load() uses it. */
function fakeDevice({ refuse } = {}) {
  const calls = [];
  return {
    calls,
    async loadKey(slot, { type, key }) {
      calls.push({ slot, type, key: Uint8Array.from(key) });
      if (refuse) throw new Error(refuse);
      return { response: 'Success' };
    },
  };
}

test('make: a 160-byte private blob and a PUBLIC v6 certificate, with its fingerprint', async () => {
  const made = await composite.make(openpgp, WHO);
  assert.equal(made.blob.length, 160);
  assert.match(made.pgp, /BEGIN PGP PUBLIC KEY BLOCK/);
  const key = await openpgp.readKey({ armoredKey: made.pgp });
  assert.equal(key.isPrivate(), false, 'the certificate carries private material');
  assert.equal(key.getUserIDs()[0], USER);
  assert.equal(made.pgpFingerprint, key.getFingerprint());
  assert.equal(made.pgpFingerprint.length, 64, 'a v6 fingerprint is 32 bytes');
  composite.discard(made);
});

test('load: the blob goes to the slot as type 0x67, then is zeroed; the entry keeps the certificate', async () => {
  const made = await composite.make(openpgp, WHO);
  const blob = made.blob;
  const device = fakeDevice();

  const e = await composite.load(device, 2, made);
  assert.equal(device.calls.length, 1);
  assert.equal(device.calls[0].slot, 2);
  assert.equal(device.calls[0].type, 0x67);
  assert.ok(device.calls[0].key.some((b) => b !== 0), 'an empty blob was loaded');
  assert.ok(blob.every((b) => b === 0), 'the private half is still in memory after the load');
  assert.equal(made.blob, null);

  assert.equal(e.kind, 'slot');
  assert.equal(e.slot, 2);
  assert.equal(e.type, 'composite');
  assert.equal(e.pgp, made.pgp);
  assert.equal(e.pgpFingerprint, made.pgpFingerprint);
  assert.equal(e.name, USER);
  assert.deepEqual(e.artifacts, { pgp: made.pgp }, 'the certificate is its only shareable form');

  await assert.rejects(composite.load(device, 2, made), /already loaded or discarded/);
});

test('a refused load keeps the blob to try again; discard zeroes it', async () => {
  const made = await composite.make(openpgp, WHO);
  const blob = made.blob;
  await assert.rejects(composite.load(fakeDevice({ refuse: 'Error not in config mode' }), 1, made), /config mode/);
  assert.ok(blob.some((b) => b !== 0), 'a refused load lost the key');
  composite.discard(made);
  assert.ok(blob.every((b) => b === 0));
  assert.equal(made.blob, null);
});

test('only an RSA slot (1-4), refused before the device is asked', async () => {
  const made = await composite.make(openpgp, WHO);
  const device = fakeDevice();
  for (const slot of [0, 5, 101, 2.5]) {
    await assert.rejects(composite.load(device, slot, made), /RSA slot/);
  }
  assert.equal(device.calls.length, 0);
  composite.discard(made);
});

test('two composite keys made in one slot are two entries: the new certificate is never merged into the old', async () => {
  const [a, b] = await Promise.all([composite.make(openpgp, WHO), composite.make(openpgp, WHO)]);
  const old = await composite.load(fakeDevice(), 3, a);
  const fresh = await composite.load(fakeDevice(), 3, b);
  assert.notEqual(old.id, fresh.id);
  const merged = list.merge([old], [fresh]);
  assert.equal(merged.added, 1);
  assert.ok(merged.entries.some((e) => e.pgp === fresh.pgp), 'the new certificate was lost');
});

test('the entry survives the file, and a private block in its place is refused', async () => {
  const made = await composite.make(openpgp, WHO);
  const e = await composite.load(fakeDevice(), 4, made);
  const [back] = list.parse(list.serialize([e]));
  assert.equal(back.id, e.id);
  assert.equal(back.pgp, e.pgp);
  assert.equal(back.pgpFingerprint, e.pgpFingerprint);

  const { privateKey } = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519', userIDs: [{ name: 'x' }] });
  assert.throws(() => composite.entry({ slot: 4, pgp: privateKey, pgpFingerprint: e.pgpFingerprint }));
  assert.throws(() => composite.entry({ slot: 4, pgp: e.pgp }), /fingerprint/);
});
