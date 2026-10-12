'use strict';

/*
 * The pinning rule on real PGP keys (the vendored OpenPGP fork): the same key merges - a new
 * subkey, a later expiry, a revocation - and a different key is never merged, only reported.
 */

const test = require('node:test');
const assert = require('node:assert');

const openpgp = require('../../src/crypto/pgp');
const age = require('../../src/crypto/age_pqc');
const { formats, merge } = require('../src');

const find = async (text) => (await formats.detectAll(text, { openpgp })).found[0];

let alice = null;
async function aliceKey() {
  if (!alice) {
    alice = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519', userIDs: [{ name: 'Alice', email: 'alice@example.com' }], keyExpirationTime: 3600 * 24 * 365, format: 'object', date: new Date(Date.now() - 3600 * 1000) }); /* made an hour ago: a later self-signature is newer */
  }
  return alice;
}

test('same key, same copy: same', async () => {
  const { publicKey } = await aliceKey();
  const pinned = await find(publicKey.armor());
  assert.deepEqual(await merge.classify(pinned, await find(publicKey.armor()), { openpgp }), { result: 'same' });
});

test('same key with a new subkey: updated, merged', async () => {
  const { privateKey, publicKey } = await aliceKey();
  const pinned = await find(publicKey.armor());
  const withSub = await privateKey.addSubkey({ type: 'ecc', curve: 'curve25519' });
  const fetched = await find(withSub.toPublic().armor());
  const r = await merge.classify(pinned, fetched, { openpgp });
  assert.equal(r.result, 'updated');
  const merged = await openpgp.readKey({ armoredKey: r.text });
  assert.equal(merged.getFingerprint(), (await openpgp.readKey({ armoredKey: pinned.text })).getFingerprint(), 'the pin moved');
  assert.equal(merged.getSubkeys().length, 2);
});

test('same key with a later expiry: updated', async () => {
  const { privateKey, publicKey } = await aliceKey();
  const pinned = await find(publicKey.armor());
  const later = await openpgp.reformatKey({ privateKey, userIDs: [{ name: 'Alice', email: 'alice@example.com' }], keyExpirationTime: 3600 * 24 * 365 * 3, format: 'object' });
  const r = await merge.classify(pinned, await find(later.publicKey.armor()), { openpgp });
  assert.equal(r.result, 'updated');
  const before = await (await openpgp.readKey({ armoredKey: pinned.text })).getExpirationTime();
  const after = await (await openpgp.readKey({ armoredKey: r.text })).getExpirationTime();
  assert.ok(after > before, 'the merged copy does not carry the later expiry');
});

test('same key, now revoked: revoked, merged (a revocation is never ignored)', async () => {
  const { privateKey, publicKey } = await aliceKey();
  const pinned = await find(publicKey.armor());
  const { publicKey: revoked } = await openpgp.revokeKey({ key: privateKey, format: 'armored' });
  const r = await merge.classify(pinned, await find(revoked), { openpgp });
  assert.equal(r.result, 'revoked');
  assert.equal(await (await openpgp.readKey({ armoredKey: r.text })).isRevoked(), true);
});

test('a different key: changed, never merged', async () => {
  const { publicKey } = await aliceKey();
  const other = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519', userIDs: [{ name: 'Alice', email: 'alice@example.com' }], format: 'armored' });
  const r = await merge.classify(await find(publicKey.armor()), await find(other.publicKey), { openpgp });
  assert.deepEqual(r, { result: 'changed' });
});

test('age, SSH, raw: the fingerprint is the whole key - same or changed', async () => {
  const a = await find(age.encodeX25519Recipient(new Uint8Array(32).fill(1)));
  const b = await find(age.encodeX25519Recipient(new Uint8Array(32).fill(2)));
  assert.deepEqual(await merge.classify(a, a), { result: 'same' });
  assert.deepEqual(await merge.classify(a, b), { result: 'changed' });
});
