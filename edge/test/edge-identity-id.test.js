'use strict';

/*
 * B3.0: the identity id every Edge record is filed under (edge.identityId, edge/src/identity-id.js).
 * Two devices of ONE backup (same owner secret, own checkpoint keys) give the same id; a key from
 * ANOTHER backup (another owner secret) a different one; the id is read once per connection.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { fakeKey, edgeOver, OWNER_PUB_PQ } = require('./helpers/fake-edge-key');
const { identityIdOf, isIdentityId } = require('../src/identity-id');

test('identity id: one backup, one id - a sibling device gives the same; another backup a different one', async () => {
  const a = edgeOver(fakeKey());
  const sibling = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey() }));
  const other = edgeOver(fakeKey({ ownerSecret: new Uint8Array(32).fill(0x42) }));
  const idA = await a.identityId();
  assert.ok(isIdentityId(idA), idA);
  assert.equal(idA, identityIdOf(OWNER_PUB_PQ), 'the plugin names it as the pure function does');
  assert.equal(await sibling.identityId(), idA, 'a device restored from the same backup: the same identity');
  assert.notEqual((await a.publicKey()).deviceId.join(), (await sibling.publicKey()).deviceId.join(), '... with its own device id');
  assert.notEqual(await other.identityId(), idA, 'a key from another backup: another identity');
});

test('identity id: read once per connection', async () => {
  const transport = fakeKey();
  let pqReads = 0;
  const write = transport.write.bind(transport);
  /* OKEDGE (0xF8) in byte 4, PUBKEY_PQ (0x05) in byte 5, 1 = the owner key in byte 6 */
  transport.write = (iface, bytes) => { if (bytes[4] === 0xf8 && bytes[5] === 0x05 && bytes[6] === 1) pqReads++; return write(iface, bytes); };
  const edge = edgeOver(transport);
  const first = await edge.identityId();
  assert.equal(await edge.identityId(), first);
  assert.equal(await edge.identityId(), first);
  assert.equal(pqReads, 1, `the owner key is read once per connection, not ${pqReads} times`);
});

test('identity id: only from an ML-DSA-65 public key', () => {
  assert.throws(() => identityIdOf(new Uint8Array(64)), /ML-DSA-65 public key/);
  assert.equal(isIdentityId('ab'.repeat(16)), true);
  assert.equal(isIdentityId('AB'.repeat(16)), false);
});
