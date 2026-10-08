'use strict';
/*
 * The owner statement (Brad, 2026-10-08: "if it has the private ecc key to sign the block,
 * then i want the log"; each device names its own fingerprint with a NAMETAG). A key signs
 * its device id, checkpoint key, seq and nametag hash with an owner key that is the same
 * on every device made from the same backup. Against fake keys (helpers/fake-edge-key.js,
 * which models okplugin_edge statement()).
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { grants, chain } = require('../src');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

/* a device of yours: its own checkpoint key (its own salt), the shared owner key */
const mine = () => edgeOver(fakeKey({ secret: p256.utils.randomSecretKey() }));

test('a statement from another device made with your OnlyKey verifies with YOUR owner key, and names its nametag', async () => {
  const phone = mine();
  const hardKey = mine();
  const myOwner = (await phone.statement('A13')).ownerKey;
  const st = await hardKey.statement('  hard key  ');
  assert.equal(st.nametag, 'hard key', 'trimmed');
  assert.deepEqual([...st.deviceId], [...chain.deviceIdOf(st.publicKey)]);
  assert.equal(grants.verifyStatement(st, myOwner), true);
  assert.notDeepEqual([...st.deviceId], [...(await phone.publicKey()).deviceId], 'two devices, two fingerprints');
});

test('a device NOT made with your OnlyKey: its statement does not verify with your owner key', async () => {
  const myOwner = (await mine().statement('A13')).ownerKey;
  const stranger = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey(), ownerSecret: p256.utils.randomSecretKey() }));
  assert.equal(grants.verifyStatement(await stranger.statement('A13'), myOwner), false);
});

test('change the nametag, the seq, the key or the id and the statement fails', async () => {
  const k = mine();
  const st = await k.statement('Pixel');
  const owner = st.ownerKey;
  assert.equal(grants.verifyStatement(st, owner), true);
  assert.equal(grants.verifyStatement({ ...st, nametag: 'A13' }, owner), false, 'nametag');
  assert.equal(grants.verifyStatement({ ...st, seq: (st.seq ?? 0) + 1 }, owner), false, 'seq');
  const other = p256.getPublicKey(p256.utils.randomSecretKey(), false).slice(1);
  assert.equal(grants.verifyStatement({ ...st, publicKey: other }, owner), false, 'another key under the same id');
  assert.equal(grants.verifyStatement({ ...st, publicKey: other, deviceId: chain.deviceIdOf(other) }, owner), false, 'another key and its id');
  assert.equal(grants.verifyStatement(null, owner), false, 'malformed');
});

test('the statement digest is SHA256("OKEDGE-STATEMENT-v1" || id || key || seq u32 LE || nametag hash), computed with node:crypto', () => {
  const id = new Uint8Array(16).fill(1);
  const key = new Uint8Array(64).fill(2);
  const nh = grants.nametagHash('A13');
  const want = crypto.createHash('sha256').update(Buffer.concat([Buffer.from('OKEDGE-STATEMENT-v1'), id, key, Buffer.from([7, 1, 0, 0]), nh])).digest();
  assert.deepEqual([...grants.statementDigest({ deviceId: id, publicKey: key, seq: 263, nametagHash: nh })], [...want]);
  const wantTag = crypto.createHash('sha256').update(Buffer.concat([Buffer.from('OKEDGE-NAMETAG-v1'), Buffer.from('A13', 'utf8')])).digest();
  assert.deepEqual([...nh], [...wantTag]);
});

test('a nametag: trimmed, 1 to 64 characters', () => {
  assert.deepEqual([...grants.nametagHash(' A13 ')], [...grants.nametagHash('A13')]);
  assert.throws(() => grants.nametagHash('   '), TypeError);
  assert.throws(() => grants.nametagHash('x'.repeat(65)), RangeError);
  assert.doesNotThrow(() => grants.nametagHash('é'.repeat(64)));
});
