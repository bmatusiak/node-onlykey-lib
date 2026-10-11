'use strict';
/*
 * The owner statement (Brad, 2026-10-08: "if it has the private ecc key to sign the block,
 * then i want the log"; each device names its own fingerprint with a NAMETAG). A key signs
 * its device id, checkpoint key, seq and nametag hash with an owner key that is the same
 * on every device made from the same backup. Against fake keys (helpers/fake-edge-key.js,
 * which models okplugin_edge statement()). The hybrid (2026-10-10): the statement names the
 * ML-DSA-65 checkpoint key too (its SHA-256 in the digest) and is signed by the owner P-256
 * key AND the owner ML-DSA-65 key - a verifier needs both.
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
  const { ownerKey: myOwner, ownerKeyPq: myOwnerPq } = await phone.statement('A13');
  const st = await hardKey.statement('  hard key  ');
  assert.equal(st.nametag, 'hard key', 'trimmed');
  assert.deepEqual([...st.deviceId], [...chain.deviceIdOf(st.publicKey)]);
  assert.equal(st.publicKeyPq.length, chain.ML_DSA65.PK);
  assert.equal(st.signaturePq.length, chain.ML_DSA65.SIG);
  assert.deepEqual([...st.ownerKeyPq], [...myOwnerPq], 'the owner ML-DSA-65 key is the same on every device of the backup');
  assert.deepEqual([...st.publicKeyPq], [...(await hardKey.publicKeyPq('checkpoint'))]);
  assert.equal(grants.verifyStatement(st, myOwner, myOwnerPq), true);
  assert.notDeepEqual([...st.deviceId], [...(await phone.publicKey()).deviceId], 'two devices, two fingerprints');
});

test('a device NOT made with your OnlyKey: its statement does not verify with your owner key', async () => {
  const { ownerKey: myOwner, ownerKeyPq: myOwnerPq } = await mine().statement('A13');
  const stranger = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey(), ownerSecret: p256.utils.randomSecretKey() }));
  assert.equal(grants.verifyStatement(await stranger.statement('A13'), myOwner, myOwnerPq), false);
});

test('change the nametag, the seq, the key or the id and the statement fails', async () => {
  const k = mine();
  const st = await k.statement('Pixel');
  const owner = st.ownerKey;
  const ownerPq = st.ownerKeyPq;
  assert.equal(grants.verifyStatement(st, owner, ownerPq), true);
  assert.equal(grants.verifyStatement({ ...st, nametag: 'A13' }, owner, ownerPq), false, 'nametag');
  assert.equal(grants.verifyStatement({ ...st, seq: (st.seq ?? 0) + 1 }, owner, ownerPq), false, 'seq');
  const other = p256.getPublicKey(p256.utils.randomSecretKey(), false).slice(1);
  assert.equal(grants.verifyStatement({ ...st, publicKey: other }, owner, ownerPq), false, 'another key under the same id');
  assert.equal(grants.verifyStatement({ ...st, publicKey: other, deviceId: chain.deviceIdOf(other) }, owner, ownerPq), false, 'another key and its id');
  /* the ML-DSA-65 checkpoint key is in the digest: another one fails */
  const otherPq = chain.mlDsaKeys(new Uint8Array(32).fill(0x44)).publicKey;
  assert.equal(grants.verifyStatement({ ...st, publicKeyPq: otherPq }, owner, ownerPq), false, 'another ML-DSA-65 checkpoint key');
  assert.equal(grants.verifyStatement(null, owner, ownerPq), false, 'malformed');
});

test('the hybrid: a statement whose ML-DSA-65 signature is missing or wrong, or checked without the owner ML-DSA-65 key, fails', async () => {
  const st = await mine().statement('Pixel');
  const { ownerKey: owner, ownerKeyPq: ownerPq } = st;
  assert.equal(grants.verifyStatement(st, owner, ownerPq), true);
  /* missing: the P-256 half alone (the shape before the hybrid) - no fallback */
  const { signaturePq: _none, ...p256Only } = st;
  assert.equal(grants.verifyStatement(p256Only, owner, ownerPq), false, 'no ML-DSA-65 signature');
  assert.equal(grants.verifyStatement({ ...st, signaturePq: new Uint8Array(0) }, owner, ownerPq), false, 'an empty one');
  /* wrong: one flipped bit, or a valid ML-DSA-65 signature from another owner */
  const flipped = Uint8Array.from(st.signaturePq);
  flipped[1234] ^= 0x01;
  assert.equal(grants.verifyStatement({ ...st, signaturePq: flipped }, owner, ownerPq), false, 'a flipped bit');
  const stranger = await edgeOver(fakeKey({ secret: p256.utils.randomSecretKey(), ownerSecret: p256.utils.randomSecretKey() })).statement('Pixel');
  assert.equal(grants.verifyStatement({ ...st, signaturePq: stranger.signaturePq }, owner, ownerPq), false, 'another owner\'s ML-DSA-65 signature');
  /* the verifier's own owner ML-DSA-65 key is required */
  assert.equal(grants.verifyStatement(st, owner), false, 'no owner ML-DSA-65 key');
  assert.equal(grants.verifyStatement(st, owner, stranger.ownerKeyPq), false, 'another owner ML-DSA-65 key');
  /* the statement without its ML-DSA-65 checkpoint key cannot even be digested */
  assert.equal(grants.verifyStatement({ ...st, publicKeyPq: undefined }, owner, ownerPq), false, 'no ML-DSA-65 checkpoint key');
});

test('the statement digest is SHA256("OKEDGE-STATEMENT-v1" || id || key || SHA256(pq key) || seq u32 LE || nametag hash), computed with node:crypto', () => {
  const id = new Uint8Array(16).fill(1);
  const key = new Uint8Array(64).fill(2);
  const keyPq = new Uint8Array(chain.ML_DSA65.PK).fill(3);
  const nh = grants.nametagHash('A13');
  const pqHash = crypto.createHash('sha256').update(keyPq).digest();
  const want = crypto.createHash('sha256').update(Buffer.concat([Buffer.from('OKEDGE-STATEMENT-v1'), id, key, pqHash, Buffer.from([7, 1, 0, 0]), nh])).digest();
  assert.deepEqual([...grants.statementDigest({ deviceId: id, publicKey: key, publicKeyPq: keyPq, seq: 263, nametagHash: nh })], [...want]);
  /* the digest commits to the ML-DSA-65 checkpoint key: another one, another digest */
  const keyPq2 = Uint8Array.from(keyPq);
  keyPq2[1951] ^= 1;
  assert.notDeepEqual([...grants.statementDigest({ deviceId: id, publicKey: key, publicKeyPq: keyPq2, seq: 263, nametagHash: nh })], [...want]);
  /* and it has to be there, at its full length */
  assert.throws(() => grants.statementDigest({ deviceId: id, publicKey: key, seq: 263, nametagHash: nh }), TypeError);
  assert.throws(() => grants.statementDigest({ deviceId: id, publicKey: key, publicKeyPq: keyPq.slice(1), seq: 263, nametagHash: nh }), TypeError);
  const wantTag = crypto.createHash('sha256').update(Buffer.concat([Buffer.from('OKEDGE-NAMETAG-v1'), Buffer.from('A13', 'utf8')])).digest();
  assert.deepEqual([...nh], [...wantTag]);
});

test('a nametag: trimmed, 1 to 64 characters', () => {
  assert.deepEqual([...grants.nametagHash(' A13 ')], [...grants.nametagHash('A13')]);
  assert.throws(() => grants.nametagHash('   '), TypeError);
  assert.throws(() => grants.nametagHash('x'.repeat(65)), RangeError);
  assert.doesNotThrow(() => grants.nametagHash('é'.repeat(64)));
});
