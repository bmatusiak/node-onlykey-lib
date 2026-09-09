/*
 * Reading key material out of a real PGP key.
 *
 * test/keys.test.js already covers the extraction rules against hand-built
 * packet fixtures. What it cannot cover is the shape OpenPGP.js actually
 * produces - and that turned out to be the whole problem: fromPgpPacket() was
 * written against v4's flat `params` array, and the vendored PQC fork is v5+,
 * which has no `params` at all. A fixture written from the v4 documentation
 * passes forever while every real key from this fork throws.
 *
 * So these generate keys with the fork that ships in this package and read
 * those. Slow - a few seconds for the ECC pairs - but it is the only version
 * of this test that would have caught the mismatch.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const openpgp = require('../src/crypto/pgp');
const keys = require('../src/device/keys');

const USER = [{ name: 'Backup Test', email: 'backup@example.test' }];

/** A freshly generated key, as an object rather than armored text. */
async function generate(opts) {
  const { privateKey } = await openpgp.generateKey({
    ...opts, userIDs: USER, format: 'object',
  });
  return privateKey;
}

test('an Ed25519 key yields a primary and a decryption subkey', async () => {
  const key = await generate({ type: 'ecc', curve: 'ed25519' });
  const candidates = keys.fromPgpKey(key);

  assert.equal(candidates.length, 2, 'expected primary + one subkey');
  assert.ok(candidates.every((c) => c.kind === 'ecc'));
  assert.ok(
    candidates.every((c) => c.scalar.length === 32),
    'an ECC scalar is 32 bytes; prepareKey rejects anything else',
  );

  /*
   * The primary is Ed25519 and the subkey is Curve25519, and curveFromOid maps
   * BOTH to CURVE.ED25519 - the device stores them the same way. Asserting
   * that here is what stops a future "fix" from splitting them apart.
   */
  assert.deepEqual(
    candidates.map((c) => c.curve),
    [keys.CURVE.ED25519, keys.CURVE.ED25519],
  );
});

test('a NIST P-256 key is read as its own curve', async () => {
  const key = await generate({ type: 'ecc', curve: 'p256' });
  const candidates = keys.fromPgpKey(key);

  assert.equal(candidates.length, 2);
  assert.deepEqual(
    candidates.map((c) => c.curve),
    [keys.CURVE.NIST256P1, keys.CURVE.NIST256P1],
  );
});

test('the secret really is the secret, not the public point', async () => {
  /*
   * The most dangerous way to get this wrong is to read a field that exists
   * and is 32 bytes and is not the private scalar. publicParams.Q is right
   * there next to it. Storing Q would give a device that accepts the key,
   * reports success, and can never decrypt anything.
   */
  const key = await generate({ type: 'ecc', curve: 'ed25519' });
  const [primary] = keys.fromPgpKey(key);

  const priv = key.keyPacket.privateParams;
  const pub = key.keyPacket.publicParams;
  const secret = priv.seed || priv.d;

  assert.deepEqual(Array.from(primary.scalar), Array.from(secret));
  assert.notDeepEqual(
    Array.from(primary.scalar), Array.from(pub.Q).slice(0, 32),
    'the public point was extracted instead of the private scalar',
  );
});

test('the candidate order is the one assignPgpSlots depends on', async () => {
  /*
   * Index 0 is the primary and index 1 the decryption subkey. A two-entry key
   * puts the primary on signature and the subkey on decryption, which is what
   * a Protonmail X25519 layout means (keys.js:228-238).
   */
  const key = await generate({ type: 'ecc', curve: 'ed25519' });
  const candidates = keys.fromPgpKey(key);
  const assigned = keys.assignPgpSlots(candidates);

  const roles = Object.fromEntries(assigned.map((a) => [a.role, a]));
  assert.equal(roles.signature.slot, keys.ROLE_SLOT.SIGNATURE);
  assert.equal(roles.decryption.slot, keys.ROLE_SLOT.DECRYPTION);

  assert.deepEqual(
    Array.from(roles.signature.key.scalar),
    Array.from(candidates[0].scalar),
    'signature should be the primary on a two-key layout',
  );
  assert.deepEqual(
    Array.from(roles.decryption.key.scalar),
    Array.from(candidates[1].scalar),
  );
});

test('an encrypted key says so instead of throwing something opaque', async () => {
  /*
   * privateParams is null until decryptKey() has run, so every field access
   * below it fails. "still encrypted" is a message someone can act on; a
   * TypeError three frames deeper is not.
   */
  const key = await generate({ type: 'ecc', curve: 'ed25519', passphrase: 'hunter2hunter2' });

  assert.throws(
    () => keys.fromPgpKey(key),
    /still encrypted/,
  );

  const unlocked = await openpgp.decryptKey({ privateKey: key, passphrase: 'hunter2hunter2' });
  const candidates = keys.fromPgpKey(unlocked);
  assert.equal(candidates.length, 2);
  assert.equal(candidates[0].scalar.length, 32);
});

test('a key read back from armored text gives the same material', async () => {
  /*
   * The path an import actually takes: the user pastes armor, not an object.
   */
  const key = await generate({ type: 'ecc', curve: 'ed25519' });
  const armored = key.armor();

  const reread = await openpgp.readPrivateKey({ armoredKey: armored });
  assert.deepEqual(
    keys.fromPgpKey(reread).map((c) => Array.from(c.scalar)),
    keys.fromPgpKey(key).map((c) => Array.from(c.scalar)),
  );
});

test('a bad subkey fails the whole key rather than shifting the roles', async () => {
  /*
   * Skipping an unreadable subkey would renumber every later one, and the roles
   * are POSITIONAL - so a dropped subkey silently makes the device sign with
   * its decryption key. Failing loudly is the only safe answer, and the message
   * names which subkey so it can be found.
   */
  const key = await generate({ type: 'ecc', curve: 'ed25519' });

  /* Corrupt the subkey's curve rather than removing it. */
  key.subkeys[0].keyPacket.publicParams.oid = { oid: [1, 2, 3, 4] };

  assert.throws(
    () => keys.fromPgpKey(key),
    /subkey 1: unsupported ECC curve/,
  );
});

test('prepareKey accepts what fromPgpKey produces', async () => {
  /*
   * The two halves have to fit: extraction is only useful if the result is
   * something OKSETPRIV can carry. ECC slots live 100 above RSA's, which
   * prepareKey applies - so this also pins that the slot arithmetic runs.
   */
  const key = await generate({ type: 'ecc', curve: 'ed25519' });
  const [primary] = keys.fromPgpKey(key);

  const prepared = keys.prepareKey(primary, { slot: 2, autoAssign: true });
  assert.equal(prepared.key.length, 32);
  assert.equal(
    prepared.slot, 2 + keys.ECC_SLOT_OFFSET,
    'an ECC key must land in the ECC slot namespace',
  );
  assert.ok(prepared.type & keys.MODIFIER.SIGNATURE, 'slot 2 is the signing role');
});
