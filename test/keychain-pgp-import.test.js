/*
 * Importing a PGP public key back into Key Chain (src/keychain/pgp-import.js):
 * a backup restores the private keys, the .asc file brings the certificate,
 * and nothing lands until the certificate verifies, its keys equal what the
 * slots report, and the slots prove them with a signature and a key exchange.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const openpgp = require('../src/vendor/openpgp/openpgp.js');
const pgpCert = require('../src/crypto/pgp-cert.js');
const keychain = require('../src/keychain');
const { ed25519, x25519 } = require('../src/vendor/exports/@noble/curves/ed25519.js');

const { pgpImport } = keychain;
const SK = new Uint8Array(32).fill(3); /* "ECC2": signing */
const XK = new Uint8Array(32).fill(5); /* "ECC1": decrypt */
const USER_ID = 'Bradley Test <bt@example.com>';

async function certificate(sk = SK, xk = XK) {
  return pgpCert.buildCertificate(openpgp, {
    userId: USER_ID, curve: 'ed25519', created: 1700000000,
    signPublic: ed25519.getPublicKey(sk), ecdhPublic: x25519.getPublicKey(xk),
    sign: async (d) => ed25519.sign(d, sk),
  });
}
/* the slots as Key Chain's readSlots returns them */
const probes = (sk = SK, xk = XK) => [
  { slot: 101, kind: 'x25519', publicKey: x25519.getPublicKey(xk) },
  { slot: 102, kind: 'ed25519', publicKey: ed25519.getPublicKey(sk) },
];
/* the device's hooks, played by the private keys: okcrypto.sign / okcrypto.decrypt */
const hooks = (sk = SK, xk = XK) => {
  const calls = [];
  return {
    calls,
    sign: async (slot, digest) => { calls.push(['sign', slot]); return ed25519.sign(digest, sk); },
    ecdh: async (slot, peer) => { calls.push(['ecdh', slot]); return x25519.getSharedSecret(xk, peer); },
  };
};

test('pgp import: a genuine certificate whose keys are in the slots, proven by both, lands linked to them', async () => {
  const cert = await certificate();
  const info = await pgpImport.inspect(openpgp, cert.armored);
  assert.equal(info.userId, USER_ID);
  assert.equal(info.fingerprint, cert.fingerprint.toUpperCase());
  const match = pgpImport.matchSlots(info, probes());
  assert.deepEqual(match, { signSlot: 102, ecdhSlot: 101 });
  const h = hooks();
  const proven = await pgpImport.proveSlots(info, match, h);
  assert.deepEqual(proven, { sign: true, ecdh: true });
  assert.deepEqual(h.calls, [['sign', 102], ['ecdh', 101]], 'one signature and one key exchange - a press each');
  const made = keychain.list.createEntry(pgpImport.entryFor(info, match, proven));
  assert.deepEqual(made.slots, [101, 102], 'decrypt first, as Key Chain writes a pair made in the key');
  assert.equal(made.kind, 'external');
  assert.match(made.pgp, /BEGIN PGP PUBLIC KEY BLOCK/);
  const back = await openpgp.readKey({ armoredKey: made.pgp });
  assert.equal(back.getFingerprint(), cert.fingerprint.toLowerCase(), 'the SAME certificate - not re-signed (the fingerprint covers the creation time)');
});

test('pgp import: a private key block, garbage, or an edited certificate is refused before any device call', async () => {
  await assert.rejects(pgpImport.inspect(openpgp, '-----BEGIN PGP PRIVATE KEY BLOCK-----\nxx\n-----END PGP PRIVATE KEY BLOCK-----'), /PRIVATE key block/);
  await assert.rejects(pgpImport.inspect(openpgp, 'not a key'), /not a PGP public key/);
  /* the user id swapped after signing: the self-signature no longer covers it */
  const cert = await certificate();
  const key = await openpgp.readKey({ armoredKey: cert.armored });
  key.users[0].userID.userID = 'Mallory <m@example.com>';
  key.users[0].userID.name = 'Mallory';
  await assert.rejects(pgpImport.inspect(openpgp, key.armor()), /does not verify/);
});

test('pgp import: keys that are not in the slots match nothing, ask the key nothing, and land unlinked', async () => {
  const other = await certificate(new Uint8Array(32).fill(7), new Uint8Array(32).fill(9));
  const info = await pgpImport.inspect(openpgp, other.armored);
  const match = pgpImport.matchSlots(info, probes());
  assert.deepEqual(match, { signSlot: null, ecdhSlot: null });
  const h = hooks();
  assert.deepEqual(await pgpImport.proveSlots(info, match, h), { sign: null, ecdh: null });
  assert.equal(h.calls.length, 0);
  assert.equal(keychain.list.createEntry(pgpImport.entryFor(info, match, { sign: null, ecdh: null })).slots, undefined);
});

test('pgp import: a slot that reports the public key but cannot prove it stops the import, naming the check', async () => {
  const cert = await certificate();
  const info = await pgpImport.inspect(openpgp, cert.armored);
  const match = pgpImport.matchSlots(info, probes());
  /* a device that answers with another key's signature / secret */
  const liar = hooks(new Uint8Array(32).fill(11), new Uint8Array(32).fill(13));
  await assert.rejects(pgpImport.proveSlots(info, match, liar), /test signature does not verify/);
  const halfLiar = { sign: hooks().sign, ecdh: liar.ecdh };
  await assert.rejects(pgpImport.proveSlots(info, match, halfLiar), /key exchange does not match/);
});
