/*
 * src/crypto/pkcs8.js - the encrypted PEM copy of a Key Chain key. The judge
 * is not this library: Node's own crypto (OpenSSL) must open every file with
 * the passphrase and find the same key inside.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { encryptedPem, DEFAULT_ITERATIONS } = require('../src/crypto/pkcs8');

const PASS = 'correct horse battery staple, twenty-five+';
const b64u = (s) => Uint8Array.from(Buffer.from(s, 'base64url'));
const pubJwk = (keyObject) => crypto.createPublicKey(keyObject).export({ format: 'jwk' });

test('RSA 2048: OpenSSL opens it and finds the same modulus', async () => {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = privateKey.export({ format: 'jwk' });
  const pem = await encryptedPem({ type: 'rsa', p: b64u(jwk.p), q: b64u(jwk.q) }, PASS, { iterations: 1000 });
  assert.match(pem, /^-----BEGIN ENCRYPTED PRIVATE KEY-----\n/);
  const opened = crypto.createPrivateKey({ key: pem, passphrase: PASS });
  assert.equal(opened.asymmetricKeyType, 'rsa');
  const back = opened.export({ format: 'jwk' });
  assert.equal(back.n, jwk.n);
  /* d is computed mod lambda(n), which may differ from the original's; it must still sign. */
  const sig = crypto.sign('sha256', Buffer.from('key chain'), opened);
  assert.ok(crypto.verify('sha256', Buffer.from('key chain'), crypto.createPublicKey(privateKey), sig));
});

for (const [type, nodeType, opts] of [
  ['ed25519', 'ed25519', undefined],
  ['x25519', 'x25519', undefined],
  ['p256', 'ec', { namedCurve: 'prime256v1' }],
  ['secp256k1', 'ec', { namedCurve: 'secp256k1' }],
]) {
  test(`${type}: OpenSSL opens it and finds the same public key`, async () => {
    const { privateKey } = crypto.generateKeyPairSync(nodeType, opts);
    const jwk = privateKey.export({ format: 'jwk' });
    const pem = await encryptedPem({ type, secret: b64u(jwk.d) }, PASS, { iterations: 1000 });
    const opened = crypto.createPrivateKey({ key: pem, passphrase: PASS });
    assert.deepEqual(pubJwk(opened), pubJwk(privateKey));
  });
}

test('the wrong passphrase does not open it; a short or mismatched one is refused before anything', async () => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const secret = b64u(privateKey.export({ format: 'jwk' }).d);
  const pem = await encryptedPem({ type: 'ed25519', secret }, PASS, { iterations: 1000 });
  assert.throws(() => crypto.createPrivateKey({ key: pem, passphrase: `${PASS}x` }));
  await assert.rejects(encryptedPem({ type: 'ed25519', secret }, 'too short'), /at least 25/);
  await assert.rejects(encryptedPem({ type: 'ed25519', secret }, PASS, { confirm: `${PASS}!` }), /do not match/);
  await assert.rejects(encryptedPem({ type: 'xwing', secret }, PASS), /armored PGP copy/);
});

test('the default is 600000 PBKDF2-SHA256 rounds, and OpenSSL reads them', async () => {
  assert.equal(DEFAULT_ITERATIONS, 600000);
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pem = await encryptedPem({ type: 'p256', secret: b64u(privateKey.export({ format: 'jwk' }).d) }, PASS);
  const opened = crypto.createPrivateKey({ key: pem, passphrase: PASS });
  assert.deepEqual(pubJwk(opened), pubJwk(privateKey));
});

test('keychain.export.encryptedPgp: gpg-style armored copy that openpgp opens only with the passphrase', async () => {
  const openpgp = require('../src/crypto/pgp');
  const { export: kcExport } = require('../keychain/src');
  const { privateKey } = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519', userIDs: [{ name: 'kc' }], format: 'object' });
  const armored = await kcExport.encryptedPgp(privateKey, PASS, { confirm: PASS, openpgp });
  assert.match(armored, /^-----BEGIN PGP PRIVATE KEY BLOCK-----/);
  const read = await openpgp.readPrivateKey({ armoredKey: armored });
  assert.equal(read.isDecrypted(), false, 'the copy is protected');
  await assert.rejects(openpgp.decryptKey({ privateKey: read, passphrase: `${PASS}x` }));
  const opened = await openpgp.decryptKey({ privateKey: read, passphrase: PASS });
  assert.equal(opened.getFingerprint(), privateKey.getFingerprint());
  await assert.rejects(kcExport.encryptedPgp(privateKey, 'short', { openpgp }), /at least 25/);
});
