'use strict';

/*
 * Guest Book's format detectors on real keys of every kind (made here with the library's own
 * encoders and the vendored OpenPGP fork, the same code that makes the device's keys), and the
 * PUBLIC ONLY rule: every private form is refused, with a reason, and nothing comes back.
 */

const test = require('node:test');
const assert = require('node:assert');
const nodeCrypto = require('crypto');

const openpgp = require('../../src/crypto/pgp');
const sshPub = require('../../src/crypto/ssh-pub');
const age = require('../../src/crypto/age_pqc');
const { ed25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { formats } = require('../src');

const seed = (n, fill) => Uint8Array.from({ length: n }, (_, i) => (i * 7 + fill) & 0xff);

let pgp = null;
async function pgpPair() {
  if (!pgp) {
    pgp = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519', userIDs: [{ name: 'Alice', email: 'alice@example.com' }], format: 'armored' });
  }
  return pgp;
}

test('OpenPGP: a public block is found, with its primary fingerprint and user id', async () => {
  const { publicKey } = await pgpPair();
  const { found, errors } = await formats.detectAll(`some text before\n${publicKey}\nand after`, { openpgp });
  assert.deepEqual(errors, []);
  assert.equal(found.length, 1);
  const k = found[0];
  assert.equal(k.format, 'openpgp');
  const key = await openpgp.readKey({ armoredKey: publicKey });
  assert.equal(k.fingerprint, key.getFingerprint().toUpperCase());
  assert.equal(k.label, 'Alice <alice@example.com>');
  assert.equal(k.info.revoked, false);
  assert.match(k.text, /BEGIN PGP PUBLIC KEY BLOCK/);
});

test('OpenPGP: a composite post-quantum certificate (Key Chain\'s quantum-safe identity) is found like any other', async () => {
  /* the lib's core maker, not keychain/composite: Guest Book must pass with Key Chain left out */
  const { generateCompositeKey } = require('../../src/crypto/composite_pgp');
  const made = await generateCompositeKey(openpgp, { userId: { name: 'Bob', email: 'bob@example.com' } });
  made.blob.fill(0);
  const { found, errors } = await formats.detectAll(made.armoredPublicKey, { openpgp });
  assert.deepEqual(errors, []);
  assert.equal(found.length, 1);
  assert.equal(found[0].format, 'openpgp');
  const key = await openpgp.readKey({ armoredKey: made.armoredPublicKey });
  assert.equal(found[0].fingerprint, key.getFingerprint().toUpperCase());
  assert.equal(found[0].label, 'Bob <bob@example.com>');
});

test('OpenSSH: ed25519 and nistp256 lines, fingerprinted as ssh-keygen -l does (SHA256 of the blob)', async () => {
  const edPub = ed25519.getPublicKey(seed(32, 1));
  const edLine = sshPub.publicKeyLine('ed25519', edPub, 'alice@laptop');
  const ecPub = p256.getPublicKey(seed(32, 9), false).slice(1); /* X||Y, as the device gives it */
  const ecLine = sshPub.publicKeyLine('nist256p1', ecPub, 'alice@phone');
  const { found } = await formats.detectAll(`${edLine}\n${ecLine}\n`);
  assert.equal(found.length, 2);
  for (const [k, line] of [[found[0], edLine], [found[1], ecLine]]) {
    const blob = Buffer.from(line.split(' ')[1], 'base64');
    const expected = `SHA256:${nodeCrypto.createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;
    assert.equal(k.format, 'ssh');
    assert.equal(k.fingerprint, expected, 'the SSH fingerprint is not what ssh-keygen -l prints');
  }
  assert.equal(found[0].label, 'alice@laptop');
  /* a line whose blob says another type is refused, not trusted */
  const lying = `ecdsa-sha2-nistp256 ${edLine.split(' ')[1]} x`;
  const r = await formats.detectAll(lying);
  assert.equal(r.found.length, 0);
  assert.match(r.errors[0], /says ecdsa-sha2-nistp256 but the key inside is ssh-ed25519/);
});

test('age: an X25519 recipient and an OnlyKey X-Wing recipient (1216 bytes)', async () => {
  const x = age.encodeX25519Recipient(seed(32, 3));
  const xw = age.encodeRecipient(seed(age.XWING_PK, 5));
  const { found } = await formats.detectAll(`${x}\n${xw}`);
  assert.deepEqual(found.map((k) => k.info.kind), ['x25519', 'xwing']);
  const hash = (s) => nodeCrypto.createHash('sha256').update(s).digest('hex').slice(0, 16);
  assert.equal(found[0].fingerprint, hash(x));
  assert.equal(found[1].fingerprint, hash(xw));
  /* an age1onlykey recipient of the wrong length is not an X-Wing key */
  const r = await formats.detectAll(age.encodeRecipient(seed(100, 1)));
  assert.equal(r.found.length, 0);
  assert.match(r.errors[0], /1216 bytes/);
});

test('raw keys: the length only offers curves - the person picks one', async () => {
  const hex = Buffer.from(seed(32, 2)).toString('hex');
  const r = await formats.detectAll(hex);
  assert.deepEqual(r.found, []);
  assert.deepEqual(r.needsCurve.sort(), ['raw-ed25519', 'raw-x25519']);
  const k = formats.readRaw(hex, 'raw-ed25519');
  assert.equal(k.fingerprint, nodeCrypto.createHash('sha256').update(seed(32, 2)).digest('hex').slice(0, 16));
  assert.throws(() => formats.readRaw(hex, 'raw-p256'), /33 or 64 or 65 bytes, this is 32/);
  assert.deepEqual(formats.rawCandidates(65).sort(), ['raw-p256', 'raw-secp256k1']);
  assert.deepEqual(formats.rawCandidates(1216), ['raw-xwing']);
});

test('PUBLIC ONLY: every private form is refused with a reason, nothing found', async () => {
  const { privateKey } = await pgpPair();
  const forms = [
    privateKey,
    '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----',
    'AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ',
    '-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE\n-----END EC PRIVATE KEY-----',
    '-----BEGIN PRIVATE KEY-----\nMC4CAQAw\n-----END PRIVATE KEY-----',
  ];
  for (const text of forms) {
    await assert.rejects(formats.detectAll(text, { openpgp }), (e) => e instanceof formats.PrivateKeyError && /Guest Book holds only public keys/.test(e.message), `not refused: ${text.slice(0, 40)}`);
  }
  /* a private key mixed in with public ones refuses the whole paste */
  const { publicKey } = await pgpPair();
  await assert.rejects(formats.detectAll(`${publicKey}\n${forms[2]}`, { openpgp }), formats.PrivateKeyError);
  /* a block labelled PUBLIC that holds secret key packets is still refused */
  const relabelled = privateKey.replace(/PRIVATE KEY BLOCK/g, 'PUBLIC KEY BLOCK');
  await assert.rejects(formats.readPgpBlock(openpgp, relabelled), formats.PrivateKeyError);
});

test('the same key pasted twice is one find; more than 1 MB is refused', async () => {
  const x = age.encodeX25519Recipient(seed(32, 4));
  const { found } = await formats.detectAll(`${x}\n${x}`);
  assert.equal(found.length, 1);
  await assert.rejects(formats.detectAll('a'.repeat(formats.MAX_TEXT + 1)), /more than 1 MB/);
});
