'use strict';

/*
 * The self-signed X.509 certificate for an OnlyKey RSA slot (src/crypto/x509.js), checked by node's own X.509 parser:
 * the key's side stood in by a node RSA key signing the way the firmware does - PKCS#1 v1.5 over the DigestInfo of the
 * digest it is handed (SHA-512 for 64 bytes, SHA-256 for 32) - so a certificate node verifies is one the key's
 * signature makes.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const x509 = require('../src/crypto/x509');

/* RFC 8017 9.2 DigestInfo prefixes: what the key puts before the digest it is given */
const DIGEST_INFO = {
  32: Buffer.from('3031300d060960864801650304020105000420', 'hex'),
  64: Buffer.from('3051300d060960864801650304020305000440', 'hex'),
};
function keyOf(bits) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: bits, publicExponent: 65537 });
  const modulus = Buffer.from(publicKey.export({ format: 'jwk' }).n, 'base64url');
  const signs = [];
  /* the firmware's RSA sign: the digest it is handed, its DigestInfo, PKCS#1 v1.5 */
  const sign = (digest) => {
    signs.push(digest.length);
    return new Uint8Array(crypto.privateEncrypt({ key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.concat([DIGEST_INFO[digest.length], Buffer.from(digest)])));
  };
  return { publicKey, modulus, sign, signs };
}

test('a 4096-bit slot (RSA3 Code Signing): sha512WithRSAEncryption, issuer = subject, 30 years, verified with the slot\'s public key', async () => {
  const k = keyOf(4096);
  const notBefore = new Date('2026-11-04T12:00:00Z');
  const der = await x509.selfSigned({ modulus: k.modulus, subject: { CN: 'ok-edge release', O: 'ok-edge (unofficial R&D)', C: 'US' }, notBefore, sign: k.sign });
  const cert = new crypto.X509Certificate(Buffer.from(der));
  assert.equal(cert.verify(k.publicKey), true, 'signed by the slot');
  assert.equal(cert.publicKey.export({ format: 'jwk' }).n, k.publicKey.export({ format: 'jwk' }).n, 'its public key is the slot\'s');
  assert.equal(cert.subject, 'C=US\nO=ok-edge (unofficial R&D)\nCN=ok-edge release');
  assert.equal(cert.issuer, cert.subject, 'self-signed');
  assert.equal(new Date(cert.validFrom).toISOString(), notBefore.toISOString());
  assert.equal(new Date(cert.validTo).getUTCFullYear(), 2056, 'past 2050: GeneralizedTime');
  assert.deepEqual(k.signs, [64], 'one sign, of a SHA-512 digest');
  assert.deepEqual([cert.publicKey.asymmetricKeyDetails.modulusLength, cert.publicKey.asymmetricKeyDetails.publicExponent], [4096, 65537n]);
  assert.match(x509.toPem(der), /^-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=]{64}\n)+[A-Za-z0-9+/=]{1,64}\n-----END CERTIFICATE-----\n$/);
  assert.equal(new crypto.X509Certificate(x509.toPem(der)).fingerprint256, cert.fingerprint256, 'the PEM is the same certificate');
});

test('a 2048-bit slot: sha256WithRSAEncryption; a serial is positive and each certificate its own', async () => {
  const k = keyOf(2048);
  const a = new crypto.X509Certificate(Buffer.from(await x509.selfSigned({ modulus: k.modulus, subject: { CN: 'test' }, days: 10, sign: k.sign })));
  const b = new crypto.X509Certificate(Buffer.from(await x509.selfSigned({ modulus: k.modulus, subject: { CN: 'test' }, days: 10, sign: k.sign })));
  assert.equal(a.verify(k.publicKey), true);
  assert.deepEqual(k.signs, [32, 32], 'SHA-256 digests');
  assert.notEqual(a.serialNumber, b.serialNumber);
  assert.ok(parseInt(a.serialNumber[0], 16) < 8, 'top bit clear: positive');
  /* a leading zero on the modulus, as some reads give it, changes nothing */
  const z = new crypto.X509Certificate(Buffer.from(await x509.selfSigned({ modulus: Buffer.concat([Buffer.alloc(1), k.modulus]), subject: { CN: 'test' }, sign: k.sign })));
  assert.equal(z.verify(k.publicKey), true);
});

test('refused: no CN, a bad country, a modulus out of range, a signature of the wrong length', async () => {
  const k = keyOf(2048);
  await assert.rejects(x509.selfSigned({ modulus: k.modulus, subject: { O: 'x' }, sign: k.sign }), /CN at least/);
  await assert.rejects(x509.selfSigned({ modulus: k.modulus, subject: { CN: 'x', C: 'USA' }, sign: k.sign }), /two-letter/);
  await assert.rejects(x509.selfSigned({ modulus: new Uint8Array(64).fill(1), subject: { CN: 'x' }, sign: k.sign }), /1024 to 4096 bits/);
  await assert.rejects(x509.selfSigned({ modulus: k.modulus, subject: { CN: 'x' }, sign: () => new Uint8Array(10) }), /not 256 \(its modulus\)/);
});

test('read: a certificate back - its subject, dates, RSA key, fingerprint and signed bytes, as node reads them', async () => {
  const k = keyOf(4096);
  const der = await x509.selfSigned({ modulus: k.modulus, subject: { CN: 'ok-edge release', O: 'bmatusiak' }, days: 30, sign: k.sign });
  const pem = x509.toPem(der);
  const r = x509.read(pem);
  const cert = new crypto.X509Certificate(pem);
  assert.deepEqual(r.subject, { O: 'bmatusiak', CN: 'ok-edge release' });
  assert.deepEqual(r.issuer, r.subject);
  assert.equal(r.bits, 4096);
  assert.equal(Buffer.from(r.modulus).toString('hex'), Buffer.from(k.modulus).toString('hex'));
  assert.equal(Buffer.from(r.exponent).toString('hex'), '010001');
  assert.equal(r.signatureAlgorithm, 'sha512WithRSAEncryption');
  assert.equal(new Date(r.notBefore).getTime(), new Date(cert.validFrom).getTime());
  assert.equal(new Date(r.notAfter).getTime(), new Date(cert.validTo).getTime());
  assert.equal(r.sha256.toUpperCase(), cert.fingerprint256.replace(/:/g, ''));
  assert.equal(crypto.verify('sha512', Buffer.from(r.tbs), k.publicKey, Buffer.from(r.signature)), true, 'the signed bytes and the signature');
  assert.equal(x509.read(der).sha256, r.sha256, 'DER reads the same');
  assert.throws(() => x509.read('-----BEGIN PGP PUBLIC KEY BLOCK-----'), /not a PEM certificate/);
  assert.throws(() => x509.read(Buffer.concat([Buffer.from(der), Buffer.alloc(1)])), /not one DER certificate/);
});
