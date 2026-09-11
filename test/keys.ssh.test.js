'use strict';

/*
 * OpenSSH private keys → what OKSETPRIV needs.
 *
 * The fixtures are THROWAWAY keys made with ssh-keygen for this file
 * (`-t ed25519`, `-t ecdsa -b 256`, `-t rsa -b 2048`, and one ed25519 with
 * the passphrase "secret"), never used anywhere. Each parsed private half is
 * checked against the matching .pub line CRYPTOGRAPHICALLY - the public key
 * derived from the parsed scalar must equal the one ssh-keygen wrote - so a
 * parser that lands on the wrong field, or off by a sign-padding byte, fails
 * here rather than on a device that signs with garbage.
 */

const test = require('node:test');
const assert = require('node:assert');

const { ed25519 } = require('@noble/curves/ed25519.js');
const { p256 } = require('@noble/curves/nist.js');

const openssh = require('../src/device/openssh');
const keys = require('../src/device/keys');
const { fromBase64, toHex } = require('../src/bytes');

const ED25519 = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCK/qwnyc6jZLTBE8LPJ7MC2tpyjtAsUTJy+HPdlcMjTgAAAJBZLVmQWS1Z
kAAAAAtzc2gtZWQyNTUxOQAAACCK/qwnyc6jZLTBE8LPJ7MC2tpyjtAsUTJy+HPdlcMjTg
AAAEBTBSBVEFDFQtEzzQNibjTjaUbUDYHtpNarNFQJFDw94Ir+rCfJzqNktMETws8nswLa
2nKO0CxRMnL4c92VwyNOAAAAB2ZpeHR1cmUBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----`;
const ED25519_PUB = 'AAAAC3NzaC1lZDI1NTE5AAAAIIr+rCfJzqNktMETws8nswLa2nKO0CxRMnL4c92VwyNO';

const ECDSA = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQywRUQbRE1U0EfKYHqHbXSDp9ihGRU
Yoy6U71BYfG47x3oUozDqW887QoOSCSz6tvLSMpQHdto7LyVlFB9HgpXAAAAoLaIGgi2iB
oIAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDLBFRBtETVTQR8p
geodtdIOn2KEZFRijLpTvUFh8bjvHehSjMOpbzztCg5IJLPq28tIylAd22jsvJWUUH0eCl
cAAAAhAOzKGrqtbMLf9ikb8HlxFJiSOFWOGInnVBKAjtvOxKBBAAAAB2ZpeHR1cmU=
-----END OPENSSH PRIVATE KEY-----`;
const ECDSA_PUB = 'AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDLBFRBtETVTQR8pgeodtdIOn2KEZFRijLpTvUFh8bjvHehSjMOpbzztCg5IJLPq28tIylAd22jsvJWUUH0eClc=';

const RSA = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA0DuPhrz9iJmCAY3Yo7RfQzrtq2EU9vEo+1cIcQf9DzIlDku/7xnN
REzOHl9ow6YliHQ20WsuL3VvRnpnWWfUaTj3ppQgicWZ+oGOu9Mqjp4wdzHjHIJcu6AdXj
siv+Vb31kycX9favV4d/FQPiH/Qpg3crJhMlOJsWaIcFCzl7ij+8BTeJ/tfFxk/tWa0xH2
gOeTsgclyIE6xlbJuyuWyyG4rFwLQP+57bbT1KGSYKLzAhpp38BzYceCLJJ7hRU66kNfSW
r9pKJKpgsNFcpIiU/n8yrHbgh/+MYVSIOQxkgex0xwna7YGEjIL92oqw4+E/nkKhJ5n6vx
pz0Tz3Gt2wAAA8BMgiUUTIIlFAAAAAdzc2gtcnNhAAABAQDQO4+GvP2ImYIBjdijtF9DOu
2rYRT28Sj7VwhxB/0PMiUOS7/vGc1ETM4eX2jDpiWIdDbRay4vdW9GemdZZ9RpOPemlCCJ
xZn6gY670yqOnjB3MeMcgly7oB1eOyK/5VvfWTJxf19q9Xh38VA+If9CmDdysmEyU4mxZo
hwULOXuKP7wFN4n+18XGT+1ZrTEfaA55OyByXIgTrGVsm7K5bLIbisXAtA/7ntttPUoZJg
ovMCGmnfwHNhx4IsknuFFTrqQ19Jav2kokqmCw0VykiJT+fzKsduCH/4xhVIg5DGSB7HTH
CdrtgYSMgv3airDj4T+eQqEnmfq/GnPRPPca3bAAAAAwEAAQAAAQAOwqIOXXglRihaftkD
5aW5CMTPGJ8ZUAflJQqypGvSN248AK+Wvb/4nu8fZQjykWTossAuAQhxkcP0/Xk087CxUr
nvQ2G5ElozURqygqnqGRl7YXxlSXJUVGmwg8WXT6U/BD4YoHw9gy/qZJ8ZAGTtLggEJ9PO
8u/4NLnoKDhKwUl7KjjR/tJTd73+bbtiY0RggRFBpli87DFAjvFRHtcC1g4jOuRaA+h/ww
mfh8T8XpsBVwvPJy/1Go+uyaYFVQaU69h5sqfg9XCEHQIvkSLy5xi1iRixEybjav1nX4C0
+j35Bly5xI2/oDNljo+cgOmTQDhTTlQYS8RUWPSKpaG5AAAAgHG+v2gDx3ibjlVos6csxt
yDOSRTsEIOyJVqPoTFtkYbOU5G1oUZw9jMSjkvZMO1ybb9UVUzxD9QzbUpuGCwDsWSi09x
uOuH1HtCBxcDG+PGn3yR4fp+qwC0F6CHWfvQOmUBbLKvOF75jkoalUzj0IYw73mGi3TZec
tA+bVmFVLjAAAAgQD6eH8P7JNNPqMQBWoqQtP7HJIelooZnzPkkIHydzz4RVjLfWLmfyO7
QWjcAV9PUNCou4rIR8TxjATqzqqQameGg9NoV3KoOK2jB/1CpmxhpHibog9YhVBLyyRfC8
LQY+K02esy/rh4OUPOceoDJmvj9WIG9unaP75GnzlBVtQYqQAAAIEA1NRcg99kFzqbTPlv
TriZhyDp0aXUQrrmHI3v2ai23wQIFKbphCcatLXA32i3Fo4fMvDW0kUS8vs7Xse4iW2Omf
qt8DEyvjOXVRBmVNUTpO2188CgiCqNt+FexD34bsylOwQ0CgGImasqnMopCTsXq7JRrlRv
VJZozEg5/6AzUOMAAAAHZml4dHVyZQECAwQ=
-----END OPENSSH PRIVATE KEY-----`;
const RSA_PUB = 'AAAAB3NzaC1yc2EAAAADAQABAAABAQDQO4+GvP2ImYIBjdijtF9DOu2rYRT28Sj7VwhxB/0PMiUOS7/vGc1ETM4eX2jDpiWIdDbRay4vdW9GemdZZ9RpOPemlCCJxZn6gY670yqOnjB3MeMcgly7oB1eOyK/5VvfWTJxf19q9Xh38VA+If9CmDdysmEyU4mxZohwULOXuKP7wFN4n+18XGT+1ZrTEfaA55OyByXIgTrGVsm7K5bLIbisXAtA/7ntttPUoZJgovMCGmnfwHNhx4IsknuFFTrqQ19Jav2kokqmCw0VykiJT+fzKsduCH/4xhVIg5DGSB7HTHCdrtgYSMgv3airDj4T+eQqEnmfq/GnPRPPca3b';

const ED25519_ENCRYPTED = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBwIfhdya
G59RaoNQxJbhtUAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIEE+zSO55q54c3Rl
yppGXG8W+ZMLFUXj12G87J67d9nDAAAAkLeoilxG9p6NAwFX/nDwKrozRTWBCHQ/wZAr/b
GzVNk+InU20pcVnJAmfhh7Y7Uc2PQqtFUomAd1HzS9hP1lLOXCLbiVsumJvGiMNEC99s/c
n/Z//0KCHZFlHRJxmSIB48l/sEwUEdUMKLebueeb1Tqa5TXZnxCFElGcGKJH7dF5KMooxS
xRDLHu5w21qKY0iQ==
-----END OPENSSH PRIVATE KEY-----`;

/** The strings of an SSH public-key blob, in order. */
function blobStrings(b64) {
  const bytes = fromBase64(b64);
  const out = [];
  let at = 0;
  while (at < bytes.length) {
    const n = ((bytes[at] << 24) | (bytes[at + 1] << 16) | (bytes[at + 2] << 8) | bytes[at + 3]) >>> 0;
    out.push(bytes.subarray(at + 4, at + 4 + n));
    at += 4 + n;
  }
  return out;
}

test('an Ed25519 key: the seed, checked against the public key ssh-keygen wrote', () => {
  const key = openssh.parsePrivateKey(ED25519);
  assert.equal(key.type, 'ed25519');
  assert.equal(key.comment, 'fixture');
  assert.equal(key.part.k.data.length, 32);

  const [, pub] = blobStrings(ED25519_PUB);
  assert.equal(toHex(ed25519.getPublicKey(key.part.k.data)), toHex(pub));

  /* And fromSshpk + prepareKey take it as they would sshpk's output. */
  const material = keys.fromSshpk(key);
  const prepared = keys.prepareKey(material, { slot: 101, signature: true });
  assert.equal(prepared.slot, 101);
  assert.equal(prepared.type & 0x0f, keys.CURVE.ED25519);
  assert.equal(prepared.type & keys.MODIFIER.SIGNATURE, keys.MODIFIER.SIGNATURE);
  assert.equal(prepared.key.length, 32);
});

test('a P-256 key: the scalar, fixed at 32 bytes, checked against Q', () => {
  const key = openssh.parsePrivateKey(ECDSA);
  assert.equal(key.type, 'ecdsa');
  assert.equal(key.curve, 'nistp256');
  assert.equal(key.part.d.data.length, 32);

  const [, , q] = blobStrings(ECDSA_PUB);
  assert.equal(q.length, 65, 'uncompressed point');
  assert.equal(toHex(p256.getPublicKey(key.part.d.data, false)), toHex(q));

  const prepared = keys.prepareKey(keys.fromSshpk(key), { slot: 102, decryption: true });
  assert.equal(prepared.type & 0x0f, keys.CURVE.NIST256P1);
  assert.equal(prepared.key.length, 32);
});

test('an RSA key: p and q whose product is the n in the public key', () => {
  const key = openssh.parsePrivateKey(RSA);
  assert.equal(key.type, 'rsa');

  const [, , n] = blobStrings(RSA_PUB);
  const big = (bytes) => BigInt('0x' + (toHex(bytes) || '0'));
  assert.equal(big(key.part.p.data) * big(key.part.q.data), big(n));

  /* 2048-bit: type 2, 256 bytes of key, RSA slots only. */
  const prepared = keys.prepareKey(keys.fromSshpk(key), { slot: 1, signature: true, decryption: true });
  assert.equal(prepared.slot, 1);
  assert.equal(prepared.type & 0x0f, 2);
  assert.equal(prepared.key.length, 256);
});

test('a passphrase-protected key is refused with the way out named', () => {
  assert.throws(() => openssh.parsePrivateKey(ED25519_ENCRYPTED), /passphrase.*ssh-keygen -p/s);
});

test('the older PEM forms and a PGP block are refused by name', () => {
  assert.throws(
    () => openssh.parsePrivateKey('-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----'),
    /older PEM form.*ssh-keygen -p -o/s,
  );
  assert.throws(() => openssh.parsePrivateKey('-----BEGIN PGP PRIVATE KEY BLOCK-----'), /PGP key/);
  assert.throws(() => openssh.parsePrivateKey('hello'), /not an OpenSSH private key/);
});

test('a truncated or tampered blob fails closed', () => {
  const cut = ED25519.replace(/2nKO0CxRMnL4c92VwyNOAAAAB2ZpeHR1cmUBAgMEBQY=/, '2nKO0CxR');
  assert.throws(() => openssh.parsePrivateKey(cut), /truncated/);
});
