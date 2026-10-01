/*
 * SSH public key lines, src/crypto/ssh-pub.js (Key Chain L2).
 *
 * The Ed25519 and P-256 lines were frozen from cli/ssh-wire.js BEFORE the
 * encoder moved to src/ (fixtures/key-chain-l2.json): a line the agent
 * already put in someone's authorized_keys must still be the line a GUI
 * shows. ssh-rsa is new; it is checked against OpenSSH (a vector whose
 * fingerprint ssh-keygen -l printed) and against Node's own RSA key parser.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

const ssh = require('../src/crypto/ssh-pub.js');
const wire = require('../cli/ssh-wire');
const { ed25519 } = require('../src/vendor/exports/@noble/curves/ed25519.js');
const { p256 } = require('../src/vendor/exports/@noble/curves/nist.js');
const FROZEN = require('./fixtures/key-chain-l2.json');

const hex = (b) => Buffer.from(b).toString('hex');
const SK = new Uint8Array(32).fill(3);
const RAW = { ed25519: ed25519.getPublicKey(SK), nist256p1: p256.getPublicKey(SK, false).slice(1) };

test('Ed25519 and P-256 lines are the frozen CLI lines, from src and from the CLI', () => {
  for (const curve of ['ed25519', 'nist256p1']) {
    const comment = `<ssh://okt@example.com|${curve}>`;
    assert.equal(ssh.publicKeyLine(curve, RAW[curve], comment), FROZEN.ssh[curve], curve);
    assert.equal(wire.publicKeyLine(curve, RAW[curve], comment), FROZEN.ssh[curve], `${curve} through cli/ssh-wire.js`);
    assert.ok(Buffer.isBuffer(wire.publicKeyBlob(curve, RAW[curve])), 'the CLI face keeps Buffer for the agent');
    assert.equal(hex(wire.publicKeyBlob(curve, RAW[curve])), hex(ssh.publicKeyBlob(curve, RAW[curve])));
  }
  assert.equal(wire.CURVES, ssh.CURVES, 'one table, re-exported');
  assert.equal(require('../src/crypto').ssh, ssh, 'and it is on the crypto barrel');
});

test('a line without a comment has no trailing space', () => {
  const line = ssh.publicKeyLine('ed25519', RAW.ed25519);
  assert.equal(line, FROZEN.ssh.ed25519.split(' ').slice(0, 2).join(' '));
  assert.equal(ssh.publicKeyLine('ed25519', RAW.ed25519, ''), line);
});

/* Reads `string name, mpint e, mpint n` back off a blob, strictly. */
function parseRsaBlob(blob) {
  const b = Buffer.from(blob);
  let at = 0;
  const field = () => {
    const n = b.readUInt32BE(at);
    const v = b.subarray(at + 4, at + 4 + n);
    assert.equal(v.length, n, 'no field runs past the blob');
    at += 4 + n;
    return v;
  };
  const name = field().toString();
  const e = field();
  const n = field();
  assert.equal(at, b.length, 'nothing after n');
  return { name, e, n };
}

test('ssh-rsa: the OpenSSH vector (ssh-keygen -l printed its fingerprint)', () => {
  const n = Buffer.from(FROZEN.rsa.n, 'base64url');
  const line = ssh.rsaPublicKeyLine(n, FROZEN.rsa.comment);
  assert.equal(line, FROZEN.rsa.line);
  const blob = ssh.rsaPublicKeyBlob(n);
  const fp = `SHA256:${crypto.createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;
  assert.equal(fp, FROZEN.rsa.sshKeygenFingerprint);
  assert.equal(line.split(' ')[1], Buffer.from(blob).toString('base64'));
});

test('ssh-rsa: e before n, the modulus mpint gets its sign byte, and Node reads the same key', () => {
  for (const bits of [1024, 2048]) {
    const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: bits });
    const jwk = publicKey.export({ format: 'jwk' });
    const n = Buffer.from(jwk.n, 'base64url');
    assert.ok(n[0] & 0x80, 'an RSA modulus has its top bit set by construction');

    const [type, b64, comment] = ssh.rsaPublicKeyLine(Uint8Array.from(n), 'me@host').split(' ');
    assert.equal(type, 'ssh-rsa');
    assert.equal(comment, 'me@host');
    const parsed = parseRsaBlob(Buffer.from(b64, 'base64'));
    assert.equal(parsed.name, 'ssh-rsa');
    assert.equal(hex(parsed.e), '010001', '65537 by default, no leading zero (top bit clear)');
    assert.equal(parsed.n.length, n.length + 1);
    assert.equal(parsed.n[0], 0, 'a leading zero, or the mpint would read as negative');

    const back = crypto.createPublicKey({
      key: { kty: 'RSA', n: parsed.n.subarray(1).toString('base64url'), e: parsed.e.toString('base64url') },
      format: 'jwk',
    });
    assert.equal(
      hex(back.export({ format: 'der', type: 'spki' })),
      hex(publicKey.export({ format: 'der', type: 'spki' })),
      `${bits}-bit: the line names the key it was made from`,
    );
  }
});

test('ssh-rsa: the exponent, and what is not a modulus', () => {
  const n = Buffer.from(FROZEN.rsa.n, 'base64url');
  assert.equal(hex(parseRsaBlob(ssh.rsaPublicKeyBlob(n, { exponent: 3 })).e), '03');
  assert.equal(hex(parseRsaBlob(ssh.rsaPublicKeyBlob(n, { exponent: 0x80 })).e), '0080', 'a set top bit in e too');
  assert.equal(hex(parseRsaBlob(ssh.rsaPublicKeyBlob(n, { exponent: Uint8Array.of(0, 1, 0, 1) })).e), '010001',
    'bytes are taken as a magnitude, leading zeros dropped');
  assert.equal(hex(parseRsaBlob(ssh.rsaPublicKeyBlob(Buffer.concat([Buffer.alloc(2), n]))).n), hex(Buffer.concat([Buffer.of(0), n])),
    'a modulus handed over with zero padding is the same modulus');
  assert.throws(() => ssh.rsaPublicKeyBlob(new Uint8Array(256)), /cannot be zero/);
  assert.throws(() => ssh.rsaPublicKeyBlob(Uint8Array.of(0x80, 0x02)), /is odd/);
  assert.throws(() => ssh.rsaPublicKeyBlob(n, { exponent: 1 }), /at least 3/);
  assert.throws(() => ssh.rsaPublicKeyBlob(n, { exponent: new Uint8Array(3) }), /cannot be zero/);
});

test('the primitives, as Uint8Array, agree with the CLI\'s Buffer ones', () => {
  assert.equal(hex(ssh.uint32(0x01020304)), '01020304');
  assert.equal(hex(ssh.string('ab')), '000000026162');
  for (const m of [[0], [0x7f], [0x80], [0, 0, 0x12, 0x34], [0, 0x80, 1]]) {
    const v = ssh.mpint(Uint8Array.from(m));
    assert.ok(v instanceof Uint8Array && !Buffer.isBuffer(v), 'src/ hands back plain Uint8Array');
    assert.equal(hex(v), hex(wire.mpint(Buffer.from(m))));
  }
});
