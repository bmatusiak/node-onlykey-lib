/*
 * The OpenPGP certificate builder, src/crypto/pgp-cert.js (Key Chain L2).
 *
 * It moved out of cli/gpg-key.js so a phone can build the same certificate.
 * The vectors in fixtures/key-chain-l2.json were frozen from the CLI's own
 * code BEFORE the move: a certificate's fingerprint is what the world knows a
 * key by, so "the same" here means the same bytes, not an equivalent key.
 * Then: the options the move added (expiry, several user ids) do only what
 * they say, and openpgp.js reads and verifies what comes out.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const openpgp = require('../src/vendor/openpgp/openpgp.js');
const pgpCert = require('../src/crypto/pgp-cert.js');
const gpgKey = require('../cli/gpg-key');
const { ed25519, x25519 } = require('../src/vendor/exports/@noble/curves/ed25519.js');
const { p256 } = require('../src/vendor/exports/@noble/curves/nist.js');
const FROZEN = require('./fixtures/key-chain-l2.json');

const hex = (b) => Buffer.from(b).toString('hex');
const USER_ID = 'OnlyKey Test <okt@example.com>';

/* Throwaway keys standing in for the device's - the frozen vectors' inputs. */
const SK = new Uint8Array(32).fill(3);
const XK = new Uint8Array(32).fill(5);
const DEV = {
  ed25519: { sign: ed25519.getPublicKey(SK), ecdh: x25519.getPublicKey(XK), sig: (d) => ed25519.sign(d, SK) },
  nist256p1: {
    sign: p256.getPublicKey(SK, false).slice(1),
    ecdh: p256.getPublicKey(XK, false).slice(1),
    sig: (d) => p256.sign(d.subarray(0, 32), SK, { prehash: false }),
  },
};

function opts(curve, extra = {}) {
  const calls = [];
  return {
    calls,
    opts: {
      userId: USER_ID,
      curve,
      signPublic: DEV[curve].sign,
      ecdhPublic: DEV[curve].ecdh,
      sign: async (digest) => { calls.push(digest); return DEV[curve].sig(digest); },
      ...extra,
    },
  };
}

test('the src builder is byte-identical to the frozen CLI certificates', async () => {
  for (const [name, want] of Object.entries(FROZEN.certificates)) {
    const [curve, created] = name.split('@');
    const { opts: o } = opts(curve, { created: Number(created) });
    const cert = await pgpCert.buildCertificate(openpgp, o);
    assert.ok(cert.bytes instanceof Uint8Array);
    assert.equal(hex(cert.bytes), want.hex, `${name} bytes`);
    assert.equal(cert.fingerprint, want.fingerprint, `${name} fingerprint`);
    assert.equal(cert.subkeyFingerprint, want.subkeyFingerprint);
    assert.deepEqual(cert.keygrips, want.keygrips);
    const back = await openpgp.unarmor(cert.armored);
    assert.equal(hex(back.data), want.hex, 'the armor carries the same bytes');
    assert.match(cert.armored, /\n=[A-Za-z0-9+/]{4}\n-----END PGP PUBLIC KEY BLOCK-----/, 'with the CRC-24 line gpg needs');
  }
});

test('the CLI goes through the src builder: same bytes, one copy', async () => {
  const { opts: o } = opts('ed25519', { created: 0 });
  const cli = await gpgKey.buildCertificate(o);
  assert.equal(hex(cli.bytes), FROZEN.certificates['ed25519@0'].hex);
  assert.equal(gpgKey.CURVES, pgpCert.CURVES, 'the CLI re-exports, it does not restate');
  assert.equal(gpgKey.keygrip, pgpCert.keygrip);
  assert.ok(Buffer.isBuffer(gpgKey.keyPacketBody(gpgKey.CURVES.ed25519.sign, DEV.ed25519.sign, 0)),
    'the CLI face keeps Buffer for the agent');
  assert.equal(require('../src/crypto').pgpCert, pgpCert, 'and it is on the crypto barrel');
});

test('created defaults to 0 (lib-agent\'s epoch), and a Date is the same as its seconds', async () => {
  const a = await pgpCert.buildCertificate(openpgp, opts('ed25519').opts);
  assert.equal(hex(a.bytes), FROZEN.certificates['ed25519@0'].hex);
  const b = await pgpCert.buildCertificate(openpgp, opts('nist256p1', { created: new Date(1700000000 * 1000) }).opts);
  assert.equal(hex(b.bytes), FROZEN.certificates['nist256p1@1700000000'].hex);
});

test('openpgp.js reads the certificate back and verifies every self-signature', async () => {
  for (const curve of ['ed25519', 'nist256p1']) {
    const { opts: o, calls } = opts(curve, { created: 1700000000 });
    const cert = await pgpCert.buildCertificate(openpgp, o);
    assert.equal(calls.length, 2, 'one certification, one binding');
    const key = await openpgp.readKey({ armoredKey: cert.armored });
    assert.equal(key.getFingerprint().toUpperCase(), cert.fingerprint);
    await key.verifyPrimaryKey();
    const user = await key.getPrimaryUser();
    assert.equal(user.user.userID.userID, USER_ID);
    assert.equal(key.subkeys.length, 1);
    await key.subkeys[0].verify();
    assert.equal(await key.getExpirationTime(), Infinity, 'no expiry unless asked');
    const enc = await key.getEncryptionKey();
    assert.equal(enc.getFingerprint().toUpperCase(), cert.subkeyFingerprint);
  }
});

function signatures(key) {
  return [...key.users.flatMap((u) => u.selfCertifications), ...key.subkeys.flatMap((s) => s.bindingSignatures)];
}

test('the Key Expiration Time subpacket is there only when asked for', async () => {
  const plain = await openpgp.readKey({
    binaryKey: (await pgpCert.buildCertificate(openpgp, opts('ed25519', { created: 1700000000 }).opts)).bytes,
  });
  for (const sig of signatures(plain)) {
    assert.equal(sig.keyExpirationTime, null);
    assert.equal(sig.rawNotations.length, 0);
  }

  const DAY = 86400;
  for (const expires of [365 * DAY, new Date((1700000000 + 365 * DAY) * 1000)]) {
    const cert = await pgpCert.buildCertificate(openpgp, opts('ed25519', { created: 1700000000, expires }).opts);
    const key = await openpgp.readKey({ binaryKey: cert.bytes });
    const sigs = signatures(key);
    assert.equal(sigs.length, 2);
    for (const sig of sigs) assert.equal(sig.keyExpirationTime, 365 * DAY, 'primary and subkey expire together');
    /* Verified at the key's own time: the year is long gone by now. */
    const at = new Date((1700000000 + DAY) * 1000);
    await key.verifyPrimaryKey(at);
    await key.subkeys[0].verify(at);
    await assert.rejects(key.verifyPrimaryKey(), /expired/i, 'and openpgp.js holds it to the subpacket today');
    assert.equal(cert.fingerprint, FROZEN.certificates['ed25519@1700000000'].fingerprint,
      'expiry lives in the signatures, never the key: same fingerprint');
  }

  for (const bad of [0, -5, 1.5, new Date(1699999999 * 1000)]) {
    await assert.rejects(pgpCert.buildCertificate(openpgp, opts('ed25519', { created: 1700000000, expires: bad }).opts),
      /expires must fall after/);
  }
});

test('several user ids: each certified by the device, the first marked primary', async () => {
  const ids = ['Alice <alice@example.com>', 'Alice (work) <alice@work.example>'];
  const { opts: o, calls } = opts('ed25519', { userId: undefined, userIds: ids, created: 1700000000 });
  const cert = await pgpCert.buildCertificate(openpgp, o);
  assert.equal(calls.length, 3, 'two certifications and the binding, one press each');
  assert.equal(cert.fingerprint, FROZEN.certificates['ed25519@1700000000'].fingerprint, 'user ids are not in the fingerprint');
  const key = await openpgp.readKey({ armoredKey: cert.armored });
  await key.verifyPrimaryKey();
  assert.deepEqual(key.users.map((u) => u.userID.userID), ids);
  for (const u of key.users) await u.verify();
  assert.equal(key.users[0].selfCertifications[0].isPrimaryUserID, true);
  assert.equal(key.users[1].selfCertifications[0].isPrimaryUserID, null);
  assert.equal((await key.getPrimaryUser()).user.userID.userID, ids[0]);
  /* The agent derives from the first user id; reading the keyring back agrees. */
  const read = await gpgKey.readDerivedKeys(cert.armored);
  assert.deepEqual(read.map((k) => [k.userId, k.role]), [[ids[0], 'sign'], [ids[0], 'ecdh']]);

  const one = await openpgp.readKey({ binaryKey: (await pgpCert.buildCertificate(openpgp, opts('ed25519').opts)).bytes });
  assert.equal(one.users[0].selfCertifications[0].isPrimaryUserID, null, 'a single id carries no flag - lib-agent\'s bytes');
});

test('the inputs it refuses, and the hook it puts back', async () => {
  const before = { ...openpgp.setHardwareHooks({}) };
  await assert.rejects(pgpCert.buildCertificate(opts('ed25519').opts), /openpgp fork/);
  await assert.rejects(pgpCert.buildCertificate(openpgp, opts('ed25519', { userId: undefined }).opts), /at least one user id/);
  await assert.rejects(pgpCert.buildCertificate(openpgp, opts('ed25519', { userId: undefined, userIds: ['ok', ''] }).opts), /at least one user id/);
  await assert.rejects(pgpCert.buildCertificate(openpgp, { ...opts('ed25519').opts, curve: 'secp256k1' }), /no GPG key for curve/);
  await assert.rejects(pgpCert.buildCertificate(openpgp, opts('ed25519', { created: -1 }).opts), /seconds since the epoch/);
  await assert.rejects(pgpCert.buildCertificate(openpgp, opts('ed25519', {
    sign: async () => new Uint8Array(64),
  }).opts), /does not verify against its own public key/);
  assert.deepEqual({ ...openpgp.setHardwareHooks({}) }, before, 'a failed build leaves the global hooks as it found them');
});

test('kindOf is the inverse of CURVES, and passes anything else by', () => {
  for (const curve of Object.keys(pgpCert.CURVES)) {
    for (const role of ['sign', 'ecdh']) {
      const k = pgpCert.CURVES[curve][role];
      const got = pgpCert.kindOf(k.algo, Uint8Array.from(k.oid));
      assert.equal(got.curve, curve);
      assert.equal(got.role, role);
    }
  }
  assert.equal(pgpCert.kindOf(1, new Uint8Array(0)), null, 'RSA');
  assert.equal(pgpCert.kindOf(pgpCert.ALGO.ECDSA, pgpCert.OID.ed25519), null, 'a right OID under the wrong algorithm');
});

test('signDetached: a detached signature by the derived key that openpgp verifies against the certificate (what git stores in a signed commit)', async () => {
  for (const curve of ['ed25519', 'nist256p1']) {
    const { opts: o } = opts(curve, { created: 1700000000 });
    const cert = await pgpCert.buildCertificate(openpgp, o);
    const data = new TextEncoder().encode('tree 0123456789abcdef\nauthor Claude <claude@test> 1700000000 +0000\n\nEdge: a commit\n');
    const sig = await pgpCert.signDetached(openpgp, { data, signPublic: DEV[curve].sign, curve, created: 1700000000, sign: async (d) => DEV[curve].sig(d) });
    assert.equal(sig.fingerprint, cert.fingerprint, `${curve}: the issuer is the certificate`);
    assert.match(sig.armored, /^-----BEGIN PGP SIGNATURE-----/);
    assert.match(sig.armored, /\n=[A-Za-z0-9+/]{4}\n-----END PGP SIGNATURE-----/, `${curve}: the CRC-24 line GnuPG needs`);
    const { signatures } = await openpgp.verify({
      message: await openpgp.createMessage({ binary: data }),
      signature: await openpgp.readSignature({ armoredSignature: sig.armored }),
      verificationKeys: await openpgp.readKey({ armoredKey: cert.armored }),
    });
    await assert.doesNotReject(signatures[0].verified, `${curve}: does not verify`);
    /* the device's signature is checked before it is encoded: a wrong one is refused, not shipped */
    await assert.rejects(pgpCert.signDetached(openpgp, { data, signPublic: DEV[curve].sign, curve, created: 1700000000, sign: async () => new Uint8Array(64) }), /does not verify/);
  }
});
