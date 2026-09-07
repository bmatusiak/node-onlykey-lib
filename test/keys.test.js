'use strict';

const test = require('node:test');
const assert = require('node:assert');

const keys = require('../src/device/keys');
const { toHex } = require('../src/bytes');

/* -------------------------------------------------------------- OID compare */

test('OID comparison is element-wise and order-sensitive', () => {
  // The original is a.sort().join() === b.sort().join(): a multiset compare,
  // so a PERMUTED OID matches. These two share every byte and are different
  // OIDs.
  const a = [1, 2, 3];
  const b = [3, 2, 1];
  assert.equal(keys.oidEquals(a, b), false, 'a permutation is not the same OID');
  assert.equal(keys.oidEquals(a, [1, 2, 3]), true);
  assert.equal(keys.oidEquals(a, [1, 2]), false);
  assert.equal(keys.oidEquals(null, a), false);
});

test('OID comparison does not mutate its operands', () => {
  // The original sorts both in place, so comparing corrupts the caller's data.
  const a = [43, 6, 1, 4, 1, 218, 71, 15, 1];
  const before = a.slice();
  keys.oidEquals(a, keys.OID.ED25519);
  assert.deepEqual(a, before, 'the operand survived the comparison');
});

test('OID comparison works across Array and Uint8Array', () => {
  // Uint8Array.sort is numeric, Array.sort is lexicographic, so the original
  // fails whenever openpgp hands back a plain Array.
  assert.equal(
    keys.oidEquals(Uint8Array.from(keys.OID.ED25519), keys.OID.ED25519),
    true,
    'typed and plain arrays must compare equal',
  );
});

test('the Curve25519 OID is recognised, not silently unsupported', () => {
  // The original's cv25519 branch re-tests the Ed25519 OID byte for byte, so
  // a real cv25519 key never matches and falls through to CURVE.NONE.
  assert.notDeepEqual(keys.OID.CURVE25519, keys.OID.ED25519);
  assert.notEqual(keys.curveFromOid(keys.OID.CURVE25519), keys.CURVE.NONE);
  assert.equal(keys.curveFromOid(keys.OID.ED25519), keys.CURVE.ED25519);
  assert.equal(keys.curveFromOid(keys.OID.NIST256P1), keys.CURVE.NIST256P1);
  assert.equal(keys.curveFromOid([9, 9, 9]), keys.CURVE.NONE);
});

/* ----------------------------------------------------------- key extraction */

test('an sshpk ed25519 key yields a 32-byte scalar on curve 1', () => {
  const out = keys.fromSshpk({ type: 'ed25519', part: { k: { data: new Uint8Array(32).fill(5) } } });
  assert.equal(out.kind, 'ecc');
  assert.equal(out.curve, keys.CURVE.ED25519);
  assert.equal(out.scalar.length, 32);
});

test('an sshpk nistp256 key reads its scalar from part.d', () => {
  const out = keys.fromSshpk({ curve: 'nistp256', part: { d: { data: new Uint8Array(32).fill(7) } } });
  assert.equal(out.curve, keys.CURVE.NIST256P1);
});

test('sshpk RSA primes have their DER sign-pad stripped', () => {
  const p = new Uint8Array(129); p[0] = 0x00; p[1] = 0xff;
  const q = new Uint8Array(129); q[0] = 0x00; q[1] = 0xee;
  const out = keys.fromSshpk({ type: 'rsa', part: { p: { data: p }, q: { data: q } } });
  assert.equal(out.p.length, 128, 'the leading zero is gone');
  assert.equal(out.p[0], 0xff);
});

test('the sign-pad strip is conditional, not unconditional', () => {
  // The original always slices, which is right for supported RSA sizes and
  // wrong in general. Conditional gives the same answer and survives a key
  // whose high bit is clear.
  const noPad = Uint8Array.from([0xff, 0x11, 0x22]);
  assert.deepEqual(Array.from(keys.stripSignPad(noPad)), [0xff, 0x11, 0x22]);
  assert.deepEqual(Array.from(keys.stripSignPad(Uint8Array.from([0x00, 0x11]))), [0x11]);
});

test('PGP MPI offsets differ between a primary and a subkey', () => {
  // EdDSA primary is [oid, Q, s]; ECDH subkey is [oid, Q, kdfParams, d].
  const oidParam = { oid: keys.OID.ED25519 };
  const scalar = { data: new Uint8Array(32).fill(3) };

  const primary = keys.fromPgpPacket({ params: [oidParam, {}, scalar] }, false);
  assert.equal(primary.scalar[0], 3, 'primary scalar at params[2]');

  const sub = keys.fromPgpPacket({ params: [oidParam, {}, {}, scalar] }, true);
  assert.equal(sub.scalar[0], 3, 'subkey scalar at params[3]');
});

test('PGP RSA primes are always params[3] and [4]', () => {
  const packet = { params: [{}, {}, {}, { data: new Uint8Array(128).fill(1) }, { data: new Uint8Array(128).fill(2) }, {}] };
  const out = keys.fromPgpPacket(packet, false);
  assert.equal(out.kind, 'rsa');
  assert.equal(out.p[0], 1);
  assert.equal(out.q[0], 2);
});

/* ------------------------------------------------------------ slot and type */

test('RSA type is derived from the prime length', () => {
  for (const [bytes, type] of [[64, 1], [128, 2], [192, 3], [256, 4]]) {
    const out = keys.prepareKey({ kind: 'rsa', p: new Uint8Array(bytes), q: new Uint8Array(bytes) });
    assert.equal(out.type, type, `${bytes * 8 * 2}-bit key`);
    assert.equal(out.key.length, bytes * 2, 'the key is p||q');
  }
});

test('an unsupported RSA size is refused with its actual length', () => {
  assert.throws(
    () => keys.prepareKey({ kind: 'rsa', p: new Uint8Array(100), q: new Uint8Array(100) }),
    /p is 100 bytes/,
  );
});

test('an ECC scalar that is not 32 bytes is refused', () => {
  assert.throws(
    () => keys.prepareKey({ kind: 'ecc', curve: keys.CURVE.ED25519, scalar: new Uint8Array(31) }),
    /32 bytes/,
  );
});

test('ECC keys move into the 100+ slot namespace', () => {
  const out = keys.prepareKey(
    { kind: 'ecc', curve: keys.CURVE.ED25519, scalar: new Uint8Array(32) },
    { slot: 2 },
  );
  assert.equal(out.slot, 102);
});

test('an ECC slot already in the namespace is not shifted twice', () => {
  const out = keys.prepareKey(
    { kind: 'ecc', curve: keys.CURVE.ED25519, scalar: new Uint8Array(32) },
    { slot: 102 },
  );
  assert.equal(out.slot, 102);
});

test('modifiers are OR-ed into the type byte', () => {
  const rsa = { kind: 'rsa', p: new Uint8Array(128), q: new Uint8Array(128) };
  assert.equal(keys.prepareKey(rsa, { backup: true }).type, 2 | 0x80);
  assert.equal(keys.prepareKey(rsa, { signature: true }).type, 2 | 0x40);
  assert.equal(keys.prepareKey(rsa, { decryption: true }).type, 2 | 0x20);
});

test('auto-assign clears the backup flag on the SIGNING key', () => {
  // "Only set backup flag on decryption key" - a signing key that kept it
  // would be pulled into backups it has no business being in.
  const rsa = { kind: 'rsa', p: new Uint8Array(128), q: new Uint8Array(128) };

  const signing = keys.prepareKey(rsa, { slot: 2, backup: true, autoAssign: true });
  assert.equal(signing.type & keys.MODIFIER.BACKUP, 0, 'backup cleared');
  assert.equal(signing.type & keys.MODIFIER.SIGNATURE, keys.MODIFIER.SIGNATURE);

  const decrypting = keys.prepareKey(rsa, { slot: 1, backup: true, autoAssign: true });
  assert.equal(decrypting.type & keys.MODIFIER.BACKUP, keys.MODIFIER.BACKUP, 'backup kept');
  assert.equal(decrypting.type & keys.MODIFIER.DECRYPTION, keys.MODIFIER.DECRYPTION);
});

/* ------------------------------------------------------- the slot convention */

test('subkey 1 decrypts on slot 1; subkey 2 signs on slot 2', () => {
  const out = keys.assignPgpSlots(['primary', 'sub1', 'sub2']);
  const byRole = Object.fromEntries(out.map((a) => [a.role, a]));
  assert.equal(byRole.signature.key, 'sub2');
  assert.equal(byRole.signature.slot, 2);
  assert.equal(byRole.decryption.key, 'sub1');
  assert.equal(byRole.decryption.slot, 1);
});

test('with only one subkey the PRIMARY signs - the Protonmail layout', () => {
  const out = keys.assignPgpSlots(['primary', 'sub1']);
  const byRole = Object.fromEntries(out.map((a) => [a.role, a]));
  assert.equal(byRole.signature.key, 'primary');
  assert.equal(byRole.decryption.key, 'sub1');
});

test('a lone primary gets the signature slot and no decryption key', () => {
  const out = keys.assignPgpSlots(['primary']);
  assert.equal(out.length, 1);
  assert.equal(out[0].role, 'signature');
});

/* ------------------------------------------------------------- backup key */

test('the backup passphrase minimum is 25 characters', () => {
  assert.match(keys.validateBackupPassphrase('short').join(' '), /at least 25/);
  assert.deepEqual(keys.validateBackupPassphrase('a'.repeat(25)), []);
});

test('a passphrase mismatch is reported', () => {
  const out = keys.validateBackupPassphrase('a'.repeat(25), 'b'.repeat(25));
  assert.match(out.join(' '), /do not match/);
});

test('the backup key is SHA256 of the passphrase, at slot 131 type 161', () => {
  const { sha256 } = require('@noble/hashes/sha2.js');
  const { fromLatin1 } = require('../src/bytes');
  const phrase = 'correct horse battery staple xyz';

  const out = keys.backupKeyFromPassphrase(phrase);
  assert.equal(out.slot, 131);
  assert.equal(out.type, 161, '0x80 backup | 0x20 decryption | 1');
  assert.equal(toHex(out.key), toHex(sha256(fromLatin1(phrase))));
  assert.equal(out.key.length, 32, 'one unchunked packet');
});

test('a short passphrase cannot be turned into a backup key at all', () => {
  assert.throws(() => keys.backupKeyFromPassphrase('too short'), /at least 25/);
});
