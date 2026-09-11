/*
 * The application crypto layer.
 *
 * These three modules came across from onlykey.github.io nearly unchanged -
 * they were already device-free CommonJS importing @noble by package name. The
 * point of these tests is not to re-derive their design; it is to prove they
 * still WORK against @noble v2, since the vendored copies were written against
 * an earlier major and a load test proves nothing about drift inside the
 * functions. Every test here is a real round trip or a pinned vector.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const pqc = require('../src/crypto/age_pqc');
const ageFile = require('../src/crypto/age_file');
const composite = require('../src/crypto/composite_pgp');
const { toHex } = require('../src/bytes');

/* -------------------------------------------------------------- age_pqc */

test('an ML-KEM keypair is deterministic from its seed', () => {
  // The whole derived-identity scheme rests on this: the same label must yield
  // the same recipient on every device, forever.
  const seed = new Uint8Array(32).fill(0x11);
  const a = pqc.mlkemKeypairFromSeed(seed);
  const b = pqc.mlkemKeypairFromSeed(seed);
  assert.equal(toHex(a.publicKey), toHex(b.publicKey));
  assert.equal(toHex(a.secretKey), toHex(b.secretKey));
});

test('a different seed gives a different keypair', () => {
  const a = pqc.mlkemKeypairFromSeed(new Uint8Array(32).fill(1));
  const b = pqc.mlkemKeypairFromSeed(new Uint8Array(32).fill(2));
  assert.notEqual(toHex(a.publicKey), toHex(b.publicKey));
});

test('a label tag is a stable SHA-256 over the label', () => {
  const { sha256 } = require('@noble/hashes/sha2.js');
  const { utf8ToBytes } = require('../src/bytes');
  assert.equal(toHex(pqc.deriveLabelTag('work')), toHex(sha256(utf8ToBytes('work'))));
  assert.equal(toHex(pqc.deriveLabelTag('work')), toHex(pqc.deriveLabelTag('work')));
  assert.notEqual(toHex(pqc.deriveLabelTag('work')), toHex(pqc.deriveLabelTag('home')));
});

test('the label tag is UTF-8, and a non-ASCII label proves it', () => {
  /*
   * The assertion above is ASCII, where latin1 and UTF-8 are the same bytes -
   * so on its own it holds under EITHER encoding and proves nothing about the
   * one that is required. This label separates them: latin1 would give 6
   * bytes, UTF-8 gives 7. python-onlykey's derived_label_tag() hashes UTF-8,
   * and a mismatch here is invisible until decryption reports "no identity
   * matched any of the recipients" on a file that is perfectly intact.
   */
  const { sha256 } = require('@noble/hashes/sha2.js');
  const { utf8ToBytes, fromLatin1 } = require('../src/bytes');
  const label = 'café-key';

  assert.equal(utf8ToBytes(label).length, 9, 'the e-acute is two bytes in UTF-8');
  assert.equal(fromLatin1(label).length, 8, 'and one in latin1 - the encodings diverge here');

  assert.equal(toHex(pqc.deriveLabelTag(label)), toHex(sha256(utf8ToBytes(label))));
  assert.notEqual(toHex(pqc.deriveLabelTag(label)), toHex(sha256(fromLatin1(label))));
});

test('X-Wing encapsulation and split decapsulation agree', () => {
  // The end-to-end property that matters: what the sender derives is what the
  // holder of both halves derives.
  const { x25519 } = require('@noble/curves/ed25519.js');

  const xSk = x25519.utils.randomSecretKey();
  const xPk = x25519.getPublicKey(xSk);
  const mlkemSeed = new Uint8Array(32).fill(0x42);

  const recipient = pqc.buildRecipient(xPk, mlkemSeed);
  const { ciphertext, sharedSecret } = pqc.xwingEncapsHost(recipient);

  // The receiving side: its X25519 half, then the combiner.
  const ctX = pqc.ctXOf(ciphertext);
  const ssX = x25519.getSharedSecret(xSk, ctX);
  const opened = pqc.splitDecapsulate(ssX, ciphertext, xPk, mlkemSeed);

  assert.equal(toHex(opened), toHex(sharedSecret), 'both sides derived the same secret');
  assert.equal(sharedSecret.length, 32);
});

test('a bech32 recipient round-trips', () => {
  const pk = new Uint8Array(1216).fill(0x5a); // X-Wing public key
  const encoded = pqc.encodeRecipient(pk);
  assert.match(encoded, /^age1/, 'age recipients are bech32 with an age1 prefix');
  assert.equal(toHex(pqc.decodeRecipient(encoded)), toHex(pk));
});

test('a corrupted recipient fails its checksum rather than decoding', () => {
  const encoded = pqc.encodeRecipient(new Uint8Array(1216).fill(3));
  const broken = `${encoded.slice(0, -1)}${encoded.slice(-1) === 'q' ? 'p' : 'q'}`;
  assert.throws(() => pqc.decodeRecipient(broken));
});

test('an identity round-trips its label', () => {
  // decodeIdentity returns a descriptor, not a bare string: the marker byte
  // distinguishes a DERIVED identity from a stored one, and callers branch on
  // it before ever reading the label.
  const encoded = pqc.encodeIdentity('my-label');
  const out = pqc.decodeIdentity(encoded);
  assert.equal(out.derived, true);
  assert.equal(out.label, 'my-label');
});

test('a non-ASCII label survives the identity round trip', () => {
  // encodeIdentity and decodeIdentity are the two halves of the UTF-8 port;
  // an ASCII-only round trip would pass with both halves wrong the same way.
  const label = 'café ☕';
  const out = pqc.decodeIdentity(pqc.encodeIdentity(label));
  assert.equal(out.label, label);
});

test('something that is not a derived identity decodes to null', () => {
  // Not an exception: the caller tries each identity in turn, so "not this
  // one" has to be an ordinary answer.
  assert.equal(pqc.decodeIdentity(pqc.encodeRecipient(new Uint8Array(1216))), null);
});

/* ------------------------------------------------------------- age_file */

test('a file key is sealed and opened under the same shared secret', () => {
  const shared = new Uint8Array(32).fill(9);
  const enc = new Uint8Array(1120).fill(4);
  const fileKey = new Uint8Array(16).fill(7);

  const sealed = ageFile.sealFileKey(shared, enc, fileKey);
  assert.notEqual(toHex(sealed), toHex(fileKey), 'it was actually wrapped');
  assert.equal(toHex(ageFile.openFileKey(shared, enc, sealed)), toHex(fileKey));
});

test('a wrong shared secret fails to open the file key', () => {
  // ChaCha20-Poly1305 is authenticated here, unlike the device transit box.
  const enc = new Uint8Array(1120).fill(4);
  const sealed = ageFile.sealFileKey(new Uint8Array(32).fill(9), enc, new Uint8Array(16).fill(7));
  assert.throws(() => ageFile.openFileKey(new Uint8Array(32).fill(8), enc, sealed));
});

test('an age file round-trips through encrypt and decrypt', async () => {
  const { fromLatin1, toLatin1 } = require('../src/bytes');
  const shared = new Uint8Array(32).fill(0x33);
  const ciphertext = new Uint8Array(1120).fill(0x44);
  const plaintext = fromLatin1('the quick brown fox jumps over the lazy dog');

  const file = ageFile.encryptAgeFile(plaintext, { ciphertext, sharedSecret: shared });
  const opened = await ageFile.decryptAgeFile(file, async () => shared);
  assert.equal(toLatin1(opened), toLatin1(plaintext));
});

test('an age file larger than one STREAM chunk round-trips', async () => {
  // The body is chunked at 64 KiB with a counter-and-final-flag nonce; a
  // single-chunk test would never exercise the counter.
  const shared = new Uint8Array(32).fill(0x55);
  const ciphertext = new Uint8Array(1120).fill(0x66);
  const plaintext = new Uint8Array(64 * 1024 * 2 + 17);
  for (let i = 0; i < plaintext.length; i++) plaintext[i] = i & 0xff;

  const file = ageFile.encryptAgeFile(plaintext, { ciphertext, sharedSecret: shared });
  const opened = await ageFile.decryptAgeFile(file, async () => shared);
  assert.equal(opened.length, plaintext.length, 'three chunks reassembled');
  assert.equal(toHex(opened.subarray(-4)), toHex(plaintext.subarray(-4)));
});

test('a tampered age file is rejected, not silently truncated', async () => {
  const shared = new Uint8Array(32).fill(0x77);
  const ciphertext = new Uint8Array(1120).fill(0x88);
  const file = ageFile.encryptAgeFile(new Uint8Array(64).fill(1), { ciphertext, sharedSecret: shared });

  const tampered = Uint8Array.from(file);
  tampered[tampered.length - 5] ^= 0xff;
  await assert.rejects(ageFile.decryptAgeFile(tampered, async () => shared));
});

/* -------------------------------------------------------- composite_pgp */

test('the composite blob layout is the documented 160 bytes', () => {
  assert.equal(composite.BLOB_LEN, 160);
  assert.equal(composite.OFF_ED25519, 0);
  assert.equal(composite.OFF_MLDSA_SEED, 32);
  assert.equal(composite.OFF_X25519, 64);
  assert.equal(composite.OFF_MLKEM_SEED, 96);
});

test('a composite blob round-trips through pack and unpack', () => {
  const ed = new Uint8Array(32).fill(1);
  const mldsa = new Uint8Array(32).fill(2);
  const x = new Uint8Array(32).fill(3);
  const mlkem = new Uint8Array(64).fill(4);

  const blob = composite.packBlob(ed, mldsa, x, mlkem);
  assert.equal(blob.length, composite.BLOB_LEN);

  const out = composite.unpackBlob(blob);
  assert.equal(toHex(out.ed25519Sk), toHex(ed));
  assert.equal(toHex(out.mldsaSeed), toHex(mldsa));
  assert.equal(toHex(out.x25519Sk), toHex(x));
  assert.equal(toHex(out.mlkemSeed), toHex(mlkem));
});

test('the two composite halves are distinct constants', () => {
  // composite_sign prepends this selector; composite_decrypt has none and the
  // device infers the half from the input size instead.
  assert.equal(composite.HALF_ECC, 0);
  assert.equal(composite.HALF_PQC, 1);
  assert.notEqual(composite.HALF_ECC, composite.HALF_PQC);
});

test('composite_pgp is device-free', () => {
  // Its header says so, and it matters: this module must be usable to inspect
  // and pack keys with no OnlyKey present. registerCompositeHooks takes the
  // device as an argument rather than importing one.
  const source = require('fs').readFileSync(require.resolve('../src/crypto/composite_pgp.js'), 'utf8');
  assert.equal(/require\(['"]\.\.\/(session|transport|device)/.test(source), false);
  assert.equal(typeof composite.registerCompositeHooks, 'function');
});

/* ------------------------------------------- slot age identities */

/*
 * THE FIXTURES BELOW WERE PRODUCED BY PYTHON-ONLYKEY, not by this library.
 *
 * They are the output of `bech32_encode` from
 * python-onlykey/onlykey/age_plugin/bech32.py, run directly, for a slot of
 * 110 and a public key of 1216 bytes of 0x07:
 *
 *   legacy     bech32_encode(HRP, bytes([110])).upper()
 *   versioned  bech32_encode(HRP, bytes([1,110]) + sha256(pk)[:8]).upper()
 *
 * That matters more than it looks. An identity written by one client has to
 * be readable by the other or a file encrypted on a phone cannot be opened on
 * a laptop, and asserting our encoder against our decoder would prove nothing
 * about that at all. These strings are the other implementation's answer.
 */
const PY_LEGACY_SLOT_110 = 'AGE-PLUGIN-ONLYKEY-1DCNPXSY2';
const PY_V1_SLOT_110_HEAD = 'AGE-PLUGIN-ONLYKEY-1Q9HTMTMK4ECTPN3LYYCV';

function testKey() {
  return new Uint8Array(1216).fill(7);
}

test('a slot identity is byte-for-byte what python-onlykey writes', () => {
  assert.equal(pqc.encodeSlotIdentity(110), PY_LEGACY_SLOT_110);

  const versioned = pqc.encodeSlotIdentity(110, testKey());
  assert.equal(versioned.slice(0, PY_V1_SLOT_110_HEAD.length), PY_V1_SLOT_110_HEAD);
});

test('both identity shapes the python plugin can read, read back here', () => {
  /*
   * One byte is what cli.py's encode_identity emits today and calls `legacy`
   * when it reads one. The versioned form is what its decoder also accepts
   * and nothing there writes yet - so files from either client open here.
   */
  const legacy = pqc.decodeIdentity(PY_LEGACY_SLOT_110);
  assert.equal(legacy.derived, false);
  assert.equal(legacy.slot, 110);
  assert.equal(legacy.legacy, true);
  assert.equal(legacy.fingerprint, null);

  const versioned = pqc.decodeIdentity(pqc.encodeSlotIdentity(110, testKey()));
  assert.equal(versioned.slot, 110);
  assert.equal(versioned.legacy, false);
  assert.equal(versioned.fingerprint.length, 8);
});

test('a derived identity and a slot identity cannot be confused', () => {
  /*
   * They share an HRP deliberately - age picks which plugin binary to exec
   * from that literal prefix, so a distinct one would break dispatch. The
   * first payload byte is what separates them, and the ranges cannot meet:
   * derived is 0xFF, a slot is 101..116, a version is 1.
   */
  const derived = pqc.decodeIdentity(pqc.encodeIdentity('me@example.com'));
  assert.equal(derived.derived, true);
  assert.equal(derived.label, 'me@example.com');

  const slot = pqc.decodeIdentity(pqc.encodeSlotIdentity(116, testKey()));
  assert.equal(slot.derived, false);
  assert.equal(slot.slot, 116);
});

test('a slot outside the user range is refused, not encoded', () => {
  /* 117..132 are reserved and 133 is not a slot at all. */
  assert.throws(() => pqc.encodeSlotIdentity(117), /101\.\.116/);
  assert.throws(() => pqc.encodeSlotIdentity(100), /101\.\.116/);
  assert.throws(() => pqc.encodeSlotIdentity(1), /101\.\.116/);
});

test('the fingerprint catches a slot that has been regenerated', () => {
  /*
   * The whole reason for writing the versioned form. An identity names a
   * slot, and a slot can be generated again - at which point a file
   * encrypted to the old key fails with "no identity matched", which points
   * at nothing. With the fingerprint a client can say what actually happened.
   */
  const identity = pqc.decodeIdentity(pqc.encodeSlotIdentity(110, testKey()));
  assert.equal(pqc.identityMatchesKey(identity, testKey()), true);

  const regenerated = new Uint8Array(1216).fill(9);
  assert.equal(pqc.identityMatchesKey(identity, regenerated), false);
});

test('a one-byte identity matches anything, because it cannot tell', () => {
  /*
   * Refusing what python-onlykey writes today would make the two clients
   * unable to share a file, which is a worse failure than not detecting a
   * regenerated slot.
   */
  const legacy = pqc.decodeIdentity(PY_LEGACY_SLOT_110);
  assert.equal(pqc.identityMatchesKey(legacy, testKey()), true);
  assert.equal(pqc.identityMatchesKey(legacy, new Uint8Array(1216).fill(9)), true);
});
