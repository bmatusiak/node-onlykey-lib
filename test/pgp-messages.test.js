/**
 * Encrypt, decrypt, sign and verify - the four pages the desktop app links out
 * to, now in the library.
 *
 * ## The oracle is openpgp itself, from the other side
 *
 * Every round trip here is closed by the SAME library that opened it, which
 * would be circular if that were all. So each test also checks something a
 * round trip cannot: that the ciphertext is not the plaintext, that a wrong key
 * fails, that a tampered message fails, and that a signature reports itself
 * invalid rather than throwing somewhere else.
 *
 * The device-backed half - decrypting with a key the OnlyKey holds - cannot run
 * here, because it needs the device. It is in ok-rn's e2e suite. What runs here
 * is everything that does not, which is most of it.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const openpgp = require('../src/vendor/openpgp/openpgp.js');
const pgp = require('../src/crypto/pgp_messages');
const { utf8ToBytes, bytesToUtf8 } = require('../src/bytes');

/*
 * ONE key pair for the whole file. Generating a composite PQC key takes about a
 * second, and twenty tests each generating their own would turn a fast suite
 * into a slow one for no extra coverage.
 */
let alice = null;
let bob = null;

async function keys() {
  if (alice) return { alice, bob };
  alice = await openpgp.generateKey({
    type: 'pqc',
    userIDs: [{ name: 'Alice', email: 'alice@example.invalid' }],
    subkeys: [{}],
    format: 'object',
    // PQC algorithms are v6-only; a v4 key refuses type 'pqc' outright.
    config: { v6Keys: true },
  });
  bob = await openpgp.generateKey({
    type: 'pqc',
    userIDs: [{ name: 'Bob', email: 'bob@example.invalid' }],
    subkeys: [{}],
    format: 'object',
    config: { v6Keys: true },
  });
  return { alice, bob };
}

const MESSAGE = 'the ciphertext is not the message';

/* ---------------------------------------------------------------- messages */

test('text encrypts to armour and comes back', async () => {
  const { alice } = await keys();

  const armored = await pgp.encryptText(openpgp, {
    text: MESSAGE, recipients: alice.publicKey,
  });

  assert.ok(/^-----BEGIN PGP MESSAGE-----/.test(armored), 'not PGP armour');
  assert.ok(!armored.includes(MESSAGE), 'the plaintext is sitting in the output');

  const result = await pgp.decryptMessage(openpgp, {
    armored, decryptWith: alice.privateKey,
  });
  assert.equal(result.data, MESSAGE);
});

test('a message encrypts to several recipients at once', async () => {
  const { alice, bob } = await keys();
  const armored = await pgp.encryptText(openpgp, {
    text: MESSAGE, recipients: [alice.publicKey, bob.publicKey],
  });

  // Either key alone opens it. That is the point of multiple recipients.
  for (const key of [alice.privateKey, bob.privateKey]) {
    const result = await pgp.decryptMessage(openpgp, { armored, decryptWith: key });
    assert.equal(result.data, MESSAGE);
  }
});

test('the wrong key does not open it', async () => {
  const { alice, bob } = await keys();
  const armored = await pgp.encryptText(openpgp, { text: MESSAGE, recipients: alice.publicKey });

  await assert.rejects(
    () => pgp.decryptMessage(openpgp, { armored, decryptWith: bob.privateKey }),
    'Bob opened a message addressed to Alice',
  );
});

test('a tampered message does not open', async () => {
  /*
   * A round trip proves the two halves agree with each other. This proves the
   * result depends on the ciphertext - which a round trip against a cipher
   * that ignored its input would also pass.
   */
  const { alice } = await keys();
  const armored = await pgp.encryptText(openpgp, { text: MESSAGE, recipients: alice.publicKey });

  const lines = armored.split('\n');
  const body = lines.findIndex((l) => l.length > 20 && !l.includes('-----'));
  lines[body] = lines[body].slice(0, 10) + (lines[body][10] === 'A' ? 'B' : 'A') + lines[body].slice(11);

  await assert.rejects(() => pgp.decryptMessage(openpgp, {
    armored: lines.join('\n'), decryptWith: alice.privateKey,
  }));
});

test('binary output is the same message without the armour', async () => {
  const { alice } = await keys();
  const binary = await pgp.encryptText(openpgp, {
    text: MESSAGE, recipients: alice.publicKey, armor: false,
  });

  assert.ok(binary instanceof Uint8Array, 'binary output should be bytes');
  const result = await pgp.decryptMessage(openpgp, { binary, decryptWith: alice.privateKey });
  assert.equal(result.data, MESSAGE);
});

/* ------------------------------------------------------------------- files */

test('a file round trips its bytes and its name', async () => {
  const { alice } = await keys();
  /*
   * Bytes that are NOT valid UTF-8 and DO contain CRLF, because that is what
   * catches a file encrypted as text: openpgp normalises line endings for text
   * messages, and the conversion is not reversible.
   */
  const data = Uint8Array.from([0xff, 0xfe, 0x00, 0x0d, 0x0a, 0x0d, 0x0a, 0x80, 0x7f]);

  const encrypted = await pgp.encryptFile(openpgp, {
    data, filename: 'secret.bin', recipients: alice.publicKey,
  });
  assert.ok(encrypted instanceof Uint8Array, 'files default to binary output');

  const result = await pgp.decryptMessage(openpgp, {
    binary: encrypted, decryptWith: alice.privateKey, format: 'binary',
  });
  assert.deepEqual(Array.from(result.data), Array.from(data), 'the bytes changed in transit');
  assert.equal(result.filename, 'secret.bin');
});

test('a file with CRLF survives, where text would have been normalised', async () => {
  const { alice } = await keys();
  const data = utf8ToBytes('line one\r\nline two\r\n');

  const encrypted = await pgp.encryptFile(openpgp, {
    data, filename: 'crlf.txt', recipients: alice.publicKey,
  });
  const result = await pgp.decryptMessage(openpgp, {
    binary: encrypted, decryptWith: alice.privateKey, format: 'binary',
  });
  assert.equal(bytesToUtf8(result.data), 'line one\r\nline two\r\n');
});

/* -------------------------------------------------------------- signatures */

test('a cleartext signature verifies and still reads as text', async () => {
  const { alice } = await keys();
  const signed = await pgp.signText(openpgp, { text: MESSAGE, signWith: alice.privateKey });

  assert.ok(/BEGIN PGP SIGNED MESSAGE/.test(signed));
  assert.ok(signed.includes(MESSAGE), 'a cleartext signature keeps the text readable');

  const result = await pgp.verifyText(openpgp, { armored: signed, verifyWith: alice.publicKey });
  assert.equal(result.valid, true);
  assert.equal(result.signatures.length, 1);
});

test('a signature from the wrong key reports invalid rather than throwing', async () => {
  /*
   * openpgp's signature results are promises that REJECT. Left unawaited they
   * surface as an unhandled rejection somewhere unrelated, which is why
   * describeSignatures awaits each one and reports it.
   */
  const { alice, bob } = await keys();
  const signed = await pgp.signText(openpgp, { text: MESSAGE, signWith: alice.privateKey });

  const result = await pgp.verifyText(openpgp, { armored: signed, verifyWith: bob.publicKey });
  assert.equal(result.valid, false);
  assert.equal(result.signatures.length, 1);
  assert.equal(result.signatures[0].valid, false);
  assert.ok(result.signatures[0].error, 'a failed verification should say why');
});

test('altered text fails its own signature', async () => {
  const { alice } = await keys();
  const signed = await pgp.signText(openpgp, { text: MESSAGE, signWith: alice.privateKey });
  const altered = signed.replace('not the message', 'NOT the message');

  const result = await pgp.verifyText(openpgp, { armored: altered, verifyWith: alice.publicKey });
  assert.equal(result.valid, false);
});

test('a detached signature verifies against text supplied separately', async () => {
  const { alice } = await keys();
  const signature = await pgp.signText(openpgp, {
    text: MESSAGE, signWith: alice.privateKey, detached: true,
  });
  assert.ok(/BEGIN PGP SIGNATURE/.test(signature));

  const good = await pgp.verifyText(openpgp, {
    armored: signature, text: MESSAGE, verifyWith: alice.publicKey,
  });
  assert.equal(good.valid, true);

  const bad = await pgp.verifyText(openpgp, {
    armored: signature, text: `${MESSAGE}!`, verifyWith: alice.publicKey,
  });
  assert.equal(bad.valid, false, 'a detached signature must not cover text it never saw');
});

test('encrypt-and-sign reports the signature on decryption', async () => {
  const { alice, bob } = await keys();
  const armored = await pgp.encryptText(openpgp, {
    text: MESSAGE, recipients: bob.publicKey, signWith: alice.privateKey,
  });

  const result = await pgp.decryptMessage(openpgp, {
    armored, decryptWith: bob.privateKey, verifyWith: alice.publicKey,
  });
  assert.equal(result.data, MESSAGE);
  assert.equal(result.signatures.length, 1);
  assert.equal(result.signatures[0].valid, true);
});

test('decrypting without verification keys still returns the message', async () => {
  // Not being able to check a signature is not a reason to withhold the text.
  const { alice, bob } = await keys();
  const armored = await pgp.encryptText(openpgp, {
    text: MESSAGE, recipients: bob.publicKey, signWith: alice.privateKey,
  });

  const result = await pgp.decryptMessage(openpgp, { armored, decryptWith: bob.privateKey });
  assert.equal(result.data, MESSAGE);
});

/* ------------------------------------------------------------------ shapes */

test('one recipient and several are the same call shape', async () => {
  const { alice } = await keys();
  const one = await pgp.readPublicKeys(openpgp, alice.publicKey);
  const many = await pgp.readPublicKeys(openpgp, [alice.publicKey]);
  assert.equal(one.length, 1);
  assert.equal(many.length, 1);
});

test('no recipients is refused rather than encrypted to nobody', async () => {
  await assert.rejects(() => pgp.encryptText(openpgp, { text: 'x', recipients: [] }),
    /no recipient keys/);
  await assert.rejects(() => pgp.encryptText(openpgp, { text: 'x', recipients: null }),
    /no recipient keys/);
});

test('encryptFile refuses text, and encryptText refuses bytes', async () => {
  const { alice } = await keys();
  await assert.rejects(
    () => pgp.encryptFile(openpgp, { data: 'not bytes', recipients: alice.publicKey }),
    /Uint8Array/,
  );
  await assert.rejects(
    () => pgp.encryptText(openpgp, { text: utf8ToBytes('bytes'), recipients: alice.publicKey }),
    /needs text/,
  );
});

test('classifyArmor tells the blocks apart', async () => {
  const { alice } = await keys();
  const armored = await pgp.encryptText(openpgp, { text: MESSAGE, recipients: alice.publicKey });
  const signed = await pgp.signText(openpgp, { text: MESSAGE, signWith: alice.privateKey });
  const detached = await pgp.signText(openpgp, {
    text: MESSAGE, signWith: alice.privateKey, detached: true,
  });

  assert.equal(pgp.classifyArmor(armored), 'message');
  assert.equal(pgp.classifyArmor(signed), 'signed');
  assert.equal(pgp.classifyArmor(detached), 'signature');
  // Armoured, because `format: 'object'` above gives Key objects rather than
  // text and classifyArmor reads armour.
  assert.equal(pgp.classifyArmor(alice.publicKey.armor()), 'public-key');
  assert.equal(pgp.classifyArmor(alice.privateKey.armor()), 'private-key');
  assert.equal(pgp.classifyArmor('hello'), 'unknown');
  assert.equal(pgp.classifyArmor(null), 'unknown');
});
