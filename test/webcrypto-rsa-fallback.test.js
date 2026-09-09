/**
 * RSA works WITHOUT RSA in the shim, and this proves it.
 *
 * The shim refuses RSA by design - @noble has none, and this project's PGP is
 * composite post-quantum. The obvious conclusion is that RSA PGP therefore
 * needs a real WebCrypto on the phone, which would mean a native module or a
 * hidden WebView, and routing private key material through one.
 *
 * That conclusion is wrong, and the reason is in openpgp itself. Its RSA
 * dispatch (openpgp.js:6107-6118 and 6134-6144) is:
 *
 *     if (util.getWebCrypto()) {
 *       try {
 *         return await webSign$1(...);
 *       } catch (err) {
 *         util.printDebugError(err);      // <- swallowed
 *       }
 *     } else if (util.getNodeCrypto()) { ... }
 *     return bnSign(hashAlgo, n, d, hashed);   // <- BigInt, always reachable
 *
 * The shim's NotSupportedError is CAUGHT and openpgp falls through to its own
 * BigInt implementation. So sign, verify, encrypt and decrypt all work.
 *
 * ## Why this file forces the shim over Node's real one
 *
 * Node HAS crypto.subtle, so without `force` these tests would exercise the
 * real implementation and prove nothing about the phone. The install happens
 * BEFORE openpgp is required, because openpgp reads WebCrypto at module scope -
 * installing afterwards would leave it holding whatever was there at load.
 *
 * That is also why this is a SEPARATE FILE. It replaces a global for its whole
 * lifetime, and doing that inside a suite that shares a process with tests
 * expecting the real thing would make those tests depend on execution order.
 *
 * ## The one real gap
 *
 * RSA key GENERATION has no such fallback and fails. That is the entire cost of
 * having no RSA in the shim, and it is worth knowing precisely, because "we
 * cannot do RSA" and "we cannot GENERATE an RSA key on the phone" lead to very
 * different decisions.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

require('../src/webcrypto/subtle').install({ force: true });

const openpgp = require('../src/vendor/openpgp/openpgp.js');
const pgp = require('../src/crypto/pgp_messages');

test('RSA key generation is the one thing the shim cannot do', async () => {
  let keys = null;
  let generationError = null;
  try {
    keys = await openpgp.generateKey({
      type: 'rsa',
      rsaBits: 2048,
      userIDs: [{ name: 'r', email: 'r@example.invalid' }],
      format: 'armored',
    });
  } catch (e) {
    generationError = e;
  }

  if (keys) {
    /*
     * GOOD NEWS if this fires. Something now supplies RSA - a real WebCrypto,
     * or RSA added to the shim - and the comment at the top of this file needs
     * revisiting rather than the test being deleted.
     */
    assert.ok(true, 'RSA generation works now; the shim gained RSA or a real one is present');
    return;
  }

  assert.match(String(generationError.message), /RSA is not implemented/);
});

/*
 * A COMMITTED RSA key, not one generated here.
 *
 * Generation is the one thing this build cannot do, so a test that needed to
 * generate one would skip - and a skipped test says nothing. The fixture was
 * made once with Node's real WebCrypto and checked in; it is a test key with no
 * secret worth keeping, which is why it can be.
 *
 * That is also the realistic case. An RSA key on an OnlyKey is one that was
 * imported; the device holds it and nobody generates it on the phone.
 */
const RSA = require('./fixtures/rsa-2048.json');

test('RSA sign and verify fall through to openpgp own BigInt implementation', async () => {
  const signed = await pgp.signText(openpgp, { text: 'hello', signWith: RSA.privateKey });
  const result = await pgp.verifyText(openpgp, {
    armored: signed, verifyWith: RSA.publicKey,
  });
  assert.equal(result.valid, true,
    'openpgp bnSign/bnVerify should carry RSA with no WebCrypto RSA at all');
});

test('a bad RSA signature is still reported invalid, not accepted', async () => {
  /*
   * The fallback has to be a real implementation, not one that returns true.
   * Altering the signed text must fail it.
   */
  const signed = await pgp.signText(openpgp, { text: 'hello', signWith: RSA.privateKey });
  const NL = String.fromCharCode(10);
  const altered = signed.replace(NL + 'hello' + NL, NL + 'HELLO' + NL);
  const result = await pgp.verifyText(openpgp, {
    armored: altered, verifyWith: RSA.publicKey,
  });
  assert.equal(result.valid, false);
});

test('RSA encrypt and decrypt work the same way', async () => {
  const armored = await pgp.encryptText(openpgp, {
    text: 'the ciphertext is not the message', recipients: RSA.publicKey,
  });
  assert.ok(!armored.includes('the ciphertext is not the message'));

  const opened = await pgp.decryptMessage(openpgp, {
    armored, decryptWith: RSA.privateKey,
  });
  assert.equal(opened.data, 'the ciphertext is not the message');
});

test('the shim really is the one in place, so the above means something', () => {
  /*
   * The whole file is worthless if Node's own implementation answered these.
   * RSA generation through globalThis.crypto.subtle must refuse.
   */
  assert.rejects(
    () => globalThis.crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true, ['sign', 'verify'],
    ),
    (e) => e.name === 'NotSupportedError',
  );
});
