/*
 * The classic age X25519 recipient, age1... (Key Chain L2), through the
 * public surface (node-onlykey-lib/crypto's pqc).
 *
 * The vector is age's own: the pair `age-keygen` prints in its manual page
 * (FiloSottile/age doc/age-keygen.1.ronn, "Traditional identity
 * generation"). The secret half is decoded with the same bech32, its X25519
 * public key taken, and the recipient this library encodes from it must be
 * the one age-keygen printed - so the HRP, the checksum (bech32, not
 * bech32m) and the bit packing are all age's, not merely self-consistent.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { pqc } = require('../src/crypto');
const { x25519 } = require('../src/vendor/exports/@noble/curves/ed25519.js');

const AGE_KEYGEN = {
  identity: 'AGE-SECRET-KEY-1N9JEPW6DWJ0ZQUDX63F5A03GX8QUW7PXDE39N8UYF82VZ9PC8UFS3M7XA9',
  recipient: 'age1lvyvwawkr0mcnnnncaghunadrqkmuf9e6507x9y920xxpp866cnql7dp2z',
};
/* The recipient in age's README examples ("Alice"). */
const README_RECIPIENT = 'age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p';

test('the recipient of age-keygen\'s published identity is the one age-keygen printed', () => {
  const { hrp, data } = pqc.bech32Decode(AGE_KEYGEN.identity);
  assert.equal(hrp, 'age-secret-key-');
  assert.equal(data.length, 32);
  const pub = x25519.getPublicKey(data);
  assert.equal(pqc.encodeX25519Recipient(pub), AGE_KEYGEN.recipient);
  assert.deepEqual(pqc.decodeX25519Recipient(AGE_KEYGEN.recipient), pub);
  assert.equal(pqc.X25519_RECIPIENT_HRP, 'age');
});

test('a recipient from age\'s README decodes and encodes back to itself', () => {
  const key = pqc.decodeX25519Recipient(README_RECIPIENT);
  assert.equal(key.length, 32);
  assert.equal(pqc.encodeX25519Recipient(key), README_RECIPIENT);
  assert.deepEqual(pqc.decodeX25519Recipient(`  ${README_RECIPIENT}\n`), key, 'surrounding whitespace is not part of it');
});

test('what is not an age X25519 recipient', () => {
  const pk = new Uint8Array(32).map((_, i) => i);
  const r = pqc.encodeX25519Recipient(pk);
  const flipped = r.slice(0, -1) + (r.endsWith('q') ? 'p' : 'q');
  for (const bad of [
    flipped,                                   // checksum
    r.toUpperCase(),                           // age refuses upper case
    pqc.encodeRecipient(pk),                   // age1onlykey1..., another HRP
    pqc.bech32Encode('age', new Uint8Array(31)), // wrong length
    'age1',
  ]) {
    assert.throws(() => pqc.decodeX25519Recipient(bad), /not a valid age X25519 recipient/, bad);
  }
  assert.throws(() => pqc.encodeX25519Recipient(new Uint8Array(33)), /32-byte/);
  assert.throws(() => pqc.encodeX25519Recipient(undefined), /32-byte/);
});
