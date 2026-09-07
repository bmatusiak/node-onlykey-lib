/*
 * The vendored openpgp fork.
 *
 * This copy is the shared PQC fork plus exactly one appended line, so that it
 * can be require()d without eval - Hermes disables eval and new Function, and
 * both existing consumers load the fork by evaluating its source, which would
 * make PGP unavailable in React Native.
 *
 * onlykey.github.io's copy and python-onlykey's copy are required to stay
 * byte-identical to each other. This one cannot be, so the check moves a level
 * down: strip the appended line and the bytes must match. These tests are that
 * check. See src/vendor/openpgp/VENDORED.md.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const VENDORED = path.resolve(__dirname, '..', 'src', 'vendor', 'openpgp', 'openpgp.js');

/* The single modification, byte for byte. CRLF because the fork is CRLF. */
const SUFFIX = Buffer.from('module.exports = openpgp;\r\n', 'utf8');

/* The fork as shared, before the appended line. */
const BODY_MD5 = '7db75c5a2200c0aca65dccb7cda4202c';
const BODY_LEN = 1272214;

const md5 = (buf) => crypto.createHash('md5').update(buf).digest('hex');

const raw = fs.readFileSync(VENDORED);
const body = raw.subarray(0, raw.length - SUFFIX.length);

test('the vendored copy is the fork plus exactly one appended line', () => {
  assert.ok(
    raw.subarray(raw.length - SUFFIX.length).equals(SUFFIX),
    'the file must end with the appended module.exports line',
  );
  assert.equal(raw.length - body.length, 27, 'exactly 27 bytes were added');
  assert.ok(
    body.subarray(body.length - 9).equals(Buffer.from('})({});\r\n', 'utf8')),
    'and the body still ends where the fork does',
  );
});

test('stripping that line reproduces the shared fork byte for byte', () => {
  // This is the whole guarantee. If it fails, either someone edited the
  // vendored file or git rewrote its line endings - see /.gitattributes.
  assert.equal(body.length, BODY_LEN);
  assert.equal(md5(body), BODY_MD5);
});

test('the line endings survived checkout', () => {
  // core.autocrlf is active in this repo. A CRLF->LF rewrite changes every
  // line and would fail the MD5 above, but this says WHY in one line rather
  // than leaving a bare checksum mismatch to diagnose.
  const head = raw.subarray(0, 4096).toString('latin1');
  assert.ok(head.includes('\r\n'), 'CRLF is gone: .gitattributes is not taking effect');
});

/* Cross-checks against the sibling checkouts, skipped when they are absent. */
const SIBLINGS = {
  'onlykey.github.io': path.resolve(
    __dirname, '..', '..', 'onlykey.github.io',
    'src', 'onlykey-fido2', 'onlykey', 'vendor', 'openpgp', 'openpgp.js',
  ),
  'python-onlykey': path.resolve(
    __dirname, '..', '..', 'python-onlykey',
    'onlykey', 'openpgp_bridge', 'openpgp.js',
  ),
};

for (const [name, file] of Object.entries(SIBLINGS)) {
  const present = fs.existsSync(file);
  test(`the body matches ${name}'s copy`, { skip: !present }, () => {
    assert.equal(md5(fs.readFileSync(file)), md5(body), `drifted from ${name}`);
  });
}

/* ------------------------------------------------------------ it actually loads */

test('the fork require()s as an ordinary CommonJS module', () => {
  // The point of the appended line. A plain require() of the unmodified fork
  // returns {}, because its top-level `var openpgp` is module-scoped.
  const openpgp = require('../src/vendor/openpgp/openpgp.js');
  assert.equal(typeof openpgp, 'object');
  assert.equal(typeof openpgp.generateKey, 'function');
});

test('the hardware-hook API is present - it is why this fork exists', () => {
  const openpgp = require('../src/vendor/openpgp/openpgp.js');
  assert.equal(typeof openpgp.setHardwareHooks, 'function');
  assert.equal(typeof openpgp.clearHardwareHooks, 'function');
  assert.equal(typeof openpgp.createHardwarePrivateKey, 'function');
});

test('the PQC codepoints are the corrected draft-10 values', () => {
  /*
   * 30 and 35 are what IANA assigns and what draft-ietf-openpgp-pqc-10 §11
   * specifies. The fork as originally received used 107 and 105, which sit in
   * IANA's "Private or Experimental Use" range - no other implementation would
   * understand them.
   *
   * This is not cosmetic and not a re-tagging: the algorithm ID is an input to
   * the key combiner, so keys and messages made under the old codepoints
   * cannot be read under the new ones in either direction. Pinned here so that
   * re-vendoring from a stale source is caught by a test rather than by a user
   * whose keys stop working.
   */
  const openpgp = require('../src/vendor/openpgp/openpgp.js');
  assert.equal(openpgp.enums.publicKey.pqc_mlkem_x25519, 35);
  assert.equal(openpgp.enums.publicKey.pqc_mldsa_ed25519, 30);
  assert.notEqual(openpgp.enums.publicKey.pqc_mlkem_x25519, 105, 'pre-correction value');
  assert.notEqual(openpgp.enums.publicKey.pqc_mldsa_ed25519, 107, 'pre-correction value');
});

test('the fork pulls in nothing at runtime', () => {
  // It is self-contained - no require(), no import, no eval. That is what
  // makes it loadable under Hermes and what makes the single appended line
  // sufficient.
  const source = body.toString('latin1');
  assert.equal(/\brequire\s*\(/.test(source), false, 'no require() in the bundle');
  assert.equal(/\bnew Function\s*\(/.test(source), false, 'no new Function in the bundle');
});
