/*
 * The vendored third-party libraries - the project's ONE copy of @noble/* and
 * tweetnacl (src/vendor/VENDORED.md, scripts/vendor.js).
 *
 * The point of one copy is that it is the only one: auditable in one place,
 * swappable in one place. These tests hold each half of that. The files are
 * still the published tarballs (a tree hash per package), nothing in this
 * library reaches past the shims or back to npm, and the copies still ship and
 * still work as a consumer reaches them.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const {execSync} = require('child_process');
const vendor = require('../scripts/vendor.js');

const ROOT = path.resolve(__dirname, '..');
const pkg = require('../package.json');
const NAMES = vendor.PACKAGES.map((p) => p.name);

test('every vendored copy matches its record, and every shim is generated', () => {
  assert.deepStrictEqual(vendor.check(), []);
});

test('no vendored package is also an npm dependency', () => {
  /* A second copy through npm is exactly the drift one copy exists to end. */
  for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    for (const name of NAMES) {
      assert.ok(!(pkg[field] && name in pkg[field]), `${name} is in ${field} - it is vendored`);
    }
  }
});

test('the library reaches the copies only through the shims', () => {
  const files = execSync('git ls-files -co --exclude-standard src plugins test scripts', {cwd: ROOT, encoding: 'utf8'})
    .split('\n')
    .filter((f) => /\.(js|ts)$/.test(f) && !f.startsWith('src/vendor/') && !f.endsWith('.d.ts') &&
      f !== 'test/vendor.test.js' && f !== 'scripts/vendor.js');
  const bare = new RegExp(`require\\('(${NAMES.map((n) => n.replace('/', '\\/')).join('|')})(/[^']*)?'\\)`);
  for (const f of files) {
    const src = fs.readFileSync(path.join(ROOT, f), 'utf8');
    assert.ok(!bare.test(src), `${f} requires a vendored package by name - use src/vendor/exports/`);
    assert.ok(!/require\(\s*['"][^'"]*vendor\/node_modules\//.test(src),
      `${f} reaches into src/vendor/node_modules/ - use src/vendor/exports/`);
  }
});

test('a consumer reaches a vendored module through the public subpath', () => {
  /* Self-reference goes through the exports map, exactly as a consumer's require does. */
  const {sha256} = require('node-onlykey-lib/vendor/@noble/hashes/sha2.js');
  const {bytesToHex} = require('node-onlykey-lib/vendor/@noble/hashes/utils.js');
  assert.equal(bytesToHex(sha256(new TextEncoder().encode('abc'))),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  const nacl = require('node-onlykey-lib/vendor/tweetnacl');
  assert.equal(typeof nacl.box.keyPair, 'function');
});

test('the copies resolve each other without npm', () => {
  /*
   * ML-KEM imports @noble/hashes and @noble/curves by bare name. With neither in
   * this repo's node_modules, a round trip proves those names land on the
   * vendored siblings (the node_modules-named directory at work).
   */
  const {ml_kem768} = require('../src/vendor/exports/@noble/post-quantum/ml-kem.js');
  const {publicKey, secretKey} = ml_kem768.keygen(new Uint8Array(64).fill(7));
  const {cipherText, sharedSecret} = ml_kem768.encapsulate(publicKey);
  assert.deepStrictEqual(ml_kem768.decapsulate(cipherText, secretKey), sharedSecret);
});

test('npm packs the vendored copies', () => {
  /*
   * npm could have dropped a nested node_modules from the tarball or a git
   * install. It does not (checked 2026-09-28) - this keeps it checked.
   */
  const [packed] = JSON.parse(execSync('npm pack --dry-run --json --ignore-scripts', {cwd: ROOT, encoding: 'utf8'}));
  const shipped = new Set(packed.files.map((f) => f.path.replace(/\\/g, '/')));
  for (const name of NAMES) {
    assert.ok(shipped.has(`src/vendor/node_modules/${name}/package.json`), `${name} is not in the packed tarball`);
  }
  assert.ok(shipped.has('src/vendor/exports/@noble/hashes/sha2.js'), 'the shims are not in the packed tarball');
});
