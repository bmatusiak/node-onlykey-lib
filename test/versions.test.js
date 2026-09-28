/*
 * The release table (src/versions), which every consumer's version matrix
 * reads: ok-rn's, node-onlykey-emulator's and the test kit's.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const versions = require('node-onlykey-lib/versions');
const { drift } = require('../scripts/versions-compat');

test('the table is reachable through the public subpath and lists the releases', () => {
  const all = versions.list();
  assert.ok(all.length >= 10, `only ${all.length} releases`);
  for (const v of ['v3.0.5', 'v3.0.4', 'v2.1.0', 'v0.2-beta.8']) assert.ok(all.includes(v), v);
});

test('every row is all pinned or all blank - never half a release', () => {
  for (const v of versions.list()) {
    assert.doesNotThrow(() => versions.pinsFor(v), v);
  }
  assert.equal(versions.pinsFor('v3.0.5'), null, 'v3.0.5 is the named-but-not-cut working tree');
  assert.deepEqual(versions.pinsFor('v3.0.4'),
    { libraries: 'c8804e3', 'OnlyKey-Firmware': '9600daa', file: 'Signed_OnlyKey_3_0_4_STD' });
});

test('an unknown release is refused by name', () => {
  assert.throws(() => versions.pinsFor('v9.9.9'), /not a known release/);
});

test('every compatibility row still matches capabilities() - regenerate with scripts/versions-compat.js --write', () => {
  for (const v of versions.list()) {
    const d = drift(v);
    assert.equal(d.length, 0,
      `${v}: ${d.map((x) => `${x.flag} recorded ${JSON.stringify(x.recorded)} expected ${JSON.stringify(x.expected)}`).join('; ')}`);
  }
});

test('the signed status of a release is what its compatibility row was made from', () => {
  assert.equal(versions.signedStatus('v3.0.4'), 'UNLOCKEDv3.0.4-prodc');
  assert.equal(versions.signedStatus('v0.2-beta.8'), 'UNLOCKEDv0.2-beta.8c');
  assert.equal(versions.compatibilityOf('v3.0.4').status, 'UNLOCKEDv3.0.4-prodc');
  assert.equal(versions.compatibilityOf('v3.0.4').capabilities.postQuantum, false);
  assert.equal(versions.compatibilityOf('v3.0.5').capabilities.postQuantum, true);
});
