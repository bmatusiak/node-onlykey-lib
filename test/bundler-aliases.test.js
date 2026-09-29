/*
 * node-onlykey-lib/bundler-aliases - the exports map as aliases, for bundlers
 * that predate package "exports" (webpack 4, the web app's). See
 * scripts/bundler-aliases.js for the spike that measured the need.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const {aliases, root} = require('node-onlykey-lib/bundler-aliases');
const pkg = require('../package.json');

test('every exported subpath has an alias, and every alias lands on disk', () => {
  const a = aliases();
  for (const subpath of Object.keys(pkg.exports)) {
    const request = 'node-onlykey-lib' + subpath.slice(1);
    const key = subpath.endsWith('/*') ? request.slice(0, -2) : `${request}$`;
    assert.ok(key in a, `${subpath} has no alias`);
    assert.ok(fs.existsSync(a[key]), `${key} -> ${a[key]} does not exist`);
  }
  assert.equal(Object.keys(a).length, Object.keys(pkg.exports).length);
});

test('an exact subpath cannot swallow a deeper one', () => {
  /* webpack's `$` suffix: 'node-onlykey-lib/crypto$' must not also match 'node-onlykey-lib/crypto/pgp'. */
  const a = aliases();
  assert.equal(a['node-onlykey-lib/crypto$'], path.join(root, 'src/crypto/index.js'));
  assert.equal(a['node-onlykey-lib/crypto/pgp$'], path.join(root, 'src/crypto/pgp.js'));
  assert.equal(a['node-onlykey-lib/vendor/@noble'], path.join(root, 'src/vendor/exports/@noble'));
});

test('an app that requires the library under another name gets its aliases', () => {
  const a = aliases({name: 'okl'});
  assert.ok('okl/crypto$' in a);
  assert.ok(!Object.keys(a).some((k) => k.startsWith('node-onlykey-lib')));
});
