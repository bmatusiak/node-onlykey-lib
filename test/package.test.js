/*
 * The package surface.
 *
 * These exist because every other test in this suite requires modules by
 * RELATIVE path, so none of them touches package.json - and for a while every
 * entry point named in `main` and `exports` was missing. `npm test` was fully
 * green against a package that could not be required at all.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const pkg = require('../package.json');

test('every exports target exists on disk', () => {
  for (const [subpath, target] of Object.entries(pkg.exports)) {
    assert.ok(
      fs.existsSync(path.join(ROOT, target)),
      `${subpath} -> ${target} does not exist`,
    );
  }
});

test('every exports target actually loads', () => {
  for (const [subpath, target] of Object.entries(pkg.exports)) {
    assert.doesNotThrow(
      () => require(path.join(ROOT, target)),
      `${subpath} -> ${target} threw on require`,
    );
  }
});

test('main points at a real file and agrees with the "." export', () => {
  assert.ok(fs.existsSync(path.join(ROOT, pkg.main)), `main -> ${pkg.main} missing`);
  assert.equal(`./${pkg.main.replace(/\\/g, '/')}`, pkg.exports['.']);
});

test('files ships everything the exports map points into', () => {
  // `files` decides what npm publishes. A subpath resolving locally but
  // omitted from the tarball fails only for the people who install it.
  const shipped = new Set(pkg.files.map((f) => f.split('/')[0].replace(/\*.*$/, '')));
  for (const target of Object.values(pkg.exports)) {
    const top = target.replace(/^\.\//, '').split('/')[0];
    if (top === 'package.json') continue;
    assert.ok(shipped.has(top), `exports reaches ${top}/ but files does not ship it`);
  }
});

test('the vendored openpgp fork ships with the package', () => {
  // It lives under src/, so `files: ["src"]` covers it - but it is 1.2 MB of
  // the thing PGP needs, and shipping without it fails at require() time on a
  // user's machine rather than here.
  assert.ok(fs.existsSync(path.join(ROOT, 'src/vendor/openpgp/openpgp.js')));
  assert.ok(pkg.files.includes('src'));
});

/* ------------------------------------------------------------- the session */

test('the raw session module is not reachable, though the plugin is', () => {
  /*
   * Two different things share the word "session" and only one is dangerous.
   *
   * `plugins/session` MUST be exported - a host cannot compose a Rectify app
   * without naming the plugin, and the plugin is precisely what enforces
   * setup.allowed = [['device'], ['okcrypto']]. Consuming it gets you a
   * registration, not a key.
   *
   * `src/session/transit.js` must NOT be, because it hands over the transit
   * key derivation directly and answers to nobody. Rectify's allowed governs
   * the REGISTRY; it does nothing about a consumer writing
   * require('node-onlykey-lib/session'). Node's exports map is what closes
   * that door, and it closes it by omission - easy to undo by accident, hence
   * this test.
   */
  for (const [subpath, target] of Object.entries(pkg.exports)) {
    assert.ok(
      !/^\.\/src\/session\//.test(target),
      `${subpath} -> ${target} exposes the raw session module`,
    );
  }
  assert.equal(
    pkg.exports['./plugins/session'], './plugins/session/index.js',
    'the plugin itself stays exported - it is what enforces the restriction',
  );
});

test('the session plugin does not re-export transit through its own surface', () => {
  // Exporting the plugin is only safe while the plugin keeps the key to
  // itself. If it ever attached transit to its provides, the closed subpath
  // would be decoration.
  const plugin = require('../plugins/session');
  assert.equal(typeof plugin, 'function', 'a Rectify plugin is its setup function');
  assert.equal(typeof plugin.transit, 'undefined');
  assert.deepEqual(plugin.setup ? plugin.setup.allowed : plugin.allowed, [['device'], ['okcrypto']]);
});

test('the root index does not re-export the session either', () => {
  // Closing the subpath is pointless if the default export hands it over.
  const source = fs.readFileSync(path.join(ROOT, 'src/index.js'), 'utf8');
  assert.equal(/require\(['"]\.\/session/.test(source), false);
  assert.equal('session' in require('../src'), false);
});

/* ------------------------------------------------------------------- cost */

/*
 * Load cost has to be measured in a FRESH process.
 *
 * The tests above require every exports target, openpgp included, so by this
 * point require.cache holds it and any in-process check would be measuring
 * this file rather than a consumer. Deleting cache entries does not help
 * either: @noble's own internal requires stay resolved. A child process is the
 * only honest answer to "what does a consumer actually pay".
 */
const { execFileSync } = require('child_process');

function loadedModulesAfter(expr) {
  const script = `
    ${expr};
    const hit = Object.keys(require.cache).filter((f) =>
      f.includes('vendor') && f.includes('openpgp') || f.includes('post-quantum'));
    process.stdout.write(JSON.stringify(hit));
  `;
  return JSON.parse(execFileSync(process.execPath, ['-e', script], {
    cwd: ROOT, encoding: 'utf8',
  }));
}

test('requiring the package loads neither the PGP fork nor post-quantum', () => {
  // 1.2 MB of OpenPGP and the heaviest @noble package, to set a PIN.
  const hit = loadedModulesAfter("require('./src')");
  assert.deepEqual(hit, [], `eagerly loaded: ${hit.join(', ')}`);
});

test('touching the crypto getter does load post-quantum', () => {
  // The negative above would also pass if the export were simply broken.
  const hit = loadedModulesAfter(
    "const lib = require('./src'); if (typeof lib.crypto.pqc.mlkemKeypairFromSeed !== 'function') throw new Error('missing')",
  );
  assert.ok(hit.some((f) => f.includes('post-quantum')), 'the getter did not reach it');
  assert.equal(hit.some((f) => f.includes('openpgp')), false, 'but still not openpgp');
});

test('the PGP subpath is the only thing that loads the fork', () => {
  const hit = loadedModulesAfter("require('./src/crypto/pgp.js')");
  assert.ok(hit.some((f) => f.includes('openpgp')), 'the subpath must load it');
});

/* --------------------------------------------------------------- contents */

test('the namespaces carry what they claim to', () => {
  const lib = require('../src');
  assert.equal(typeof lib.bytes.toHex, 'function');
  assert.equal(typeof lib.protocol.msg.MSG.OKSETSLOT, 'number');
  assert.equal(typeof lib.protocol.okmsg.build, 'function');
  assert.equal(typeof lib.device.pin.validatePin, 'function');
  assert.equal(typeof lib.device.keys.prepareKey, 'function');
  assert.equal(typeof lib.transport.assertTransport, 'function');
});

test('the PGP subpath yields the fork itself, not a wrapper', () => {
  const pgp = require('../src/crypto/pgp.js');
  assert.equal(pgp, require('../src/vendor/openpgp/openpgp.js'));
  assert.equal(typeof pgp.setHardwareHooks, 'function');
});
