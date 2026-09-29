/*
 * bundler-aliases.js - this library's public subpaths as bundler aliases.
 *
 *   const lib = require('node-onlykey-lib/bundler-aliases');
 *   resolve: { alias: { ...lib.aliases() } },
 *   module: { rules: [{ test: /\.m?js$/, include: [lib.root], use: 'babel-loader' }] },
 *   node: { crypto: 'empty' },
 *
 * WHY. webpack 4 - the web app's bundler (apps.onlykey.io 4.0.0) - predates
 * package "exports", so `require('node-onlykey-lib/crypto')` looks for a
 * `crypto` folder at the package root and fails, and only the subpaths that
 * happen to be real paths (plugins/...) resolve. Measured 2026-09-28 in a
 * webpack 4.47 spike. One alias per exported subpath, generated from the
 * exports map itself, makes an old bundler resolve exactly what Node does - and
 * because it is generated, a new export needs no edit in any consumer.
 *
 * The other two lines above, from the same spike:
 *   - babel over `root`: webpack 4's parser does not know the syntax this
 *     library and its vendored @noble use (BigInt literals, `??`, `?.`).
 *     preset-env `{ targets: { esmodules: true }, modules: false }` is enough.
 *   - `node: { crypto: 'empty' }` is OPTIONAL: the vendored tweetnacl names
 *     Node's `crypto` for a branch a browser never takes, so without it
 *     webpack 4 bundles a crypto polyfill for nothing. But only set it when
 *     nothing else in the app needs that polyfill - the web app's other
 *     dependencies already bundle it, so it leaves this alone.
 * With those three the whole stack - host, tunnel transport, session, device,
 * okcrypto, the webauthn ctap, crypto and the PGP fork - bundled and composed.
 *
 * Build-time Node code, which is why it lives in scripts/ and not src/ (src/
 * stays free of Node built-ins so it bundles for a browser).
 */
'use strict';

const path = require('path');

const ROOT = path.resolve(__dirname, '..');

/**
 * {"node-onlykey-lib/crypto$": "<root>/src/crypto/index.js", ...}
 *
 * An exact subpath gets a `$` alias (webpack's exact match), so it cannot
 * swallow a deeper path. A pattern subpath ("./vendor/@noble/*") becomes a
 * prefix alias to its directory.
 *
 * @param {object} [opts]
 * @param {string} [opts.name]  the package name as the app requires it
 * @param {string} [opts.root]  this library's directory (default: where this file is)
 */
function aliases({ name = 'node-onlykey-lib', root = ROOT } = {}) {
  const { exports: map } = require(path.join(root, 'package.json'));
  const out = {};
  for (const [subpath, target] of Object.entries(map)) {
    const request = name + subpath.slice(1);
    if (subpath.endsWith('/*')) {
      out[request.slice(0, -2)] = path.join(root, target.slice(0, -2));
    } else {
      out[`${request}$`] = path.join(root, target);
    }
  }
  return out;
}

module.exports = { aliases, root: ROOT };
