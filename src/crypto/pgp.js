/*
 * The vendored PQC-aware OpenPGP.js fork, as its own subpath export.
 *
 * 1.2 MB parsed on first require, which is the entire reason it is not
 * reachable from the package root: connecting to a device, reading labels or
 * setting a PIN must not pay for a PGP implementation.
 *
 * Pass it in where it is needed:
 *
 *     const openpgp = require('node-onlykey-lib/crypto/pgp');
 *     const { composite } = require('node-onlykey-lib/crypto');
 *     composite.registerCompositeHooks(openpgp, device, slot);
 *
 * See vendor/openpgp/VENDORED.md for what this fork is and why it carries one
 * appended line.
 */
'use strict';

module.exports = require('../vendor/openpgp/openpgp.js');
