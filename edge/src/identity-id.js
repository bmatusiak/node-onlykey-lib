'use strict';

/**
 * edge/src/identity-id.js - the id every Edge record is filed under (ok-edge B3.0; Brad, 2026-10-24:
 * "everything Edge keeps belongs to one identity").
 *
 * The OWNER key is derived from the key's secret with no salt, so it is the same on every device made
 * from one backup and different for a key from another backup. Its id: the first 16 bytes of SHA-256
 * over the owner key's ML-DSA-65 public key, as 32 lower-case hex characters. Pure, so a host that
 * already holds the owner key (a phone's statement, a test) names it the same way the plugin does
 * (edge.identityId()).
 */

const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { toHex } = require('../../src/bytes');
const chain = require('./chain');

const ID_HEX = 32;

/** the owner key's ML-DSA-65 public key -> the identity id */
function identityIdOf(ownerKeyPq) {
  if (!(ownerKeyPq instanceof Uint8Array) || ownerKeyPq.length !== chain.ML_DSA65.PK) {
    throw new TypeError(`edge: an identity is named from the owner key's ML-DSA-65 public key (${chain.ML_DSA65.PK} bytes)`);
  }
  return toHex(sha256(ownerKeyPq)).slice(0, ID_HEX);
}

/** is this an identity id as identityIdOf makes them? */
const isIdentityId = (s) => typeof s === 'string' && new RegExp(`^[0-9a-f]{${ID_HEX}}$`).test(s);

module.exports = { identityIdOf, isIdentityId, ID_HEX };
