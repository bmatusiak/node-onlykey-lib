'use strict';

/**
 * The Password Manager, as its own plugin folder (Brad, 2026-10-11: "i want the password manager
 * to act as its own plugin, keeping it easy to remove and work on seperatly"), like keychain/ and
 * edge/: it uses core (src/crypto/vault.js, vault_store.js, pbkdf2.js), core never uses it, and the
 * lib builds and passes its tests without this folder (scripts/check-without.js passwords).
 *
 * Namespaced like ./keychain: each part is its own module.
 */
module.exports = {
  manager: require('./manager'),
  inner: require('./inner'),
  legacy: require('./legacy'),
  mnemonic: require('./mnemonic'),
  totp: require('./totp'),
  derived: require('./derived'),
};
