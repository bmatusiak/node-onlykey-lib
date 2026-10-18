'use strict';

/**
 * Cryptobox (onlykey-edge/features/CRYPTOBOX-SPEC.md): messages kept chat-style, one thread per
 * person, stored ONLY as encrypted or signed PGP blocks. Its own plugin: core never requires this
 * folder, and `node scripts/check-without.js cryptobox` proves the rest of the library stands
 * without it.
 */
module.exports = {
  store: require('./store'),
};
