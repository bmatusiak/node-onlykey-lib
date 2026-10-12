'use strict';

/**
 * Guest Book (onlykey-edge/features/GUEST-BOOK-SPEC.md): a contacts list of other people's PUBLIC
 * keys, pinned by fingerprint. Its own plugin: core never requires this folder, and
 * `node scripts/check-without.js guestbook` proves the rest of the library stands without it.
 */
module.exports = {
  formats: require('./formats'),
  store: require('./store'),
  merge: require('./merge'),
  sources: require('./sources'),
  refresh: require('./refresh'),
};
