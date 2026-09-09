/*
 * Application crypto: age, post-quantum, and the composite PGP blob.
 *
 * Deliberately free of OpenPGP. composite_pgp takes an `openpgp` instance as
 * an argument rather than importing one, so this whole subtree costs only
 * @noble. The 1.2 MB fork is behind `node-onlykey-lib/crypto/pgp`, and
 * nothing here reaches for it.
 */
'use strict';

module.exports = {
  age: require('./age_file'),
  pqc: require('./age_pqc'),
  composite: require('./composite_pgp'),
  /*
   * Messages and files. Takes the openpgp instance as an argument like
   * composite does, so requiring this costs nothing until a caller hands it
   * the fork.
   */
  messages: require('./pgp_messages'),
  vault: require('./vault'),
  okconnect: require('./okconnect'),
};
