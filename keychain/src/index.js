'use strict';

/**
 * Key Chain: generate, store, import, derive and export keys for an OnlyKey
 * (hard or soft), keeping private keys as private as possible - made ON the
 * key where the firmware can, otherwise on the host in memory and wiped.
 *
 * Namespaced like ./device: each part is its own module.
 */
module.exports = {
  tag: require('./tag'),
  export: require('./export'),
  generate: require('./generate'),
  artifacts: require('./artifacts'),
  derive: require('./derive'),
  press: require('./press'),
  list: require('./list'),
  cert: require('./cert'),
  pgpImport: require('./pgp-import'),
};
