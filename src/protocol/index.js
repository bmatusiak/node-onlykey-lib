/*
 * The wire protocol: what an OnlyKey message is, independent of how it travels.
 *
 * Namespaced rather than flattened. `msg` and `ctap` both carry a STATUS-ish
 * table and both have an `encode`, and merging them would make which one you
 * got depend on require order.
 */
'use strict';

module.exports = {
  msg: require('./msg'),
  okmsg: require('./okmsg'),
  ctap: require('./ctap'),
  chunk: require('./chunk'),
};
