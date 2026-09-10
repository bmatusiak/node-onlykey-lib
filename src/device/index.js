/*
 * Device management: slots, PINs, keys, backups, firmware.
 *
 * Everything above the wire and below a GUI. Namespaced - `keys` and
 * `encoders` both talk about key material and mean different things by it.
 */
'use strict';

module.exports = {
  version: require('./version'),
  slots: require('./slots'),
  pin: require('./pin'),
  press: require('./press'),
  keys: require('./keys'),
  chunker: require('./chunker'),
  parsers: require('./parsers'),
  encoders: require('./encoders'),
  keystrokes: require('./keystrokes'),
};
