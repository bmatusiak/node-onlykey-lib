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
  /* OpenSSH private keys, parsed here so keys.fromSshpk is reachable without sshpk. */
  openssh: require('./openssh'),
  /* Signed firmware files and the OKFWUPDATE frames; not yet run on hardware. */
  firmware: require('./firmware'),
  chunker: require('./chunker'),
  parsers: require('./parsers'),
  encoders: require('./encoders'),
  keystrokes: require('./keystrokes'),
  /* The slot field table, so a host form is driven by it rather than restated. */
  slotConfig: require('./slotConfig'),
};
