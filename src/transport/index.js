/*
 * The transport seam.
 *
 * Only the contract lives here. Concrete transports are Rectify plugins
 * (plugins/transport/) because each one needs platform wiring that this
 * package must not reach for on its own - an embedded emulator handle, a USB
 * OTG permission grant, a WebAuthn credential.
 */
'use strict';

module.exports = require('./contract');
