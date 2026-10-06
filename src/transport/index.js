/*
 * The transport seam.
 *
 * Only the contract lives here. Concrete transports are Rectify plugins
 * (plugins/transport/) because each one needs platform wiring that this
 * package must not reach for on its own - an embedded emulator handle, a USB
 * OTG permission grant, a WebAuthn credential.
 */
'use strict';

module.exports = {
  ...require('./contract'),

  /*
   * What the device looks like on a USB bus - the interface table, and how to
   * tell apart interfaces that are identical in every other respect.
   *
   * Namespaced rather than spread, because these are facts about ONE transport
   * while the contract is the seam every transport meets. A host that never
   * touches USB should not find `parseUsage` beside `assertTransport`.
   */
  usb: require('./usbDescriptors'),

  /*
   * The key's lane (one conversation at a time; urgent goes to the front -
   * rule 8). Exported for a host that relays another computer's requests to
   * the key (ok-rn's Bluetooth bridge) and its tests.
   */
  lane: require('./lane'),
};
