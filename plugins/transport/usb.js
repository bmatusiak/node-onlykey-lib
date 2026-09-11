/*
 * transport/usb - a physical OnlyKey on a USB bus.
 *
 * The sibling of transport/embedded. It was, deliberately, a near-copy of it
 * while the two were being proven against real hardware for the first time -
 * a broken suite then could have been either the new bus or a refactor. Both
 * are green (the hard key connects, unlocks, types a slot and reads it back),
 * so the common part is now src/transport/pipeTransport.js and this file is
 * the name and the wiring.
 *
 * Like its sibling it does NOT import react-native or reach for a native
 * module. The host passes in a byte pipe through Rectify config:
 *
 *     const plugins = [hostPlugin, usbTransport, sessionPlugin, ...];
 *     plugins.config = { transport: { pipe: UsbPipe } };
 *
 * THE PIPE CONTRACT is the same one embedded uses, and that is the point: the
 * session, the device plugin, the crypto plugin and every screen above them are
 * written once and work against either key.
 *
 * ## What differs from embedded, and where each difference lives
 *
 * Only one difference is in this file: the name. The rest belong BELOW the
 * pipe, because they are properties of the bus rather than of the
 * demultiplexing:
 *
 *   - A USB pipe physically sees inbound reports only. Rather than make the
 *     transport cope with a half-silent pipe, the HOST echoes its own writes -
 *     so `dir` means the same thing on both pipes.
 *   - Endpoint widths differ per interface, and the debug console's outbound
 *     endpoint is 32 bytes where the others are 64. The layer that knows the
 *     endpoints enforces that.
 *   - A write to the keyboard interface is refused, because it is device to
 *     host only. The emulator refuses it natively for the same reason.
 *   - Which interface is which is decided by HID usage page, not by position;
 *     three of the four are otherwise identical on the wire. See
 *     src/transport/usbDescriptors.js and ok-rn's FINDING #40.
 */
'use strict';

const { createPipeTransport } = require('../../src/transport/pipeTransport');

function setup(imports, register, config) {
  const { app } = imports;
  const settings = (config && config.transport) || {};

  const { transport, destroy } = createPipeTransport({
    name: 'usb',
    pipe: settings.pipe,
    EventEmitter: app.EventEmitter,
  });

  register(null, { transport, onDestroy: destroy });
}

setup.consumes = ['app'];
setup.provides = ['transport'];

module.exports = setup;
