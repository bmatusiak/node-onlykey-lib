/*
 * transport/ble - an OnlyKey reached over Bluetooth Low Energy.
 *
 * The third sibling of transport/embedded and transport/usb, and like both of
 * them it is the NAME AND THE WIRING: everything shared lives in
 * src/transport/pipeTransport.js, and everything bus-specific lives below the
 * pipe, in the host.
 *
 *     const plugins = [hostPlugin, bleTransport, sessionPlugin, ...];
 *     plugins.config = { transport: { pipe: BlePipe } };
 *
 * ## What is on the other end
 *
 * A phone running ok-rn, publishing the OnlyKey vendor GATT service beside its
 * FIDO one: one characteristic the host writes, one the device notifies on. The
 * phone relays what arrives to its own key's VENDOR interface and notifies back
 * what the firmware produces, so what crosses this transport is exactly what
 * would cross a cable.
 *
 * ## ONLY ONE INTERFACE EXISTS ON THIS BUS, and that is the real difference
 *
 * USB presents four - KEYBOARD, FIDO, VENDOR, SEREMU - and the pipe demuxes
 * them. The radio carries VENDOR alone:
 *
 *   - KEYBOARD is not missing, it is DELIVERED ELSEWHERE. A paired phone types
 *     into the computer it is paired with, through Bluetooth HID, which is a
 *     different profile sharing nothing with GATT. Nothing here can capture it.
 *     See ok-rn's FINDING-a-ble-paired-phone-types-the-backup-to-the-paired-host.
 *   - FIDO has its own GATT service, spoken as CTAP rather than as reports. A
 *     host wanting it uses the platform's WebAuthn stack, not this.
 *   - SEREMU is a debug console that the phone does not publish.
 *
 * A pipe that carries one interface still reports it, so nothing above this
 * file changes: the demux simply never sees the other three. Refusing a write
 * to an interface the radio does not carry belongs to the PIPE, which is the
 * layer that knows what it is connected to - the same division that puts USB's
 * per-interface endpoint widths and its refusal to write to KEYBOARD in the USB
 * pipe rather than in transport/usb.js.
 *
 * ## The two rules a BLE pipe gets wrong first
 *
 * Both are properties of the contract rather than of this bus, and both are in
 * src/transport/contract.js - but they are what breaks a new pipe:
 *
 *   - DIR.OUT = 0 is DEVICE TO HOST and DIR.IN = 1 is host to device. Inverted
 *     from intuition, because the numbering is the emulator's. Get it wrong and
 *     every request() resolves with the bytes it just sent.
 *   - The pipe MUST ECHO ITS OWN WRITES with dir: DIR.IN. Like USB it sees only
 *     inbound traffic, and the transport's write event is fed from the echo.
 */
'use strict';

const { createPipeTransport } = require('../../src/transport/pipeTransport');

function setup(imports, register, config) {
  const { app } = imports;
  const settings = (config && config.transport) || {};

  const { transport, destroy } = createPipeTransport({
    name: 'ble',
    pipe: settings.pipe,
    EventEmitter: app.EventEmitter,
  });

  register(null, { transport, onDestroy: destroy });
}

setup.consumes = ['app'];
setup.provides = ['transport'];

module.exports = setup;
