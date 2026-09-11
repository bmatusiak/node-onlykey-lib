/*
 * transport/embedded - the firmware running in this process.
 *
 * On Android the OnlyKey firmware is compiled to a .so and runs on its own
 * thread behind JNI, so "the device" is a function call away rather than a bus
 * away. This plugin is the seam between that and the rest of the library.
 *
 * It does NOT import react-native, or reach for a TurboModule. The host passes
 * in a byte pipe through Rectify config:
 *
 *     const plugins = [hostPlugin, embeddedTransport, sessionPlugin, ...];
 *     plugins.config = { transport: { pipe: OkEmu } };
 *
 * Two reasons. The library has to stay loadable in Node, a browser and nw.js,
 * where that module does not exist and importing it is a hard failure at
 * require time rather than a graceful absence. And a pipe is a small enough
 * surface to fake, so everything below can be tested without a device - which
 * is the only way the normalisation rules get tested at all.
 *
 * Everything the transport DOES - the pipe contract, the demultiplexing, the
 * request/reply matching - is src/transport/pipeTransport.js, shared with
 * transport/usb. This file is the name and the wiring.
 */
'use strict';

const { createPipeTransport } = require('../../src/transport/pipeTransport');

function setup(imports, register, config) {
  const { app } = imports;
  const settings = (config && config.transport) || {};

  const { transport, destroy } = createPipeTransport({
    name: 'embedded',
    pipe: settings.pipe,
    EventEmitter: app.EventEmitter,
  });

  register(null, { transport, onDestroy: destroy });
}

setup.consumes = ['app'];
setup.provides = ['transport'];

module.exports = setup;
