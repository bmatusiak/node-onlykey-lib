'use strict';

/**
 * EDGE, THE CLI PLUGIN (step 3; Brad, 2026-10-07). It adds `edge …` to the CLI
 * (register.js) and provides `edge`. It consumes `keychain`: `edge setup` files the
 * agent's certificate in this computer's Key Chain list, and the testnet keeps a
 * Key Chain file of its own - so a build without Key Chain refuses Edge and names
 * it (Rectify), the dependency stated once. Edge's sync never carries the list. Core never requires this
 * folder; left out, there is no `edge` command.
 *
 * An emitter, as every feature plugin is (Brad, 2026-10-07); its events come as
 * code needs them ("we will find out").
 */
const { EventEmitter } = require('events');

function setup(imports, register) {
  const { cli } = imports;
  require('./register')(cli.commands, cli.helpers);
  register(null, { edge: new EventEmitter() });
}

setup.consumes = ['cli', 'keychain'];
setup.provides = ['edge'];

module.exports = setup;
