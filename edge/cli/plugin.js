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

/* the person's time to answer the app's approval sheet (as a budget's: 2 min), and the wire's margin past it */
const APPROVE_MS = 150000;

function setup(imports, register) {
  const { cli } = imports;
  require('./register')(cli.commands, cli.helpers);
  /*
   * THE APP APPROVES FIRST, THEN THE KEY IS PRESSED (Brad, 2026-11-03: "edge gives a prompt sheet, i press approve, and then
   * the key press"; "i dont know what i was approving"): a command whose key is the desktop app's asks the app on the Edge
   * wire (edge/src/pressask.js) before each request that waits for a press - what it is for, the message, the code - and
   * the app shows it as a budget is shown. Approve: the request goes to the key. Anything else: it never does. Here, not in
   * core (core never requires edge/): every command's start passes through this wrapper (cli aroundStart).
   */
  cli.aroundStart((start) => async (opts) => {
    const app = await start(opts);
    const okcrypto = app && app.services && app.services.okcrypto;
    /*
     * only a stack that really speaks through the desktop app's pipe (cli/desktop.js throughDesktopApp) - not a fake key a
     * test gives (with an app running on the machine, the options still said desktop, and the ask waited on no app)
     */
    if (!(app && app.throughDesktopApp) || (opts && opts.ble) || !okcrypto || typeof okcrypto.setBeforePress !== 'function') return app;
    const { wire, pressAsk } = require('../src');
    const channel = wire.createWireChannel(app.services.transport, { timeoutMs: APPROVE_MS });
    okcrypto.setBeforePress(async ({ what, subject, code }) => {
      const a = await channel.send(pressAsk.build({ what: what || 'a press', subject, code }), { timeoutMs: APPROVE_MS });
      if (a && a.ok) return;
      const why = !a ? 'no answer' : a.refusal === 'declined' ? 'declined' : a.detail || a.refusal || 'refused';
      throw Object.assign(new Error(`the desktop app: ${why} - the key was not asked`), { code: 'EPRESSDECLINED' });
    });
    return app;
  });
  register(null, { edge: new EventEmitter() });
}

setup.consumes = ['cli', 'keychain'];
setup.provides = ['edge'];

module.exports = setup;
