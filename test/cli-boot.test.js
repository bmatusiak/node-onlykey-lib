/*
 * THE CLI'S BOOT (step 3a): core and the feature plugins, built with Rectify. Written in
 * Rectify's own harness (Brad, 2026-10-07: "rectify's harness"), where a test can be a
 * plugin: it consumes the services under test like any other plugin. run() returns its
 * verdict as data, so this one node:test test hosts the suites and asserts none failed.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('events');
const { boot } = require('../cli/boot');
const core = require('../cli/core');
const keychain = require('../keychain/cli/plugin');
const edge = require('../edge/cli/plugin');

/* a fresh command table with the one command Key Chain extends */
const table = () => ({ gpg: { options: { skey: { type: 'string' } }, run: async () => 0 } });
const helpers = { NAME: 'onlykey-js', CliError: Error, usage: (m) => new Error(m), row: (k, v) => `${k} ${v}` };

const h = require('@bmatusiak/rectify/harness.js').create();

h.describe('the CLI boot (Rectify)', () => {
  h.it('core alone builds: the cli service, no keychain or edge command', async ({ assert: a }) => {
    const COMMANDS = table();
    const app = await boot([core], { COMMANDS, helpers });
    a.ok(app.services.cli && typeof app.services.cli.command === 'function', 'core provides cli');
    a.ok(!COMMANDS.keychain && !COMMANDS.edge, 'no feature commands without their plugins');
    a.ok(!COMMANDS.gpg.options['import-pub'] && !COMMANDS.gpg.slotCertificate, 'gpg has no slot mode without Key Chain');
  });

  h.it('core + Key Chain: the keychain command, gpg --import-pub and its slot step, and the emitter', async ({ assert: a }) => {
    const COMMANDS = table();
    const app = await boot([keychain, core], { COMMANDS, helpers });
    a.ok(COMMANDS.keychain && typeof COMMANDS.keychain.run === 'function', 'keychain command');
    a.ok(COMMANDS.gpg.options['import-pub'], 'gpg --import-pub');
    a.equal(typeof COMMANDS.gpg.slotCertificate, 'function');
    a.ok(app.services.keychain instanceof EventEmitter, 'Key Chain is an emitter');
  });

  h.it('Edge without Key Chain: build() refuses and names keychain', async ({ assert: a }) => {
    let err = null;
    try {
      await boot([edge, core], { COMMANDS: table(), helpers });
    } catch (e) {
      err = e;
    }
    a.ok(err, 'refused');
    a.ok(/keychain/.test(String(err && (err.message || err))), `names keychain: ${err && err.message}`);
  });

  h.it('core + Key Chain + Edge, in any order: the edge command', async ({ assert: a }) => {
    const COMMANDS = table();
    const app = await boot([edge, core, keychain], { COMMANDS, helpers });
    a.ok(COMMANDS.edge && COMMANDS.keychain, 'both commands');
    a.ok(app.services.edge instanceof EventEmitter, 'Edge is an emitter');
  });

  h.it('a test plugin consumes keychain like any plugin and hears what it records', async ({ assert: a }) => {
    const heard = [];
    function listener(imports, register) {
      imports.keychain.on('recorded', (e) => heard.push(e));
      register(null, { listener: {} });
    }
    listener.consumes = ['keychain'];
    listener.provides = ['listener'];
    const COMMANDS = table();
    const app = await boot([listener, keychain, core], { COMMANDS, helpers });
    const full = { err: () => {} };
    const start = app.services.cli.wrapStart(async () => ({}), { name: 'status', io: { keychainRecord: () => {} }, full });
    a.equal(typeof start, 'function', 'the wrapped start');
    a.equal(typeof full.keychainRecord, 'function', 'Key Chain put its recorder on the run');
    full.keychainRecord({ label: 'x' });
    a.equal(heard.length, 1, 'the listener heard the record');
    a.equal(heard[0].label, 'x');
  });
});

test('the CLI boot, in Rectify\'s harness', async () => {
  const r = await h.run({ log: () => {} });
  const failed = r.suites.flatMap((s) => s.tests.filter((t) => !t.ok).map((t) => `${t.name}: ${t.error}`));
  assert.deepEqual(failed, []);
  assert.ok(r.passed >= 5, `ran ${r.passed}`);
});
