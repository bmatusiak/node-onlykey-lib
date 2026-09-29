/*
 * node-onlykey-lib/browser - the stack a web page composes, in one call.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { startBrowser } = require('node-onlykey-lib/browser');

const credentials = { get: async () => { throw new Error('not reached in these tests'); } };

test('composes the tunnel-only stack a page uses', async () => {
  const app = await startBrowser({ credentials });
  assert.deepEqual(Object.keys(app.services).sort(), ['app', 'device', 'host', 'okcrypto', 'transport']);
  assert.equal(app.services.transport.tunnelOnly, true);
  assert.equal(typeof app.services.okcrypto.connectTunnel, 'function');
  await app.destroy();
});

test('refuses to start without credentials rather than reaching for a global', async () => {
  await assert.rejects(() => startBrowser({}), /needs \{ credentials \}/);
});

