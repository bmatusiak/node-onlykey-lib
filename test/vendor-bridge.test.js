/*
 * The vendor-bridge ctap (src/transport/vendor-bridge.js): a request waiting for the key's answer ends when the key
 * goes away (cancel), at once - not at its timeout, holding the lane and the app's busy sheet that long.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createVendorBridgeCtap } = require('../src/transport/vendor-bridge');

/* a transport whose key never answers: writes go nowhere */
function silentTransport() {
  return { on: () => () => {}, write: async () => 64 };
}
const params = () => new Map([[3, [{ id: new Uint8Array(40).fill(7) }]]]);

test('cancel ends a waiting request with ECANCELED, before its timeout', async () => {
  const ctap = createVendorBridgeCtap(silentTransport(), { timeoutMs: 60000 });
  const asked = ctap.getAssertion(params());
  setImmediate(() => ctap.cancel());
  const started = Date.now();
  await assert.rejects(asked, (e) => e.code === 'ECANCELED');
  assert.ok(Date.now() - started < 1000);
});

test('cancel with nothing waiting does nothing; a later request still times out on its own', async () => {
  const ctap = createVendorBridgeCtap(silentTransport(), { timeoutMs: 50 });
  ctap.cancel();
  await assert.rejects(ctap.getAssertion(params()), (e) => e.code === 'ETIMEDOUT');
});
