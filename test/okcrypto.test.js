/*
 * plugins/okcrypto - the second plugin the session authorises.
 *
 * The device operations are not implemented yet (see the file's own header for
 * why: the derive path is CTAP-only, and the composite path needs a framing
 * that differs from the chunker's by one byte). So these test what IS here -
 * the crypto surface, the openpgp wiring, and the composition rules - plus the
 * one thing that matters most about an unfinished plugin: that it says so,
 * rather than failing somewhere unrelated.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const Rectify = require('@bmatusiak/rectify');
const hostPlugin = require('../plugins/host');
const embedded = require('../plugins/transport/embedded');
const sessionPlugin = require('../plugins/session');
const devicePlugin = require('../plugins/device');
const okcryptoPlugin = require('../plugins/okcrypto');
const { fakeFirmware } = require('./helpers/fake-firmware');

function start(plugins) {
  const pipe = fakeFirmware();
  plugins.config = { transport: { pipe } };
  return new Promise((resolve, reject) => {
    const app = Rectify.build(plugins, (err, started) => {
      if (err) reject(err);
      else resolve(started);
    });
    app.start();
  });
}

const FULL = () => [hostPlugin, embedded, sessionPlugin, devicePlugin, okcryptoPlugin];

/* ------------------------------------------------------------ composition */

test('device and okcrypto coexist as separate authorised consumers', async () => {
  /*
   * setup.allowed is [['device'], ['okcrypto']] - two groups of one, not one
   * group of two. The distinction is real: a single flat group would mean "a
   * plugin providing BOTH names", which no plugin does, and the session would
   * be unreachable.
   */
  const app = await start(FULL());
  assert.equal(typeof app.services.device.setPin, 'function');
  assert.equal(typeof app.services.okcrypto.registerPgpHooks, 'function');
  assert.equal('session' in app.services, false, 'still restricted from the registry');
  await app.destroy();
});

test('an unauthorised plugin cannot join by also consuming session', async () => {
  // The guarantee is worth re-asserting with okcrypto present: adding a second
  // legitimate consumer must not widen the door for a third.
  const nosy = (imports, register) => register(null, { snooper: {} });
  nosy.consumes = ['session'];
  nosy.provides = ['snooper'];

  await assert.rejects(() => start([...FULL(), nosy]), /snooper|allows|consume/);
});

/* ------------------------------------------------------------ the surface */

test('the device-free crypto is reachable through the service', async () => {
  const app = await start(FULL());
  const { okcrypto } = app.services;

  assert.equal(typeof okcrypto.age.encryptAgeFile, 'function');
  assert.equal(typeof okcrypto.pqc.buildRecipient, 'function');
  assert.equal(typeof okcrypto.composite.packBlob, 'function');
  assert.equal(okcrypto.composite.BLOB_LEN, 160);
  await app.destroy();
});

test('loading the plugin does not pull in the 1.2 MB PGP fork', async () => {
  /*
   * composite_pgp takes the openpgp instance as an argument rather than
   * importing one, and that is what keeps the fork off this plugin's
   * dependency graph. A caller doing age or X-Wing must not pay for PGP.
   */
  const { execFileSync } = require('child_process');
  const path = require('path');
  const loaded = execFileSync(
    process.execPath,
    ['-e', `require('./plugins/okcrypto');
      const hit = Object.keys(require.cache).filter((f) => f.includes('openpgp'));
      process.stdout.write(JSON.stringify(hit));`],
    { cwd: path.resolve(__dirname, '..'), encoding: 'utf8' },
  );
  assert.deepEqual(JSON.parse(loaded), []);
});

test('registerPgpHooks passes the service through as the device', async () => {
  // The hooks are registered against whatever object is handed over, so this
  // pins that it is the okcrypto service itself - the thing that will grow
  // composite_sign/composite_decrypt - and not some inner object.
  const app = await start(FULL());
  const { okcrypto } = app.services;

  let sawDevice = null;
  const fakeOpenpgp = {
    setHardwareHooks(hooks) {
      sawDevice = hooks;
    },
  };
  okcrypto.registerPgpHooks(fakeOpenpgp, 132);

  assert.ok(sawDevice, 'hooks were registered');
  assert.equal(typeof sawDevice.ecdh, 'function');
  assert.equal(typeof sawDevice.mlkemDecaps, 'function');
  await app.destroy();
});

/* -------------------------------------------------- honesty about the gap */

test('the plugin states which device operations it cannot do', async () => {
  /*
   * The alternative is worse than a missing method. composite_pgp registers
   * hooks against this object; if one is silently absent, the failure surfaces
   * from inside openpgp as a complaint about the PGP message, and the actual
   * cause - no CTAPHID transport - appears nowhere.
   */
  const app = await start(FULL());
  const ops = app.services.okcrypto.deviceOperations;

  assert.equal(ops.compositeSign, false);
  assert.equal(ops.compositeDecrypt, false);
  assert.equal(ops.deriveXwing, false);
  assert.match(ops.reason, /CTAPHID|IFACE\.FIDO/, 'and says what is missing');
  await app.destroy();
});

test('the crypto that needs no device works end to end through the service', async () => {
  /*
   * Proof the plugin is useful today rather than a placeholder: a full age
   * round trip, with the shared secret supplied directly instead of derived on
   * a device. That is exactly what the derive operations will provide later,
   * so this exercises everything downstream of them.
   */
  const app = await start(FULL());
  const { okcrypto } = app.services;
  const { toLatin1, fromLatin1 } = require('../src/bytes');

  const shared = new Uint8Array(32).fill(0x21);
  const ciphertext = new Uint8Array(1120).fill(0x43);
  const plaintext = fromLatin1('secrets, but only the ones that fit');

  const file = okcrypto.age.encryptAgeFile(plaintext, { ciphertext, sharedSecret: shared });
  const opened = await okcrypto.age.decryptAgeFile(file, async () => shared);

  assert.equal(toLatin1(opened), toLatin1(plaintext));
  await app.destroy();
});
