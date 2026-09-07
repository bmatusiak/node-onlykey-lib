/*
 * The library as an actual rectify app.
 *
 * Two things these tests establish that unit tests cannot.
 *
 * The memory transport derives its session key the way the firmware does -
 * real X25519, real beforenm, real SHA-256 - rather than returning a canned
 * reply. So "both sides agree on the key" is a genuine assertion, and a broken
 * derivation fails here instead of surviving until it meets hardware.
 *
 * And the session is reached the way a real consumer must reach it: through a
 * permitted plugin's imports. `setup.allowed` is stronger than "you may not
 * consume this" - a restricted service is never announced, so it is absent
 * from app.services entirely. Tests that poke at app.services.session would be
 * testing a path the design forbids.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const Rectify = require('@bmatusiak/rectify');

const hostPlugin = require('../plugins/host');
const memoryTransport = require('../plugins/transport/memory');
const sessionPlugin = require('../plugins/session');
const transit = require('../src/session/transit');
const { toHex } = require('../src/bytes');

/** Build and start an app, resolving once every plugin has registered. */
function start(plugins) {
  return new Promise((resolve, reject) => {
    const app = Rectify.build(plugins, (err, started) => {
      if (err) reject(err);
      else resolve(started);
    });
    app.start();
  });
}

/**
 * A stand-in for the real device plugin, which is in `allowed`.
 *
 * It hands the session back out so a test can drive it - which a genuine
 * consumer would not do, but is the only way to assert on a service the
 * registry deliberately hides.
 */
function harness(onSession) {
  function setup(imports, register) {
    onSession(imports.session);
    register(null, { device: { session: imports.session } });
  }
  setup.consumes = ['session'];
  setup.provides = ['device'];
  return setup;
}

/** Start an app and return {app, session, transport}. */
async function startWithSession(extra = []) {
  let session = null;
  const app = await start([
    hostPlugin, memoryTransport, sessionPlugin,
    harness((s) => { session = s; }),
    ...extra,
  ]);
  return { app, session, transport: app.services.transport };
}

test('the app builds and the unrestricted services register', async () => {
  const { app } = await startWithSession();
  try {
    assert.ok(app.services.host, 'host');
    assert.ok(app.services.transport, 'transport');
    assert.equal(app.services.transport.name, 'memory');
  } finally {
    await app.destroy();
  }
});

test('a restricted service is absent from the registry, not merely unconsumable', async () => {
  const { app } = await startWithSession();
  try {
    assert.equal(app.services.session, undefined, 'session is never announced');
    assert.ok(app.services.device.session, 'but a permitted plugin holds it');
  } finally {
    await app.destroy();
  }
});

test('rectify orders the load from consumes/provides, not the array order', async () => {
  // session consumes transport, so it must load after it however it is listed.
  let session = null;
  const app = await start([
    harness((s) => { session = s; }), sessionPlugin, memoryTransport, hostPlugin,
  ]);
  try {
    assert.ok(session, 'the harness received a built session');
  } finally {
    await app.destroy();
  }
});

test('OKCONNECT completes and both sides derive the same key', async () => {
  const { app, session, transport } = await startWithSession();
  try {
    assert.equal(session.established, false, 'no key before connect');
    const result = await session.connect();

    assert.equal(session.established, true);
    assert.equal(result.status, memoryTransport.DEFAULT_STATUS);
    assert.equal(result.sealed, true, 'the status tail was boxed');

    // The real assertion: client and device independently derived the same 32
    // bytes. A wrong beforenm yields a plausible key and a device that answers
    // noise, so this is what catches it.
    const probe = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
    const opened = transit.box(transport.sessionKey, session.box(probe));
    assert.deepEqual(Array.from(opened), Array.from(probe));
  } finally {
    await app.destroy();
  }
});

test('the OKCONNECT payload goes out unencrypted', async () => {
  // It IS the key exchange; boxing it would need a key neither side has yet.
  const { app, session, transport } = await startWithSession();
  try {
    const writes = [];
    transport.on('write', (e) => writes.push(e.data));
    await session.connect();

    assert.equal(writes.length, 1);
    assert.deepEqual(
      Array.from(writes[0].subarray(0, 5)),
      [0xff, 0xff, 0xff, 0xff, 0xe4],
      'the frame header is in the clear',
    );
    assert.equal(writes[0].length, 43);
  } finally {
    await app.destroy();
  }
});

test('box() before connect() throws rather than passing bytes through', async () => {
  // Sending unboxed bytes to a device expecting boxed ones is decrypted into
  // noise and dispatched, with no error at any layer. Failing loudly is the
  // only place it can be caught.
  const { app, session } = await startWithSession();
  try {
    assert.throws(() => session.box(new Uint8Array(4)), /no session/);
  } finally {
    await app.destroy();
  }
});

test('reconnecting rekeys rather than reusing the keystream', async () => {
  const { app, session } = await startWithSession();
  try {
    await session.connect();
    const first = toHex(session.box(new Uint8Array(16)));
    await session.connect();
    const second = toHex(session.box(new Uint8Array(16)));

    // Same plaintext, different session. Identical output would mean the key
    // was reused, widening keystream reuse beyond a single session.
    assert.notEqual(first, second, 'a fresh keypair per connect');
  } finally {
    await app.destroy();
  }
});

test('destroy() forgets the session key', async () => {
  const { app, session } = await startWithSession();
  await session.connect();
  assert.equal(session.established, true);

  await app.destroy();
  assert.equal(session.established, false, 'onDestroy cleared it');
});

test('allowed blocks a plugin that is not permitted to consume the session', async () => {
  // The point of setup.allowed: a logging or UI plugin asking for "session"
  // must fail at build(), not quietly receive key material.
  function nosy(imports, register) { register(null, { snooper: {} }); }
  nosy.consumes = ['session'];
  nosy.provides = ['snooper'];

  await assert.rejects(
    start([hostPlugin, memoryTransport, sessionPlugin, nosy]),
    /allows only|session/i,
  );
});

test('allowed groups are per-plugin, so okcrypto is admitted separately', async () => {
  // A flat allowed list would be the ONE-plugin shorthand and reject this.
  function okcrypto(imports, register) {
    assert.ok(imports.session);
    register(null, { okcrypto: {} });
  }
  okcrypto.consumes = ['session'];
  okcrypto.provides = ['okcrypto'];

  const { app } = await startWithSession([okcrypto]);
  try {
    assert.ok(app.services.okcrypto);
  } finally {
    await app.destroy();
  }
});

test('a transport missing a contract method fails at build, naming the gap', async () => {
  // Validation lives in the consumer, so it applies to every transport rather
  // than only the ones that remember to self-check.
  function broken(imports, register) {
    register(null, { transport: { open() {}, close() {}, isOpen() {} } });
  }
  broken.consumes = ['app'];
  broken.provides = ['transport'];

  await assert.rejects(
    start([hostPlugin, broken, sessionPlugin, harness(() => {})]),
    /write|request|on/,
  );
});
