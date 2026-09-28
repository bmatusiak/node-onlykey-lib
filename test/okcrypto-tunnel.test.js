/*
 * okcrypto over a SUPPLIED ctap, with no vendor interface at all - the shape a
 * browser composes.
 *
 * The device is test/helpers/fake-tunnel-device.js, which does what
 * bridge_to_onlykey() does with a keyhandle rather than what a host would like
 * it to: it authenticates (v2) or decrypts (v1) the WHOLE data region, splits
 * it into 57-byte packets, drops a repeated opt3, and keeps a served reply
 * staged until it has been quiet for a while. So a request that is sealed
 * wrongly, chunked wrongly or numbered wrongly produces the wrong answer or no
 * answer here, the way it would on a key.
 *
 * Both framings are covered: v3.0.5 (transit v2, the version that decides it
 * read from the tunnel connect) and v3.0.4, the compatibility target (the v1
 * box, no tag).
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const Rectify = require('@bmatusiak/rectify');
const hostPlugin = require('../plugins/host');
const tunnelTransport = require('../plugins/transport/tunnel');
const sessionPlugin = require('../plugins/session');
const devicePlugin = require('../plugins/device');
const okcryptoPlugin = require('../plugins/okcrypto');
const composite = require('../src/crypto/composite_pgp');
const okconnect = require('../src/crypto/okconnect');
const chunk = require('../src/protocol/chunk');
const { MSG } = require('../src/protocol/msg');
const { IFACE } = require('../src/transport/contract');
const { challengeDigits } = require('../src/protocol/challenge');
const { fakeTunnelDevice, resultFor } = require('./helpers/fake-tunnel-device');

/*
 * The fake's staged replies expire after 30 ms of quiet; the plugin is told the
 * window is 40. On a key the two are 5000 and 5500 - see STAGED_WIPE_MS.
 */
function start(device, okcrypto = {}) {
  const plugins = [hostPlugin, tunnelTransport, sessionPlugin, devicePlugin, okcryptoPlugin];
  plugins.config = { okcrypto: { ctap: device, stagedWipeMs: 40, ...okcrypto } };
  return new Promise((resolve, reject) => {
    const app = Rectify.build(plugins, (err, started) => (err ? reject(err) : resolve(started)));
    app.start();
  });
}

/** A confirm() that enters the digits it is shown, as a person would. */
const pressing = (device, seen = []) => async ({ digits }) => {
  seen.push(digits);
  device.enter(digits);
};

const FAST = { pollIntervalMs: 2, timeoutMs: 3000 };
const DIGEST = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const halfPayload = (half, digest) => Uint8Array.from([half, ...digest]);

/* ------------------------------------------------------------ composition */

test('a browser composes with no vendor interface, and the vendor side refuses by name', async () => {
  const app = await start(fakeTunnelDevice());
  const { transport } = app.services;
  assert.equal(transport.tunnelOnly, true);
  assert.equal(transport.isOpen(), false);
  await assert.rejects(
    transport.write(IFACE.VENDOR, new Uint8Array(64)),
    (err) => err.code === 'NO_VENDOR_INTERFACE' && /only\s+through the WebAuthn tunnel/.test(err.message),
  );
  /* A vendor-only operation fails at its write, and leaves no timer behind. */
  await assert.rejects(app.services.okcrypto.sign(1, [1, 2, 3], { timeoutMs: 60000 }), /no vendor interface/);
  await app.destroy();
});

test('connectTunnel refuses when no ctap was supplied - the vendor session reads the version there', async () => {
  const { fakeFirmware } = require('./helpers/fake-firmware');
  const embedded = require('../plugins/transport/embedded');
  const plugins = [hostPlugin, embedded, sessionPlugin, devicePlugin, okcryptoPlugin];
  plugins.config = { transport: { pipe: fakeFirmware() } };
  const app = await new Promise((resolve, reject) => {
    const built = Rectify.build(plugins, (err, started) => (err ? reject(err) : resolve(started)));
    built.start();
  });
  await assert.rejects(app.services.okcrypto.connectTunnel(), /session\.connect\(\)/);
  await app.destroy();
});

/* ---------------------------------------------------- 3a: the tunnel connect */

test('connectTunnel reads the version from the PLAIN connect reply: v3.0.5 is transit v2', async () => {
  const device = fakeTunnelDevice({ firmware: 'v3.0.5-prodc' });
  const app = await start(device);

  const connected = await app.services.okcrypto.connectTunnel();
  assert.equal(connected.status, 'UNLOCKEDv3.0.5-prodc');
  assert.equal(connected.capabilities.transitV2, true);
  assert.equal(connected.identity.version, 'v3.0.5-prodc');

  assert.equal(device.requests.length, 1, 'one ceremony, so one browser prompt');
  const [req] = device.requests;
  assert.equal(req.cmd, okconnect.OKCONNECT);
  assert.equal(req.opt1, 0, 'no key action - a plain connect');
  assert.equal(req.opt3, 0, 'opt3 = 0, or the device would seal its own public key');
  await app.destroy();
});

test('connectTunnel on v3.0.4 - the compatibility target - reads transit v1', async () => {
  const app = await start(fakeTunnelDevice({ firmware: 'v3.0.4-prodc' }));
  const connected = await app.services.okcrypto.connectTunnel();
  assert.equal(connected.capabilities.transitV2, false);
  await app.destroy();
});

test('a locked device or an untrusted origin is named, not timed out', async () => {
  const app = await start(fakeTunnelDevice({ webcryptLevel: 0 }));
  await assert.rejects(app.services.okcrypto.connectTunnel(), /EXTENSION_NOT_SUPPORTED/);
  await app.destroy();
});

/* ------------------------------------------- 3b/3c: v3.0.5, transit v2 seal */

test('v3.0.5: composite_sign (Ed25519) - sealed request, three-button challenge, v2-framed result opened', async () => {
  const device = fakeTunnelDevice({ firmware: 'v3.0.5-prodc' });
  const app = await start(device);
  const seen = [];

  const sig = await app.services.okcrypto.composite_sign(
    3, composite.HALF_ECC, DIGEST, { ...FAST, confirm: pressing(device, seen) },
  );

  const payload = halfPayload(composite.HALF_ECC, DIGEST);
  assert.deepEqual(Uint8Array.from(sig), resultFor(MSG.OKSIGN, payload),
    'the device signed exactly the payload the host sent, and the frame opened');
  assert.deepEqual(seen, [challengeDigits(payload, { formula: 'modern' })],
    'confirm() was handed the same digits the vendor path computes');

  const [connect, sign, ...polls] = device.requests;
  assert.equal(connect.cmd, okconnect.OKCONNECT, 'no session yet, so it connected first');
  assert.equal(sign.cmd, MSG.OKSIGN);
  assert.equal(sign.opt1, 3, 'the slot rides opt1, outside the seal');
  assert.equal(sign.opt2, 1, 'one keyhandle, so it is the final one');
  assert.equal(sign.length, payload.length + 20, 'sealed: counter(4) + ciphertext + tag(16), unpadded');
  assert.equal(sign.authFailed, undefined);
  assert.ok(polls.length >= 1 && polls.every((p) => p.cmd === MSG.OKPING && p.opt3 === 0));
  assert.ok(polls.every((p) => !p.authFailed), 'the polls are sealed too');
  await app.destroy();
});

test('v3.0.5: composite_sign (ML-DSA-65) collects 3329 framed bytes across 512-byte polls', async () => {
  const device = fakeTunnelDevice({ firmware: 'v3.0.5-prodc' });
  const app = await start(device);

  const sig = await app.services.okcrypto.composite_sign(
    3, composite.HALF_PQC, DIGEST, { ...FAST, confirm: pressing(device) },
  );
  assert.equal(sig.length, composite.MLDSA_SIG_LEN);
  assert.deepEqual(Uint8Array.from(sig), resultFor(MSG.OKSIGN, halfPayload(composite.HALF_PQC, DIGEST)));
  const pings = device.requests.filter((r) => r.cmd === MSG.OKPING);
  assert.ok(pings.length >= Math.ceil(3329 / 512), `only ${pings.length} polls for 7 chunks`);
  await app.destroy();
});

test('v3.0.5: an ML-KEM ciphertext goes as 171-byte sealed chunks, numbered upward, one counter per key', async () => {
  const device = fakeTunnelDevice({ firmware: 'v3.0.5-prodc' });
  const app = await start(device);
  const ct = Uint8Array.from({ length: 1088 }, (_, i) => (i * 7) & 0xff);

  const ss = await app.services.okcrypto.composite_decrypt(5, ct, { ...FAST, confirm: pressing(device) });
  assert.deepEqual(Uint8Array.from(ss), resultFor(MSG.OKDECRYPT, ct));

  const chunks = device.requests.filter((r) => r.cmd === MSG.OKDECRYPT);
  assert.deepEqual(chunks.map((c) => c.length), [191, 191, 191, 191, 191, 191, 82],
    'six 171-byte chunks (3 whole packets) and the 62-byte rest, each +20');
  assert.deepEqual(chunks.map((c) => c.opt2), [0, 0, 0, 0, 0, 0, 1], 'opt2 on the final chunk only');
  for (let i = 1; i < chunks.length; i++) {
    assert.ok(chunks[i].opt3 > chunks[i - 1].opt3, 'opt3 strictly increases within the operation');
  }
  assert.deepEqual(chunks.map((c) => c.counter), [0, 1, 2, 3, 4, 5, 6], 'the host counter starts at 0 on a fresh key');
  const lastCounter = Math.max(...device.requests.filter((r) => r.counter !== undefined).map((r) => r.counter));

  /* A second operation under the same key continues the counter: no IV reuse. */
  await app.services.okcrypto.composite_decrypt(5, new Uint8Array(32).fill(9), { ...FAST, confirm: pressing(device) });
  const second = device.requests.filter((r) => r.cmd === MSG.OKDECRYPT).pop();
  assert.ok(second.counter > lastCounter, `counter ${second.counter} did not continue past ${lastCounter}`);
  assert.equal(device.requests.filter((r) => r.cmd === okconnect.OKCONNECT).length, 1, 'no second key exchange');

  /* A new key exchange resets it, as the firmware resets its own. */
  await app.services.okcrypto.connectTunnel();
  await app.services.okcrypto.composite_decrypt(5, new Uint8Array(32).fill(9), { ...FAST, confirm: pressing(device) });
  assert.equal(device.requests.filter((r) => r.cmd === MSG.OKDECRYPT).pop().counter, 0);
  await app.destroy();
});

test('v3.0.5: a derived X-Wing decapsulation (slot 128) - accepted chunks are answered "no data ready", and that is not a refusal', async () => {
  /*
   * The web-and-agent derivation slot gathers its [label32 | ct(1120)] outside
   * packet_buffer, so the firmware answers each ACCEPTED non-final chunk with
   * CTAP2_ERR_NO_OPERATION_PENDING (ok_extension.cpp:793-798) where a stored slot
   * says USER_ACTION_PENDING. Measured on the emulator 2026-09-28: the device's
   * console showed the first chunk opened and dispatched, and this plugin
   * aborted on it as REQUEST_NOT_ACCEPTED - the decap never ran (audit #8).
   */
  const device = fakeTunnelDevice({ firmware: 'v3.0.5-prodc' });
  const app = await start(device);
  const payload = Uint8Array.from({ length: 32 + 1120 }, (_, i) => (i * 11) & 0xff);

  const ss = await app.services.okcrypto.composite_decrypt(128, payload, { ...FAST, confirm: pressing(device) });
  assert.deepEqual(Uint8Array.from(ss), resultFor(MSG.OKDECRYPT, payload));
  const chunks = device.requests.filter((r) => r.cmd === MSG.OKDECRYPT);
  assert.equal(chunks.length, 7, 'the 1152-byte payload goes as seven sealed chunks');
  assert.deepEqual(chunks.map((c) => c.opt2), [0, 0, 0, 0, 0, 0, 1], 'opt2 on the final chunk only');
  await app.destroy();
});

test('v3.0.5: a derive re-keys the device, and the next stored-key operation seals under the derive key', async () => {
  const device = fakeTunnelDevice({ firmware: 'v3.0.5-prodc' });
  const app = await start(device);
  await app.services.okcrypto.connectTunnel();
  const derived = await app.services.okcrypto.derivePublicKey('example.com');
  assert.equal(derived.publicKey.length, 65);

  const sig = await app.services.okcrypto.composite_sign(
    3, composite.HALF_ECC, DIGEST, { ...FAST, confirm: pressing(device) },
  );
  assert.deepEqual(Uint8Array.from(sig), resultFor(MSG.OKSIGN, halfPayload(composite.HALF_ECC, DIGEST)));
  assert.equal(device.requests.filter((r) => r.cmd === okconnect.OKCONNECT).length, 2,
    'the connect and the derive - no third exchange: the derive reply carried the key');
  await app.destroy();
});

/* ------------------------------------------------ v3.0.4: the transit v1 box */

test('v3.0.4: the same ciphertext goes as 228-byte v1-boxed chunks, and the result is read in the clear', async () => {
  const device = fakeTunnelDevice({ firmware: 'v3.0.4-prodc' });
  const app = await start(device);
  const ct = Uint8Array.from({ length: 1088 }, (_, i) => (i * 3) & 0xff);

  const ss = await app.services.okcrypto.composite_decrypt(5, ct, { ...FAST, confirm: pressing(device) });
  assert.deepEqual(Uint8Array.from(ss), resultFor(MSG.OKDECRYPT, ct),
    'the box is length-preserving, so the device decrypted exactly the payload');
  assert.deepEqual(
    device.requests.filter((r) => r.cmd === MSG.OKDECRYPT).map((c) => c.length),
    [228, 228, 228, 228, 176],
  );
  await app.destroy();
});

test('v3.0.4: two operations back to back - the RNG2 byte in the duplicate guard is waited out', async () => {
  /*
   * On 3.0.4 process_packets() leaves two random bytes in the slot the
   * duplicate guard reads, cleared only by wipetasks(). The staged-reply
   * settle is what gets the second operation past it.
   */
  const device = fakeTunnelDevice({ firmware: 'v3.0.4-prodc' });
  const app = await start(device);
  chunk._resetPacketCounter(0);
  for (let i = 0; i < 2; i++) {
    const out = await app.services.okcrypto.composite_sign(
      3, composite.HALF_ECC, DIGEST, { ...FAST, confirm: pressing(device) },
    );
    assert.equal(out.length, 64);
  }
  assert.equal(device.requests.some((r) => r.dropped), false);
  await app.destroy();
});

/* ------------------------------------------- the reply to the request itself */

test('a request that fails transit authentication is named at once, not polled for', async () => {
  const device = fakeTunnelDevice({ firmware: 'v3.0.5-prodc' });
  const app = await start(device);
  await app.services.okcrypto.connectTunnel();
  await new Promise((r) => setTimeout(r, 50)); /* let the connect reply expire */
  device.rekey(); /* another client connected: the device holds a key we do not */

  const t0 = Date.now();
  await assert.rejects(
    app.services.okcrypto.composite_sign(3, composite.HALF_ECC, DIGEST, { ...FAST, timeoutMs: 20000 }),
    (err) => err.code === 'REQUEST_NOT_ACCEPTED'
      && /transit authentication failed/.test(err.message)
      && /Error message failed authentication/.test(err.message),
  );
  assert.ok(Date.now() - t0 < 5000, 'it did not wait out the poll budget');
  assert.equal(device.requests.some((r) => r.cmd === MSG.OKPING), false, 'nothing was polled');

  /* The session was dropped, so the next operation connects again and works. */
  const sig = await app.services.okcrypto.composite_sign(
    3, composite.HALF_ECC, DIGEST, { ...FAST, confirm: pressing(device) },
  );
  assert.equal(sig.length, 64);
  assert.equal(device.requests.filter((r) => r.cmd === okconnect.OKCONNECT).length, 2);
  await app.destroy();
});

test('a stale staged reply in answer to a request chunk fails by name', async () => {
  /* The plugin is told not to wait, and the device keeps its connect reply. */
  const device = fakeTunnelDevice({ firmware: 'v3.0.5-prodc', wipeMs: 60000 });
  const app = await start(device, { stagedWipeMs: 0 });
  await app.services.okcrypto.connectTunnel();

  await assert.rejects(
    app.services.okcrypto.composite_sign(3, composite.HALF_ECC, DIGEST, { ...FAST, timeoutMs: 20000 }),
    (err) => err.code === 'REQUEST_NOT_ACCEPTED' && /stale reply/.test(err.message)
      && /chunk 1 of 1/.test(err.message),
  );
  await app.destroy();
});

test('stored keys disabled over FIDO2 comes back as the device sentence', async () => {
  const app = await start(fakeTunnelDevice({ webcryptLevel: 1 }));
  await assert.rejects(
    app.services.okcrypto.composite_decrypt(5, new Uint8Array(32), FAST),
    (err) => /stored key use over FIDO2 not enabled/.test(err.message) && err.deviceText !== undefined,
  );
  await app.destroy();
});

test('right after a connect the operation waits for the staged reply to expire, and says so', async () => {
  const device = fakeTunnelDevice();
  const app = await start(device);
  const settles = [];
  app.services.okcrypto.on('settle', (e) => settles.push(e));
  await app.services.okcrypto.composite_sign(3, composite.HALF_ECC, DIGEST, { ...FAST, confirm: pressing(device) });
  assert.equal(settles.length, 1);
  assert.ok(settles[0].ms > 0 && settles[0].ms <= 40);
  assert.match(settles[0].why, /serve it again/);
  await app.destroy();
});

test('a payload that cannot be sealed without padding is refused before anything is sent', async () => {
  /* 18 + 20 = 38 bytes: a 48-byte keyhandle, which the encoder must pad. */
  const device = fakeTunnelDevice();
  const app = await start(device);
  await app.services.okcrypto.connectTunnel();
  const before = device.requests.length;
  await assert.rejects(
    app.services.okcrypto.composite_decrypt(5, new Uint8Array(18), FAST),
    RangeError,
  );
  assert.equal(device.requests.length, before);
  await app.destroy();
});
