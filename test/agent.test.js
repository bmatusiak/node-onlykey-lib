/*
 * Agent derivation - SSH/GPG keys the device derives from an identity
 * (src/protocol/agent.js, okcrypto.agent).
 *
 * There are no cross-device vectors: every OnlyKey has its own random K132.
 * So the fake firmware carries a K132 and the 3.1.0 derivation, and these
 * tests hold the only thing that can be held without one device's secret:
 * the key the library READS is the key that SIGNS and AGREES - a signature
 * verifies against the public key, and ECDH meets the host's half. The wire
 * itself (codes, identity hash, chunking) is pinned byte for byte. On a real
 * key: onlykey-testing 02-cli/18 drives lib-agent against the same codes.
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
const agent = require('../src/protocol/agent');
const { fakeFirmware } = require('./helpers/fake-firmware');
const { MSG } = require('../src/protocol/msg');
const { sha256 } = require('../src/vendor/exports/@noble/hashes/sha2.js');
const { ed25519, x25519 } = require('../src/vendor/exports/@noble/curves/ed25519.js');
const { p256 } = require('../src/vendor/exports/@noble/curves/nist.js');

const K132 = new Uint8Array(32).map((_, i) => (i * 29 + 7) & 0xff);
const SSH = { ssh: { user: 'brad', host: 'bench.example' } };
const ascii = (s) => new TextEncoder().encode(s);
const hex = (b) => Buffer.from(b).toString('hex');

async function start(opts = {}) {
  const pipe = fakeFirmware({ agent: { k132: K132, ...opts.agent }, ...opts.fw });
  const plugins = [hostPlugin, embedded, sessionPlugin, devicePlugin, okcryptoPlugin];
  plugins.config = { transport: { pipe } };
  const app = await new Promise((resolve, reject) => {
    const a = Rectify.build(plugins, (err, started) => (err ? reject(err) : resolve(started)));
    a.start();
  });
  return { app, pipe, ok: app.services.okcrypto };
}

/* ------------------------------------------------------------ the protocol */

test('the identity hash is what lib-agent hashes', () => {
  assert.equal(hex(agent.identityHash(SSH)), hex(sha256(ascii('brad@bench.example'))));
  assert.equal(hex(agent.identityHash({ ssh: { host: 'bench.example' } })), hex(sha256(ascii('bench.example'))));
  assert.equal(hex(agent.identityHash({ gpg: 'Brad <b@example.com>' })), hex(sha256(ascii('gpg://Brad <b@example.com>'))));
  const ready = new Uint8Array(32).fill(3);
  assert.equal(agent.identityHash(ready), ready);
});

test('an identity lib-agent would transliterate is refused, not hashed differently', () => {
  assert.throws(() => agent.identityHash({ ssh: { user: 'zoë', host: 'h' } }), /unidecode/);
  assert.throws(() => agent.identityHash(new Uint8Array(31)), /32 bytes/);
  assert.throws(() => agent.identityHash({}), /identity is/);
});

test('the codes, and the combinations the firmware refuses', () => {
  assert.equal(agent.publicKeyCode(1, 1), 132);
  assert.equal(agent.publicKeyCode(2, 4), 232);
  assert.equal(agent.signCode(1, 1), 201);
  assert.equal(agent.signCode(2, 3), 223);
  assert.equal(agent.ecdhCode(1, 4), 204);
  assert.equal(agent.ecdhCode(2, 2), 222);
  assert.throws(() => agent.signCode(1, 4), /signing takes key type 1, 2, 3/);
  assert.throws(() => agent.ecdhCode(1, 1), /ECDH takes key type 2, 3, 4/);
  assert.throws(() => agent.signCode(3, 1), /version 1 or 2/);
});

/* ---------------------------------------------------------------- the I/O */

test('the public key request carries the type and the identity hash', async () => {
  const { app, pipe, ok } = await start();
  const key = await ok.agent.publicKey(SSH, { keyType: 1 });
  assert.equal(key.length, 32);
  const w = pipe.writes.filter((x) => x.data[4] === MSG.OKGETPUBKEY).pop().data;
  assert.equal(w[5], 132);
  assert.equal(w[6], 1);
  assert.equal(hex(w.slice(7, 39)), hex(agent.identityHash(SSH)));
  assert.equal((await ok.agent.publicKey(SSH, { keyType: 2 })).length, 64, 'P-256 is X||Y');
  await app.destroy();
});

test('v1 Ed25519: the signature verifies against the key the library read', async () => {
  const { app, ok } = await start();
  const pub = await ok.agent.publicKey(SSH, { keyType: 1 });
  const message = ascii('ssh userauth request');
  const sig = await ok.agent.sign(SSH, message, { keyType: 1 });
  assert.equal(sig.length, 64);
  assert.ok(ed25519.verify(sig, message, pub));
  await app.destroy();
});

test('v2 P-256: an ECDSA signature over a long message verifies (the device hashes it)', async () => {
  const { app, ok } = await start();
  const pub = await ok.agent.publicKey(SSH, { keyType: 2, version: 2 });
  const message = ascii('x'.repeat(200));
  const sig = await ok.agent.sign(SSH, message, { keyType: 2, version: 2 });
  assert.ok(p256.verify(sig, sha256(message), Uint8Array.of(4, ...pub), { prehash: false }));
  await app.destroy();
});

test('v1 and v2 are different keys for the same identity', async () => {
  const { app, ok } = await start();
  const v1 = await ok.agent.publicKey(SSH, { keyType: 1, version: 1 });
  const v2 = await ok.agent.publicKey(SSH, { keyType: 1, version: 2 });
  assert.notEqual(hex(v1), hex(v2));
  assert.equal(hex(await ok.agent.publicKey(SSH, { keyType: 1, version: 1 })), hex(v1), 'and each is stable');
  await app.destroy();
});

test('X25519 ECDH meets the host half', async () => {
  const { app, ok } = await start();
  const gpg = { gpg: 'Brad <b@example.com>' };
  const devicePub = await ok.agent.publicKey(gpg, { keyType: 4, version: 2 });
  const hostSk = new Uint8Array(32).fill(0x42);
  const secret = await ok.agent.ecdh(gpg, x25519.getPublicKey(hostSk), { keyType: 4, version: 2 });
  assert.equal(secret.length, 32);
  assert.equal(hex(secret), hex(x25519.getSharedSecret(hostSk, devicePub)));
  await app.destroy();
});

test('P-256 ECDH with a prefixed 65-byte peer key gives the shared point', async () => {
  const { app, ok } = await start();
  const devicePub = await ok.agent.publicKey(SSH, { keyType: 2 });
  const hostSk = new Uint8Array(32).fill(0x11);
  const point = await ok.agent.ecdh(SSH, p256.getPublicKey(hostSk, false), { keyType: 2 });
  assert.equal(point.length, 64);
  assert.equal(hex(point), hex(p256.getSharedSecret(hostSk, Uint8Array.of(4, ...devicePub), false).slice(1)));
  await app.destroy();
});

test('a payload that ends on a whole 57-byte chunk still arrives whole', async () => {
  /*
   * python-onlykey's send_large_message2 marks an exactly-57-byte final chunk
   * as "more follows" and the device waits forever. 82 + 32 = 114 = 2 x 57.
   */
  const { app, pipe, ok } = await start();
  const message = new Uint8Array(82).fill(9);
  const sig = await ok.agent.sign(SSH, message, { keyType: 1 });
  assert.ok(ed25519.verify(sig, message, await ok.agent.publicKey(SSH, { keyType: 1 })));
  assert.equal(pipe.agentPayloads.at(-1).length, 114);
  await app.destroy();
});

test('v2 is refused before anything is sent to firmware that lacks it', async () => {
  const { app, pipe, ok } = await start({ fw: { version: 'v3.0.4' }, agent: { v2: false } });
  await app.services.device.connect();
  const before = pipe.writes.length;
  await assert.rejects(() => ok.agent.publicKey(SSH, { keyType: 1, version: 2 }), /arrived in 3\.0\.5/);
  await assert.rejects(() => ok.agent.sign(SSH, ascii('m'), { keyType: 1, version: 2 }), /arrived in 3\.0\.5/);
  assert.equal(pipe.writes.length, before);
  assert.equal((await ok.agent.publicKey(SSH, { keyType: 1 })).length, 32, 'v1 still works there');
  await app.destroy();
});

/* ------------------------------------- low-order X25519 (G-12, x25519guard) */

test('agent.ecdh refuses a low-order X25519 peer before the device sees it', async () => {
  /*
   * v3.0.4 computes X25519 with whatever it is sent and answers 32 zero
   * bytes; only 8d28305 refuses on the device. The host refuses on every line.
   */
  const { LOW_ORDER_U } = require('../src/crypto/x25519guard');
  const { app, pipe, ok } = await start();
  const gpg = { gpg: 'Brad <b@example.com>' };
  const before = pipe.writes.length;
  for (const u of LOW_ORDER_U) {
    await assert.rejects(ok.agent.ecdh(gpg, u, { keyType: 4, version: 2, timeoutMs: 300 }),
      (err) => err.code === 'LOW_ORDER_POINT');
    /* gpg's 33-byte form, prefix 0x40, is the same point. */
    await assert.rejects(ok.agent.ecdh(gpg, Uint8Array.of(0x40, ...u), { keyType: 4, version: 2, timeoutMs: 300 }),
      (err) => err.code === 'LOW_ORDER_POINT');
  }
  assert.equal(pipe.writes.length, before, 'a low-order point was sent to the device');
  await app.destroy();
});

test('the 5-second wipe after an unanswered press: "Error device locked" from an unlocked key is waited out once, then the sign goes through', async () => {
  const { app, ok } = await start({ fw: { cryptoBusy: 1 } });
  const pub = await ok.agent.publicKey(SSH, { keyType: 1 });
  const message = ascii('a push right after one that timed out');
  const busy = [];
  const sig = await ok.agent.sign(SSH, message, { keyType: 1, busyWaitMs: 50, onBusy: (b) => busy.push(b) });
  assert.equal(busy.length, 1, 'waited the wipe out once');
  assert.ok(ed25519.verify(sig, message, pub), 'the retry is a real signature over THIS message');
  await app.destroy();
});

test('a key still "locked" after the wait: the second answer stands - one retry, not a loop', async () => {
  const { app, ok } = await start({ fw: { cryptoBusy: 5 } });
  await assert.rejects(ok.agent.sign(SSH, ascii('m'), { keyType: 1, busyWaitMs: 20 }), /Error device locked/);
  await app.destroy();
});
