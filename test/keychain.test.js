/*
 * Key Chain, step L1: the label tag, probing what a slot holds, and naming a
 * key as it is made. Against the fake firmware, which models what the real
 * one does here - including the reply buffer it never clears, because
 * probeKeySlot must not be fooled by zeros the device does not send.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Rectify = require('@bmatusiak/rectify');
const hostPlugin = require('../plugins/host');
const embedded = require('../plugins/transport/embedded');
const sessionPlugin = require('../plugins/session');
const devicePlugin = require('../plugins/device');
const { fakeFirmware } = require('./helpers/fake-firmware');
const { MSG } = require('../src/protocol/msg');
const { toLatin1 } = require('../src/bytes');
const keychain = require('../src/keychain');
const { p256 } = require('../src/vendor/exports/@noble/curves/nist.js');
const { secp256k1 } = require('../src/vendor/exports/@noble/curves/secp256k1.js');
const { ed25519, x25519 } = require('../src/vendor/exports/@noble/curves/ed25519.js');

const { formatTag, parseTag, LABEL_MAX } = keychain.tag;

function start(pipe) {
  const plugins = [hostPlugin, embedded, sessionPlugin, devicePlugin];
  plugins.config = { transport: { pipe } };
  return new Promise((resolve, reject) => {
    const app = Rectify.build(plugins, (err, started) => (err ? reject(err) : resolve(started)));
    app.start();
  });
}

const random = (n) => Uint8Array.from({ length: n }, () => Math.floor(Math.random() * 256));
const sent = (pipe, msg) => pipe.writes.filter((w) => w.data[4] === msg).map((w) => w.data);
/* An OKSETSLOT frame's label index and text. */
const labelWrite = (frame) => {
  const text = [];
  for (let i = 7; i < frame.length && frame[i] !== 0; i++) text.push(frame[i]);
  return { index: frame[5], text: toLatin1(Uint8Array.from(text)) };
};

/* ------------------------------------------------------------ tag */

test('a tag is "<kind>:<name>" within the 16-byte key label, readable as written', () => {
  assert.equal(formatTag('pgp', 'alice'), 'pgp:alice');
  assert.deepEqual(parseTag('xwg:backups'), { kind: 'xwg', name: 'backups', hint: 'xwing' });
  assert.deepEqual(parseTag('mlk:inbox'), { kind: 'mlk', name: 'inbox', hint: 'mlkem768' });
  assert.deepEqual(parseTag('ssh:my laptop'), { kind: 'ssh', name: 'my laptop', hint: null });
  assert.equal(formatTag('ssh', 'twelve-chars').length, LABEL_MAX);
  assert.throws(() => formatTag('ssh', 'thirteen-char'), /17 characters.*at most 12/);
  assert.throws(() => formatTag('key', 'x'), /unknown Key Chain kind/);
  assert.throws(() => formatTag('pgp', 'a:b'), /without a colon/);
  assert.throws(() => formatTag('pgp', ' padded'), /surrounding spaces/);
  assert.throws(() => formatTag('pgp', 'café'), /printable ASCII/);
});

test('a label that is not a tag is someone\'s own name, left alone', () => {
  for (const label of ['', 'Work key', 'pgp:', ':alice', 'zzz:alice', null, undefined]) {
    assert.equal(parseTag(label), null, String(label));
  }
});

/* ------------------------------------------------------------ probe */

test('probeKeySlot: empty, composite and RSA slots, from the device\'s own answers', async () => {
  const pipe = fakeFirmware({ pubKeys: { 2: random(256) }, keyKinds: { 3: 'composite' } });
  const app = await start(pipe);
  const { device } = app.services;
  assert.deepEqual(await device.probeKeySlot(1), { slot: 1, kind: 'empty' });
  assert.deepEqual(await device.probeKeySlot(105), { slot: 105, kind: 'empty' });
  assert.deepEqual(await device.probeKeySlot(3), { slot: 3, kind: 'composite' });
  const rsa = await device.probeKeySlot(2);
  assert.equal(rsa.kind, 'rsa');
  assert.equal(rsa.bits, 2048);
  await app.destroy();
});

test('probeKeySlot tells P-256 from secp256k1 by the curve, and both from a 32-byte key', async () => {
  const p = p256.getPublicKey(p256.utils.randomSecretKey(), false).slice(1);
  const k = secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), false).slice(1);
  const edSecret = ed25519.utils.randomSecretKey();
  const ed = ed25519.getPublicKey(edSecret);
  const edAsX = x25519.getPublicKey(random(32));
  const x = x25519.getPublicKey(random(32));
  const pipe = fakeFirmware({
    pubKeys: { 101: p, 102: k, 103: ed, 104: x },
    keyKinds: { 103: 'ed25519' },
    converted: { 103: edAsX },
  });
  const app = await start(pipe);
  const { device } = app.services;
  /* P-256 first, so the reply buffer holds 64 real bytes when a 32-byte key follows. */
  const r1 = await device.probeKeySlot(101);
  assert.equal(r1.kind, 'p256');
  assert.deepEqual([...r1.publicKey], [...p]);
  assert.equal((await device.probeKeySlot(102)).kind, 'secp256k1');
  const r3 = await device.probeKeySlot(103);
  assert.equal(r3.kind, 'ed25519');
  assert.deepEqual([...r3.publicKey], [...ed]);
  const r4 = await device.probeKeySlot(104);
  assert.equal(r4.kind, 'x25519');
  assert.deepEqual([...r4.publicKey], [...x]);
  await app.destroy();
});

test('probeKeySlot tells ML-KEM from X-Wing by the leftover bytes, and a tag\'s hint wins', async () => {
  const mlkem = random(1184);
  const xwing = random(1216);
  const pipe = fakeFirmware({ pubKeys: { 110: mlkem, 111: xwing } });
  const app = await start(pipe);
  const { device } = app.services;
  const a = await device.probeKeySlot(110);
  assert.equal(a.kind, 'mlkem768');
  assert.deepEqual([...a.publicKey], [...mlkem]);
  const b = await device.probeKeySlot(111);
  assert.equal(b.kind, 'xwing');
  assert.deepEqual([...b.publicKey], [...xwing]);
  assert.equal((await device.probeKeySlot(110, { hint: 'xwing' })).kind, 'xwing', 'the tag decides');
  await app.destroy();
});

test('probeKeySlot in config mode (or locked): silence is reported as that, not as an empty slot', async () => {
  const pipe = fakeFirmware({ pubKeys: { 101: random(64) }, inConfigMode: true });
  const app = await start(pipe);
  await assert.rejects(
    app.services.device.probeKeySlot(101, { timeoutMs: 200 }),
    /did not answer OKGETPUBKEY.*LOCKED.*config mode/s,
  );
  await assert.rejects(app.services.device.probeKeySlot(20), /only RSA1-4 and ECC1-16/);
  await app.destroy();
});

/* ------------------------------------------------------------ labels */

test('setKeyLabel names a slot (and blanks it with "") without touching the key', async () => {
  const pipe = fakeFirmware();
  const app = await start(pipe);
  const { device } = app.services;
  await device.setKeyLabel(101, 'pgp:alice');
  await device.setKeyLabel(2, '');
  const writes = sent(pipe, MSG.OKSETSLOT).map(labelWrite);
  assert.deepEqual(writes, [{ index: 29, text: 'pgp:alice' }, { index: 26, text: '' }]);
  assert.equal(sent(pipe, MSG.OKSETPRIV).length + sent(pipe, MSG.OKWIPEPRIV).length, 0);
  await assert.rejects(device.setKeyLabel(120, 'x'), /has no key label/);
  await app.destroy();
});

test('generateEccKey and generateKey write the label AFTER the key', async () => {
  const pq = random(1216);
  const pipe = fakeFirmware({ generates: { 112: pq } });
  const app = await start(pipe);
  const { device } = app.services;
  const ecc = await device.generateEccKey(101, 1, { signature: true, label: 'ssh:laptop' });
  assert.equal(ecc.response, 'Successfully set ECC Key');
  const key = await device.generateKey(112, 6, { label: 'xwg:backups' });
  assert.deepEqual([...key], [...pq]);
  const order = pipe.writes.map((w) => w.data[4]).filter((m) => m === MSG.OKSETPRIV || m === MSG.OKSETSLOT);
  assert.deepEqual(order, [MSG.OKSETPRIV, MSG.OKSETSLOT, MSG.OKSETPRIV, MSG.OKSETSLOT]);
  assert.deepEqual(sent(pipe, MSG.OKSETSLOT).map(labelWrite),
    [{ index: 29, text: 'ssh:laptop' }, { index: 40, text: 'xwg:backups' }]);
  await app.destroy();
});
