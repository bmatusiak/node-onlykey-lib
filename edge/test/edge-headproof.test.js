'use strict';
/*
 * THE HEAD PROOF (Brad, 2026-10-30: "providing proof to the key we have the last transaction"). On firmware with
 * CERTIFY_HEADPROOF the key never reveals its head - HEAD, PICKUP and the RECEIPT/SETTLE/LOSS answers carry zeros - so a
 * host knows the head only by welding the links onto a head it holds, and the key confirms a head (both checkpoint
 * signatures) only when the host proves it (PROVE_HEAD). Against the fake key (helpers/fake-edge-key.js headproof).
 */
const test = require('node:test');
const assert = require('node:assert');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { chain } = require('../src');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

const key = (o = {}) => { const t = fakeKey({ secret: p256.utils.randomSecretKey(), ...o }); return { t, e: edgeOver(t) }; };
const zero = (b) => b.every((x) => x === 0);

test('the key never reveals its head: HEAD names the capability, the head is the one this host welded', async () => {
  const { t, e } = key();
  for (let i = 0; i < 3; i += 1) t.edgeRecord();
  const h = await e.head();
  assert.equal(h.caps & 1, 1, 'HEAD byte 59: CERTIFY_HEADPROOF');
  /* the client welded it from the genesis through every link the key holds */
  const links = await e.pickup(0, h.seq + 1);
  const welded = links.reduce((at, l) => chain.weld(at, l.link), chain.genesis((await e.publicKey()).deviceId));
  assert.deepEqual([...h.head], [...welded]);
});

test('PROVE_HEAD: the welded head is confirmed with both checkpoint signatures; another head is refused', async () => {
  const { t, e } = key();
  for (let i = 0; i < 4; i += 1) t.edgeRecord();
  const cp = await e.checkpoint();
  const h = await e.head();
  assert.equal(cp.seq, h.seq);
  assert.deepEqual([...cp.head], [...h.head], 'the confirmation names the proven head');
  const { publicKey, deviceId } = await e.publicKey();
  assert.equal(chain.verifyCheckpoint({ deviceId, seq: cp.seq, head: cp.head }, cp.signature, publicKey, cp.signaturePq, await e.publicKeyPq('checkpoint')), true);
  /* a host whose copy ends on another head proves that one: refused, no confirmation */
  const other = edgeOver(t);
  const wrong = Uint8Array.from(h.head); wrong[0] ^= 1;
  other.knownHead(h.seq, wrong, deviceId);
  await assert.rejects(() => other.checkpoint(), (err) => err.code === 0x0b);
});

test('firmware before the head proof: the key\'s own head and CHECKPOINT, and no certify', async () => {
  const { t, e } = key({ headproof: false });
  t.edgeRecord();
  const h = await e.head();
  assert.equal(h.caps & 1, 0);
  assert.ok(!zero(h.head), 'the old firmware sends its head');
  const cp = await e.checkpoint();
  assert.deepEqual([...cp.head], [...h.head]);
  await assert.rejects(() => e.ownerPublicKey(), { code: 'EOLDFIRMWARE' });
  await assert.rejects(() => e.certify(new Uint8Array(32)), { code: 'EOLDFIRMWARE' });
});

test('RECEIPT / SETTLE answers: the head after the new link is the client\'s weld, not the key\'s (zeros on the wire)', async () => {
  const { e } = key();
  const r = await e.receipt(0, 0, new Uint8Array(32));
  const h = await e.head();
  assert.equal(r.seq, h.seq);
  assert.deepEqual([...r.head], [...h.head]);
});
