'use strict';
/*
 * OPS_CHECKPOINT (Brad, 2026-10-31: "receipts and certify are checkpoints"; "to warm up edge, we need a checkpoint"):
 * on firmware with HEAD byte 59 bit 2, RECEIPT and CERTIFY end with the key's checkpoint signatures over the head after
 * their link (the head not shown). Against the fake key (helpers/fake-edge-key.js opsCheckpoint), over USB and over a
 * WebAuthn-shaped tunnel that keeps each ML-DSA-65 signature for MORE, as the firmware does.
 */
const test = require('node:test');
const assert = require('node:assert');
const setup = require('../plugin');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { chain, grants } = require('../src');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

const key = (o = {}) => { const t = fakeKey({ secret: p256.utils.randomSecretKey(), ...o }); return { t, e: edgeOver(t) }; };
const PQ = Math.ceil(chain.ML_DSA65.SIG / 64);

async function verifies(e, cp) {
  const { publicKey, deviceId } = await e.publicKey();
  return chain.verifyCheckpoint({ deviceId, seq: cp.seq, head: cp.head }, cp.signature, publicKey, cp.signaturePq, await e.publicKeyPq('checkpoint'));
}

/*
 * The fake key behind a WebAuthn tunnel: one answer per request, and the ML-DSA-65 signatures the firmware keeps for
 * MORE (a CERTIFY's owner signature and its checkpoint's, a RECEIPT's checkpoint's) held back, oldest first.
 */
function overTunnel(t) {
  const kept = [];
  const ask = (sub, args) => new Promise((resolve) => {
    const got = [];
    let quiet = null;
    const off = t.on('report', ({ data }) => {
      got.push(Uint8Array.from(data));
      clearTimeout(quiet);
      quiet = setTimeout(() => { off(); resolve(got); }, 25);
    });
    t.write(0, Uint8Array.from([0xff, 0xff, 0xff, 0xff, 0xf8, sub, ...args]));
  });
  const join = (rs) => { const out = new Uint8Array(rs.length * 64); rs.forEach((r, i) => out.set(r.subarray(0, 64), i * 64)); return out; };
  const okcrypto = {
    async tunnelRequest(msg, sub, args) {
      if (sub === 0x07) {
        const sig = kept.shift();
        return sig ? { data: join(sig).subarray(0, chain.ML_DSA65.SIG) } : { text: 'EDGE:0E' };
      }
      let rs = await ask(sub, args);
      const said = Buffer.from(rs[0]).toString('latin1');
      if (said.startsWith('EDGE:')) return { text: said.replace(/\0.*$/s, '') };
      if (sub === 0x08 && rs.length === 3 + PQ + 2 + PQ) {
        kept.push(rs.slice(3, 3 + PQ), rs.slice(5 + PQ));
        rs = [...rs.slice(0, 3), ...rs.slice(3 + PQ, 5 + PQ)];
      } else if (sub === 0x20 && rs.length === 2 + PQ) {
        kept.push(rs.slice(2));
        rs = rs.slice(0, 2);
      }
      return { data: join(rs) };
    },
  };
  const transport = { ...t, tunnelOnly: true };
  let edge = null;
  setup({ transport, app: { services: { okcrypto } } }, (err, services) => { if (err) throw err; edge = services.edge; });
  return { e: edge, kept };
}

test('HEAD names OPS_CHECKPOINT beside CERTIFY_HEADPROOF', async () => {
  const { e } = key();
  assert.equal((await e.head()).caps, 3);
});

test('a RECEIPT ends with a checkpoint over the head after its link (head not shown)', async () => {
  const { e } = key();
  await e.pickup(0, 1); /* this host welds the chain from its genesis */
  const r = await e.receipt(0, 0, new Uint8Array(32));
  assert.equal(r.seq, 1);
  assert.ok(r.checkpoint, 'the receipt carries a checkpoint');
  assert.equal(r.checkpoint.seq, r.seq);
  assert.deepEqual([...r.checkpoint.head], [...r.head], 'the checkpoint names the head this host welded');
  assert.equal(await verifies(e, r.checkpoint), true, 'both checkpoint signatures verify over that head');
});

test('a CERTIFY ends with a checkpoint at its own link, and its owner signatures still verify', async () => {
  const { e } = key();
  await e.pickup(0, 1);
  const c = await e.certify(new Uint8Array(32).fill(7));
  assert.ok(c.checkpoint);
  assert.equal(c.checkpoint.seq, c.seq, 'the checkpoint is at the certification\'s link');
  assert.equal(await verifies(e, c.checkpoint), true);
  assert.equal(c.signaturePq.length, chain.ML_DSA65.SIG);
  assert.equal(grants.verifyCertification(c, c.ownerKey, c.ownerKeyPq), true, 'the owner\'s P-256 and ML-DSA-65 signatures are the certification\'s, not the checkpoint\'s');
});

test('firmware without OPS_CHECKPOINT: today\'s replies, no checkpoint', async () => {
  const { e } = key({ opsCheckpoint: false });
  assert.equal((await e.head()).caps, 1);
  await e.pickup(0, 1);
  const r = await e.receipt(0, 0, new Uint8Array(32));
  assert.equal(r.checkpoint, undefined);
  const c = await e.certify(new Uint8Array(32).fill(1));
  assert.equal(c.checkpoint, null);
  assert.equal(grants.verifyCertification(c, c.ownerKey, c.ownerKeyPq), true);
});

test('over WebAuthn: the two kept ML-DSA signatures of a CERTIFY land where USB has them; a RECEIPT\'s too', async () => {
  const { t } = key();
  const { e, kept } = overTunnel(t);
  await e.pickup(0, 1);
  const c = await e.certify(new Uint8Array(32).fill(5));
  assert.equal(kept.length, 0, 'both MOREs were asked for');
  assert.equal(grants.verifyCertification(c, c.ownerKey, c.ownerKeyPq), true, 'the owner signature came from the first MORE');
  assert.equal(await verifies(e, c.checkpoint), true, 'the checkpoint\'s from the second');
  const r = await e.receipt(0, 0, new Uint8Array(32));
  assert.equal(kept.length, 0);
  assert.equal(await verifies(e, r.checkpoint), true);
});
