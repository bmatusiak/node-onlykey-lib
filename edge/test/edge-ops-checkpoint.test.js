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
const { chain, grants, certify, codes } = require('../src');
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

test('HEAD names OPS_CHECKPOINT, LOSS_ANCHOR and WARM_GATE beside CERTIFY_HEADPROOF', async () => {
  const { e } = key();
  assert.equal((await e.head()).caps, 15);
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

/*
 * WARM-UP FROM A CARD'S TOP: host A (this device, with the chain) keeps the newest checkpoint and the links after it
 * (certify.top); a fresh host B - the chain past the key's 8-link ring - warms Edge from that top, no press.
 */
async function hostWithTop(after = 3, more = 6, o = {}) {
  const { t } = key({ ring: 8, ...o });
  const a = edgeOver(t);
  await a.pickup(0, 1);
  const { checkpoint } = await a.receipt(0, 0, new Uint8Array(32));
  for (let i = 0; i < after; i += 1) t.edgeRecord();
  const links = (await a.pickup(checkpoint.seq + 1, after)).map((l) => l.link);
  for (let i = 0; i < more; i += 1) t.edgeRecord();
  return { t, top: certify.top(checkpoint, links), checkpoint };
}

test('warm-up: a fresh host past the ring warms from the card\'s top, proves the head and opens a budget', async () => {
  const { t, top } = await hostWithTop();
  const b = edgeOver(t);
  const before = await b.head();
  assert.equal(before.head, null, 'B cannot weld the key\'s head: the ring starts after anything it holds');
  const proven = await b.warmUp(top);
  const h = await b.head();
  assert.equal(proven.seq, h.seq);
  assert.deepEqual([...proven.head], [...h.head], 'the proven head is the one B now welds');
  assert.equal(await verifies(b, proven), true);
  /* the budget gate: a copy that starts at the proven head (copy.anchor) */
  const g = await b.grants.create({ copy: { anchor: { seq: proven.seq, head: proven.head }, links: [] }, scopes: [{ op: 1, slot: 2, cap: 1 }], reasonHash: new Uint8Array(32) });
  assert.ok(g.grantId > 0, 'a budget opened on the warmed host');
});

/* the weld path (firmware without WARM_GATE, or a gate refused): its own checks */
test('warm-up refuses what does not stand: no top, a forged one, one that ends before the ring', async () => {
  const { t, top } = await hostWithTop(3, 6, { warmGate: false });
  await assert.rejects(edgeOver(t).warmUp(null), (e) => e.code === 'EDGE_NO_CHECKPOINT' && e.why === 'no-top');
  const forged = JSON.parse(JSON.stringify(top));
  forged.checkpoint.head = forged.checkpoint.head.replace(/^./, (c) => (c === '0' ? '1' : '0'));
  await assert.rejects(edgeOver(t).warmUp(forged), (e) => e.code === 'EDGE_NO_CHECKPOINT' && e.why === 'checkpoint-signature');
  const far = await hostWithTop(3, 12, { warmGate: false });
  await assert.rejects(edgeOver(far.t).warmUp(far.top), (e) => e.code === 'EDGE_NO_CHECKPOINT' && e.why === 'top-ends-before-the-ring');
});

test('the 1024 limit: a top whose checkpoint is more than 1024 links behind the key\'s head does not stand', async () => {
  const { t, top } = await hostWithTop();
  const e = edgeOver(t);
  const { publicKey, deviceId } = await e.publicKey();
  const keys = { deviceId, publicKey, publicKeyPq: await e.publicKeyPq('checkpoint') };
  assert.equal(certify.verifyTop(top, { ...keys, keySeq: top.checkpoint.seq + certify.TOP_REACH }).ok, true);
  assert.equal(certify.verifyTop(top, { ...keys, keySeq: top.checkpoint.seq + certify.TOP_REACH + 1 }).reason, 'too-far-back');
});

/*
 * THE WARM-UP GATE (WARM_GATE; Brad, 2026-11-01: "the login identity card holds cold boot for edge to warm up"; "the
 * enabled gate is enough, we just need to be close to the head"): a host that holds none of the chain certifies once
 * (a press) - its checkpoint hides the head but carries the gate token, so it is a top; any later cold host shows the
 * token and the key gives the head, no press, and a budget opens. A token that is not the key's is refused.
 */
async function coldTop() {
  const { t } = key({ ring: 8 });
  /* the fake key's use #0 owes its receipt: paid first, as a key in use would have, so no budget is refused for debts */
  const z = edgeOver(t);
  await z.pickup(0, 1);
  await z.receipt(0, 0, new Uint8Array(32));
  for (let i = 0; i < 12; i += 1) t.edgeRecord();
  const a = edgeOver(t);
  assert.equal((await a.head()).head, null, 'host A holds none of the chain');
  const c = await a.certify(new Uint8Array(32).fill(7));
  assert.ok(c.checkpoint.gate, 'the certify\'s checkpoint carries no gate token');
  assert.deepEqual(a.newestGate(), { seq: c.checkpoint.seq, gate: c.checkpoint.gate }, 'the gate is kept for the card\'s top');
  return { t, top: certify.top({ seq: c.checkpoint.seq, gate: c.checkpoint.gate }) };
}

test('the gate: a cold host\'s certify makes a top of its gate token alone; another cold host warms from it with no press and opens a budget', async () => {
  const { t, top } = await coldTop();
  assert.deepEqual(Object.keys(top.checkpoint).sort(), ['gate', 'seq'], 'a gate-only top carries no head');
  const b = edgeOver(t);
  assert.equal((await b.head()).head, null, 'host B holds none of the chain either');
  const warmed = await b.warmUp(top);
  const h = await b.head();
  assert.equal(warmed.seq, h.seq);
  assert.deepEqual([...warmed.head], [...h.head], 'the key showed its head');
  assert.equal(await verifies(b, warmed), true);
  const g = await b.grants.create({ copy: { anchor: { seq: warmed.seq, head: warmed.head }, links: [] }, scopes: [{ op: 1, slot: 2, cap: 1 }], reasonHash: new Uint8Array(32) });
  assert.ok(g.grantId > 0, 'a budget opened on the gated host');
});

test('the gate refuses a token that is not the key\'s: a gate-only top with nothing else to try says gate-refused', async () => {
  const { t, top } = await coldTop();
  const forged = JSON.parse(JSON.stringify(top));
  forged.checkpoint.gate = forged.checkpoint.gate.replace(/^./, (c) => (c === '0' ? '1' : '0'));
  await assert.rejects(edgeOver(t).warmUp(forged), (e) => e.code === 'EDGE_NO_CHECKPOINT' && e.why === 'gate-refused');
  await assert.rejects(edgeOver(t).warm(top.checkpoint.seq + 1, Uint8Array.from(Buffer.from(top.checkpoint.gate, 'hex'))), (e) => e.status === 'gate-refused');
});

test('firmware without WARM_GATE: no token in its checkpoints, and warm is refused as old firmware', async () => {
  const { t } = key({ warmGate: false });
  const a = edgeOver(t);
  const c = await a.certify(new Uint8Array(32).fill(7));
  assert.equal(c.checkpoint.gate, undefined);
  await assert.rejects(a.warm(0, new Uint8Array(16)), (e) => e.code === 'EOLDFIRMWARE');
});

test('warm-up on a host that already holds the head: it proves it, the top is not needed', async () => {
  const { e } = key();
  await e.pickup(0, 1);
  const proven = await e.warmUp(null);
  assert.equal(await verifies(e, proven), true);
});

test('the newest checkpoint is kept for the card\'s top: a receipt\'s, then a certify\'s', async () => {
  const { e } = key();
  await e.pickup(0, 1);
  assert.equal(e.newestCheckpoint(), null);
  const r = await e.receipt(0, 0, new Uint8Array(32));
  assert.equal(e.newestCheckpoint().seq, r.seq);
  const c = await e.certify(new Uint8Array(32).fill(2));
  assert.equal(e.newestCheckpoint().seq, c.seq);
  assert.equal(await verifies(e, e.newestCheckpoint()), true);
});

/*
 * A LOST LINK NEVER STRANDS A KEY (LOSS_ANCHOR; Brad, 2026-10-31: "we certify that we know about the missing block so we
 * can continue"): a host whose copy ends before the key's ring cannot weld the head - the warm-up says where the copy
 * ends and where the ring starts; the person's pressed LOSS of the range between names it in the chain, and its
 * checkpoint shows the head after it, signed - the host goes on from there: proves the head and opens a budget.
 */
test('LOSS_ANCHOR: the range a copy cannot reach, accepted at a press, gives the head to go on from', async () => {
  const far = await hostWithTop(3, 12, { warmGate: false });
  const b = edgeOver(far.t);
  const cold = await b.warmUp(far.top).then(() => null, (e) => e);
  assert.equal(cold && cold.why, 'top-ends-before-the-ring');
  assert.ok(cold.copyEnds < cold.ringFrom - 1, `a gap between the copy (#${cold.copyEnds}) and the ring (#${cold.ringFrom})`);
  let pressedAsked = false;
  const after = await b.loss({ from: cold.copyEnds + 1, to: cold.ringFrom - 1, onPress: () => { pressedAsked = true; } });
  assert.ok(pressedAsked, 'the LOSS asked for its press');
  const h = await b.head();
  assert.equal(after.seq, h.seq, 'the LOSS is the key\'s newest link');
  assert.deepEqual([...after.head], [...h.head], 'the host now welds the head the LOSS showed');
  assert.equal(await verifies(b, after.checkpoint), true);
  const [l] = await b.pickup(after.seq, 1);
  const f = chain.decodeLink(l.link);
  assert.equal(f.op, codes.OP.LOSS);
  assert.equal(f.grantId, cold.copyEnds + 1, 'the LOSS names where the lost range starts');
  /* and the host goes on: the head proven, a budget from a copy anchored there */
  const proven = await b.checkpoint();
  assert.equal(proven.seq, after.seq);
  const g = await b.grants.create({ copy: { anchor: { seq: after.seq, head: after.head }, links: [] }, scopes: [{ op: 1, slot: 2, cap: 1 }], reasonHash: new Uint8Array(32) });
  assert.ok(g.grantId > 0, 'a budget opened past the lost range');
});

test('LOSS on firmware without LOSS_ANCHOR answers as before: seq, no head', async () => {
  const { t, e } = key({ lossAnchor: false });
  await e.pickup(0, 1);
  t.edgeRecord();
  const r = await e.loss({ from: 1, to: 1 });
  assert.equal(r.checkpoint, undefined);
  assert.equal(r.seq, (await e.head()).seq);
});
