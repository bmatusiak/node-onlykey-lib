'use strict';
/*
 * R30 anchors (okedge sync phase 2, P2c): a key writes, with a press, that it
 * has seen a sibling's chain up to that sibling's SIGNED checkpoint. Against two
 * fake keys (test/helpers/fake-edge-key.js), which model okplugin_edge ANCHOR.
 */
const test = require('node:test');
const assert = require('node:assert');
const { codes, chain, grants } = require('../src/edge');
const { sha256 } = require('../src/vendor/exports/@noble/hashes/sha2.js');
const { p256 } = require('../src/vendor/exports/@noble/curves/nist.js');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

const enc = (s) => new TextEncoder().encode(s);
const cat = (...a) => Uint8Array.from(a.flatMap((x) => [...x]));
const twoKeys = async () => {
  const a = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey() }));
  const b = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey() }));
  const kb = await b.publicKey();
  await a.siblingAdd(kb.publicKey, { timeoutMs: 2000 });
  return { a, b, kb };
};
const lastLink = async (edge) => {
  const h = await edge.head();
  const [l] = await edge.pickup(h.seq, 1);
  return chain.decodeLink(l.link);
};

test('anchorSubject = SHA256("OKEDGE-ANCHOR-v1" || device id || seq u32 LE || head || signature)', () => {
  const f = { deviceId: new Uint8Array(16).fill(1), seq: 0x01020304, head: new Uint8Array(32).fill(2), signature: new Uint8Array(64).fill(3) };
  assert.deepEqual([...grants.anchorSubject(f)], [...sha256(cat(enc('OKEDGE-ANCHOR-v1'), f.deviceId, [4, 3, 2, 1], f.head, f.signature))]);
  assert.throws(() => grants.anchorSubject({ ...f, signature: f.signature.slice(1) }), TypeError);
});

test('a key anchors its sibling at the sibling\'s signed checkpoint, with a press: op 19, slot = index, grant_id = seq', async () => {
  const { a, b, kb } = await twoKeys();
  const cp = await b.checkpoint();
  assert.ok(chain.verifyCheckpoint({ deviceId: kb.deviceId, seq: cp.seq, head: cp.head }, cp.signature, kb.publicKey));
  const r = await a.anchor(0, cp, { timeoutMs: 2000 });
  const f = await lastLink(a);
  assert.equal(f.seq, r.seq);
  assert.equal(f.op, codes.OP.ANCHOR);
  assert.equal(f.slot, 0);
  assert.equal(f.grantId, cp.seq);
  assert.ok(f.flags & codes.FLAG.PRESS_OBSERVED);
  assert.deepEqual([...f.subject], [...grants.anchorSubject({ deviceId: kb.deviceId, ...cp })]);
});

test('a checkpoint not signed by the sibling, or no sibling at the index, is refused and writes nothing', async () => {
  const { a, b } = await twoKeys();
  const cp = await b.checkpoint();
  const before = (await a.head()).seq;
  const bad = Uint8Array.from(cp.signature); bad[3] ^= 1;
  await assert.rejects(a.anchor(0, { ...cp, signature: bad }, { timeoutMs: 2000 }), (e) => e.status === 'bad-checkpoint');
  /* a checkpoint of ANOTHER key, offered as the sibling's */
  const other = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey() }));
  await assert.rejects(a.anchor(0, await other.checkpoint(), { timeoutMs: 2000 }), (e) => e.status === 'bad-checkpoint');
  await assert.rejects(a.anchor(1, cp, { timeoutMs: 2000 }), (e) => e.status === 'no-such-sibling');
  assert.equal((await a.head()).seq, before, 'a refused anchor wrote a link');
});

/* --- the phone's side: anchorCheck (the alarms) and approveAnchor (the sheet, the press, the link) --- */
const syncLib = require('../src/edge/sync');
const approve = require('../src/edge/approve');
const peerKey = () => p256.getPublicKey(p256.utils.randomSecretKey(), false).slice(1);
/* a sibling with a few links of its own, and what a place would read from it */
const withHistory = async () => {
  const k = await twoKeys();
  for (let i = 0; i < 3; i += 1) await k.b.peerAdd(peerKey(), { timeoutMs: 2000 });
  const h = await k.b.head();
  const records = await k.b.pickup(0, h.seq + 1);
  return { ...k, records, cp: await k.b.checkpoint() };
};

test('anchorCheck: the sibling\'s chain up to its signed checkpoint verifies', async () => {
  const { kb, records, cp } = await withHistory();
  const r = syncLib.anchorCheck({ records, publicKey: kb.publicKey, checkpoint: cp, anchors: [] });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.verifiedThrough, cp.seq);
});

test('anchorCheck alarms: a rollback, a changed history, a tampered link, a checkpoint not the sibling\'s', async () => {
  const { kb, records, cp } = await withHistory();
  const check = (o) => syncLib.anchorCheck({ records, publicKey: kb.publicKey, checkpoint: cp, anchors: [], ...o });
  assert.equal(check({ anchors: [{ seq: cp.seq + 2, head: new Uint8Array(32) }] }).alarm, 'rollback');
  assert.equal(check({ anchors: [{ seq: 1, head: new Uint8Array(32).fill(7) }] }).alarm, 'changed');
  assert.equal(check({ anchors: [{ seq: cp.seq, head: new Uint8Array(32).fill(7) }] }).alarm, 'changed');
  assert.equal(check({ anchors: [{ seq: 1, head: records[1].head }] }).ok, true, 'the same head at an anchored seq is fine');
  const flipped = records.map((r, i) => (i === 1 ? { ...r, link: Uint8Array.from(r.link, (x, j) => (j === 50 ? x ^ 1 : x)) } : r));
  assert.equal(check({ records: flipped }).alarm, 'tampered');
  const sig = Uint8Array.from(cp.signature); sig[0] ^= 1;
  assert.equal(check({ checkpoint: { ...cp, signature: sig } }).alarm, 'bad-checkpoint');
  assert.equal(check({ publicKey: peerKey() }).alarm, 'bad-checkpoint');
});

test('approveAnchor: the sheet, Yes, the press - the anchor link is checked; Decline writes nothing; a wrong index is refused unasked', async () => {
  const { a, kb, cp } = await withHistory();
  const asked = [];
  const run = (o) => approve.approveAnchor({ peer: 'ab'.repeat(64), name: 'Pixel', index: 0, chain: kb.deviceId, checkpoint: cp, count: 4, edge: a,
    ask: async (v) => { asked.push(v); return 'approve'; }, timeoutMs: 2000, ...o });
  const before = (await a.head()).seq;
  assert.equal((await run({ ask: async () => 'decline' })).refusal, 'declined');
  assert.equal((await a.head()).seq, before);
  assert.equal((await run({ index: 1, ask: async () => assert.fail('asked') })).refusal, 'invalid');
  const r = await run();
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.deepEqual([asked[0].name, asked[0].seq, asked[0].count], ['Pixel', cp.seq, 4]);
  const f = await lastLink(a);
  assert.deepEqual([f.op, f.slot, f.grantId], [codes.OP.ANCHOR, 0, cp.seq]);
});

/* --- the PC: edge-agent 'sync-with' over two phones, each answered in-process the way ok-rn does --- */
test('edge-agent sync-with: each phone gets the other\'s chain and anchors it with a press; a later rollback raises the alarm', async () => {
  const fsm = require('fs');
  const os = require('os');
  const path = require('path');
  const { client, request } = require('../src/edge');
  const { controlHandlers } = require('../cli/edge-agent');
  const { toHex, fromHex } = require('../src/bytes');
  const home = fsm.mkdtempSync(path.join(os.tmpdir(), 'okanc-'));
  const place = require('../cli/edge-copy').peerSigner(home);
  const AGENT = request.signerFromSecret(new Uint8Array(32).fill(21));
  const seqOf = (r) => chain.decodeLink(r.link).seq;
  /* a phone: its copy of each sibling's chain (+ the anchors), the ok-rn handler's checks in miniature */
  const phone = (edge) => {
    const seen = new Set();
    const copies = new Map();
    const staged = new Map();
    const own = async () => { const h = await edge.head(); return edge.pickup(0, h.seq + 1); };
    return {
      copies,
      send: async (msg) => {
        if (!syncLib.verify(msg, { seen }).ok) return null;
        seen.add(msg.nonce);
        if (!(await edge.peers()).peers.some((p) => toHex(p.publicKey) === msg.peer)) return null;
        const p = msg.payload;
        if (msg.type === syncLib.GIVE_TYPE) {
          const from = (await own()).filter((r) => seqOf(r) >= p.from);
          const batch = from.slice(0, syncLib.BATCH);
          return { ok: true, links: batch.map((r) => [toHex(r.link), toHex(r.head), null]), next: from.length > batch.length ? seqOf(from[batch.length]) : null };
        }
        const sibs = (await edge.siblings()).siblings;
        const index = sibs.findIndex((s) => toHex(s.deviceId) === p.chain);
        if (index < 0) return { ok: false, refusal: 'invalid' };
        const held = copies.get(p.chain) || { links: [], anchors: [] };
        if (msg.type === syncLib.HAVE_TYPE) return { ok: true, ranges: syncLib.rangesOf(held.links.map(seqOf)) };
        if (msg.type === syncLib.LINKS_TYPE) { staged.set(p.part, syncLib.recordsOf(msg)); return { ok: true }; }
        const m = syncLib.merge(held.links, [...staged.values()].flat());
        staged.clear();
        const checkpoint = { seq: p.checkpoint.seq, head: fromHex(p.checkpoint.head), signature: fromHex(p.checkpoint.signature) };
        const c = syncLib.anchorCheck({ records: m.links, publicKey: sibs[index].publicKey, checkpoint, anchors: held.anchors });
        if (!c.ok) return { ok: false, refusal: 'invalid', detail: c.alarm };
        const r = await approve.approveAnchor({ peer: msg.peer, name: p.name, index, chain: fromHex(p.chain), checkpoint, count: m.added.length, edge, ask: async () => 'approve', timeoutMs: 2000 });
        if (r.ok) copies.set(p.chain, { links: m.links, anchors: [...held.anchors, { seq: checkpoint.seq, head: checkpoint.head }] });
        return r;
      },
    };
  };
  const a = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey() }));
  const b = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey() }));
  const [ka, kb] = [await a.publicKey(), await b.publicKey()];
  for (const e of [a, b]) await e.peerAdd(place.publicKey, { timeoutMs: 2000 });
  await a.siblingAdd(kb.publicKey, { timeoutMs: 2000 });
  await b.siblingAdd(ka.publicKey, { timeoutMs: 2000 });
  for (let i = 0; i < 2; i += 1) await b.peerAdd(peerKey(), { timeoutMs: 2000 });
  const pa = phone(a);
  const pb = phone(b);
  const ca = client.createEdgeClient({ edge: a, channel: pa, signer: AGENT });
  const cb = client.createEdgeClient({ edge: b, channel: pb, signer: AGENT });
  const h = controlHandlers({ agent: null, client: ca, ssh: null, edge: a, home, selfName: 'A13',
    openOther: async () => ({ edge: b, client: cb, close: async () => {} }) });
  const bHead = (await b.head()).seq;
  const r = await h['sync-with']({ address: 'AA:BB', otherName: 'Pixel' });
  assert.deepEqual([r.this.ok, r.other.ok], [true, true], JSON.stringify(r));
  assert.equal(r.this.anchored.seq, bHead, 'this phone anchored the other at its head');
  const fa = await lastLink(a);
  assert.deepEqual([fa.op, fa.slot, fa.grantId], [codes.OP.ANCHOR, 0, bHead]);
  assert.equal(pa.copies.get(toHex(kb.deviceId)).links.length, bHead + 1, 'this phone keeps the other\'s whole chain');
  assert.ok(pb.copies.get(toHex(ka.deviceId)), 'the other phone keeps this one\'s chain');
  /* the other key's chain "goes back": this phone anchored #bHead, now it says an older head */
  pa.copies.get(toHex(kb.deviceId)).anchors.push({ seq: bHead + 5, head: new Uint8Array(32) });
  const again = await h['sync-with']({ address: 'AA:BB' });
  assert.equal(again.this.ok, false);
  assert.match(again.this.error, /rollback/);
  fsm.rmSync(home, { recursive: true, force: true });
});
