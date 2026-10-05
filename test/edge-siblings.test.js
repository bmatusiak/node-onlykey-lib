'use strict';
/*
 * R29 siblings (okedge sync phase 2, P2b): other keys that are yours, each
 * with its own chain, paired and unpaired only with a press, each a link in
 * the chain. Against the fake key (test/helpers/fake-edge-key.js), which
 * models the soft key's okplugin_edge SIBLING_ADD / SIBLING_REMOVE /
 * SIBLING_LIST. Plus the 6-digit code both phones show, so the person can
 * see the computer in the middle did not swap a key.
 */
const test = require('node:test');
const assert = require('node:assert');
const { codes, chain, grants } = require('../src/edge');
const { sha256 } = require('../src/vendor/exports/@noble/hashes/sha2.js');
const { p256 } = require('../src/vendor/exports/@noble/curves/nist.js');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

/* another key's Edge key as the key gives keys: X || Y */
const otherKey = () => p256.getPublicKey(p256.utils.randomSecretKey(), false).slice(1);
const enc = (s) => new TextEncoder().encode(s);
const cat = (...a) => Uint8Array.from(a.flatMap((x) => [...x]));

const lastLink = async (edge) => {
  const h = await edge.head();
  const [l] = await edge.pickup(h.seq, 1);
  return chain.decodeLink(l.link);
};

test('siblingSubject = SHA256("OKEDGE-SIBLING-v1" || X || Y || device id)', () => {
  const key = otherKey();
  const id = chain.deviceIdOf(key);
  assert.equal(id.length, 16);
  assert.deepEqual([...id], [...sha256(cat(enc('OKEDGE-DEVICE-v1'), key)).slice(0, 16)]);
  assert.deepEqual([...grants.siblingSubject(key, id)], [...sha256(cat(enc('OKEDGE-SIBLING-v1'), key, id))]);
  assert.throws(() => grants.siblingSubject(key.slice(1), id), TypeError);
  assert.throws(() => grants.siblingSubject(key, id.slice(1)), TypeError);
});

test('a sibling is paired with a press: a sibling-add link, then listed with its device id', async () => {
  const edge = edgeOver(fakeKey());
  const key = otherKey();
  const r = await edge.siblingAdd(key, { timeoutMs: 2000 });
  const f = await lastLink(edge);
  assert.equal(f.seq, r.seq);
  assert.equal(f.op, codes.OP.SIBLING_ADD);
  assert.ok(f.flags & codes.FLAG.PRESS_OBSERVED);
  assert.deepEqual([...f.subject], [...grants.siblingSubject(key, chain.deviceIdOf(key))]);
  const list = await edge.siblings();
  assert.equal(list.max, 4);
  assert.equal(list.siblings.length, 1);
  assert.deepEqual([...list.siblings[0].publicKey], [...key]);
  assert.deepEqual([...list.siblings[0].deviceId], [...chain.deviceIdOf(key)]);
});

test('the key refuses itself and a known sibling; a fifth is refused; removal is a press and names the key', async () => {
  const edge = edgeOver(fakeKey());
  const own = await edge.publicKey();
  await assert.rejects(edge.siblingAdd(own.publicKey, { timeoutMs: 2000 }), (e) => e.status === 'bad-key');
  const keys = [otherKey(), otherKey(), otherKey(), otherKey()];
  for (const k of keys) await edge.siblingAdd(k, { timeoutMs: 2000 });
  await assert.rejects(edge.siblingAdd(keys[0], { timeoutMs: 2000 }), (e) => e.status === 'sibling-known');
  await assert.rejects(edge.siblingAdd(otherKey(), { timeoutMs: 2000 }), (e) => e.status === 'siblings-full');
  await edge.siblingRemove(1, { timeoutMs: 2000 });
  const f = await lastLink(edge);
  assert.equal(f.op, codes.OP.SIBLING_REMOVE);
  assert.deepEqual([...f.subject], [...grants.siblingSubject(keys[1], chain.deviceIdOf(keys[1]))], 'the removal names the key it removed');
  const list = await edge.siblings();
  assert.deepEqual(list.siblings.map((s) => Buffer.from(s.publicKey).toString('hex')),
    [keys[0], keys[2], keys[3]].map((k) => Buffer.from(k).toString('hex')));
  await assert.rejects(edge.siblingRemove(3, { timeoutMs: 2000 }), (e) => e.status === 'no-such-sibling');
});

test('the sibling code: six digits, the same on both phones whichever way round', () => {
  const a = { publicKey: otherKey() };
  const b = { publicKey: otherKey() };
  a.deviceId = chain.deviceIdOf(a.publicKey);
  b.deviceId = chain.deviceIdOf(b.publicKey);
  const ab = grants.siblingCode(a, b);
  assert.match(ab, /^\d{3} \d{3}$/);
  assert.equal(grants.siblingCode(b, a), ab, 'each phone computes it from (its own, the other) - the order must not matter');
});

test('a swapped key gives different codes on the two phones (R29: the computer relays each key)', () => {
  const a = { publicKey: otherKey() };
  const b = { publicKey: otherKey() };
  const m = { publicKey: otherKey() }; /* the key the computer slips in */
  for (const x of [a, b, m]) x.deviceId = chain.deviceIdOf(x.publicKey);
  /* the computer gives phone A the key m instead of b: A shows code(A, m), B shows code(B, A) */
  assert.notEqual(grants.siblingCode(a, m), grants.siblingCode(b, a));
  /* a swapped id with the real key changes it too */
  assert.notEqual(grants.siblingCode(a, { publicKey: b.publicKey, deviceId: m.deviceId }), grants.siblingCode(a, b));
});

/* --- the phone's side: approveSibling (the sheet with the code, the press, the link check) --- */
const approve = require('../src/edge/approve');
const request = require('../src/edge/request');
const syncLib = require('../src/edge/sync');
const placeSigner = () => request.peerSignerFromSecret(p256.utils.randomSecretKey());
const twoPhones = async () => {
  const a = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey() }));
  const b = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey() }));
  const place = placeSigner();
  await a.peerAdd(place.publicKey, { timeoutMs: 2000 });
  await b.peerAdd(place.publicKey, { timeoutMs: 2000 });
  return { a, b, place, ka: await a.publicKey(), kb: await b.publicKey() };
};
const askFor = (to, from, place, name = 'Pixel') => syncLib.buildSibling({ signer: place, deviceId: to.deviceId, key: from.publicKey, id: from.deviceId, name });

test('approveSibling: both phones show the same code; Yes and a press on each pairs them both ways', async () => {
  const { a, b, place, ka, kb } = await twoPhones();
  const shown = [];
  const ask = async (v) => { shown.push(v); return 'approve'; };
  const ra = await approve.approveSibling(await askFor(ka, kb, place), { edge: a, seen: new Set(), ask, timeoutMs: 2000 });
  const rb = await approve.approveSibling(await askFor(kb, ka, place), { edge: b, seen: new Set(), ask, timeoutMs: 2000 });
  assert.deepEqual([ra.ok, rb.ok], [true, true]);
  assert.equal(shown.length, 2);
  assert.match(shown[0].code, /^\d{3} \d{3}$/);
  assert.equal(shown[0].code, shown[1].code, 'the two sheets must show the same code');
  assert.equal(shown[0].sibling, Buffer.from(kb.publicKey).toString('hex'));
  const fa = await lastLink(a);
  assert.equal(fa.seq, ra.seq);
  assert.deepEqual([...fa.subject], [...grants.siblingSubject(kb.publicKey, kb.deviceId)]);
  assert.equal((await b.siblings()).siblings.length, 1);
  /* asked again: already paired - no sheet, no press */
  const again = await approve.approveSibling(await askFor(ka, kb, place), { edge: a, seen: new Set(), ask: async () => assert.fail('asked again') });
  assert.deepEqual([again.ok, again.already], [true, true]);
});

test('approveSibling: a key swapped by the place shows a different code on the two phones', async () => {
  const { a, b, place, ka, kb } = await twoPhones();
  const m = otherKey();
  const shown = [];
  const ask = async (v) => { shown.push(v.code); return 'decline'; };
  await approve.approveSibling(await askFor(ka, { publicKey: m, deviceId: chain.deviceIdOf(m) }, place), { edge: a, seen: new Set(), ask });
  await approve.approveSibling(await askFor(kb, ka, place), { edge: b, seen: new Set(), ask });
  assert.equal(shown.length, 2);
  assert.notEqual(shown[0], shown[1]);
});

test('approveSibling: refused unheard - a place not on the list, another key\'s request, a wrong id, itself, a bad signature', async () => {
  const { a, place, ka, kb } = await twoPhones();
  const never = async () => assert.fail('the sheet came up');
  const run = async (msg) => approve.approveSibling(msg, { edge: a, seen: new Set(), ask: never });
  assert.equal((await run(await askFor(ka, kb, placeSigner()))).refusal, 'invalid');
  assert.equal((await run(await askFor(kb, kb, place))).refusal, 'invalid');
  assert.equal((await run(await syncLib.buildSibling({ signer: place, deviceId: ka.deviceId, key: kb.publicKey, id: ka.deviceId, name: 'x' }))).refusal, 'invalid');
  assert.equal((await run(await askFor(ka, ka, place))).refusal, 'invalid');
  const bad = await askFor(ka, kb, place);
  bad.payload.name = 'changed';
  assert.equal((await run(bad)).dropped, 'bad-signature');
  const before = (await a.head()).seq;
  const d = await approve.approveSibling(await askFor(ka, kb, place), { edge: a, seen: new Set(), ask: async () => 'decline' });
  assert.equal(d.refusal, 'declined');
  assert.equal((await a.head()).seq, before, 'a declined pairing wrote a link');
});

/* --- the PC: edge-agent 'sibling-add' over two phones (each answered in-process like ok-rn) --- */
test('edge-agent sibling-add: adds this PC to each key\'s list if missing, then both sheets at once; both keys pair', async () => {
  const fsm = require('fs');
  const os = require('os');
  const path = require('path');
  const { client } = require('../src/edge');
  const { controlHandlers } = require('../cli/edge-agent');
  const home = fsm.mkdtempSync(path.join(os.tmpdir(), 'oksib-'));
  const AGENT = request.signerFromSecret(new Uint8Array(32).fill(21));
  const sheets = [];
  /* a phone: answers the place's requests the way ok-rn does; every sheet says Yes */
  const phone = (edge, label) => {
    const seen = new Set();
    return {
      send: async (msg) => {
        const ask = async (v) => { sheets.push({ phone: label, type: msg.type, ...v }); return 'approve'; };
        if (msg.type === request.PEER_TYPE) return approve.approvePeerAdd(msg, { edge, seen, ask, timeoutMs: 2000 });
        if (msg.type === syncLib.SIBLING_TYPE) {
          const r = await approve.approveSibling(msg, { edge, seen, ask, timeoutMs: 2000 });
          return r.dropped ? null : r;
        }
        return null;
      },
    };
  };
  const a = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey() }));
  const b = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey() }));
  const ca = client.createEdgeClient({ edge: a, channel: phone(a, 'A'), signer: AGENT });
  const cb = client.createEdgeClient({ edge: b, channel: phone(b, 'B'), signer: AGENT });
  let closed = 0;
  const h = controlHandlers({ agent: null, client: ca, ssh: null, edge: a, home, selfName: 'A13',
    openOther: async (address) => { assert.equal(address, 'AA:BB'); return { edge: b, client: cb, close: async () => { closed += 1; } }; } });
  const r = await h['sibling-add']({ address: 'AA:BB', otherName: 'Pixel' });
  assert.deepEqual(r.peersAdded.sort(), ['other', 'this']);
  assert.deepEqual([r.this.ok, r.other.ok], [true, true]);
  assert.equal(closed, 1, 'the second link is closed after the request');
  const sib = sheets.filter((s) => s.type === syncLib.SIBLING_TYPE);
  assert.equal(sib.length, 2);
  assert.equal(sib[0].code, sib[1].code, 'the two phones show the same code');
  assert.deepEqual(sib.map((s) => [s.phone, s.name]).sort(), [['A', 'Pixel'], ['B', 'A13']]);
  const la = await h.siblings();
  assert.equal(la.siblings.length, 1);
  assert.equal(la.siblings[0].key, Buffer.from((await b.publicKey()).publicKey).toString('hex'));
  assert.equal((await b.siblings()).siblings.length, 1);
  /* again: already paired on both, no peer sheets */
  sheets.length = 0;
  const again = await h['sibling-add']({ address: 'AA:BB' });
  assert.deepEqual([again.peersAdded.length, again.this.already, again.other.already], [0, true, true]);
  assert.equal(sheets.length, 0);
  /* the same key behind both links is refused before anything is asked */
  const same = controlHandlers({ agent: null, client: ca, ssh: null, edge: a, home, openOther: async () => ({ edge: a, client: ca, close: async () => {} }) });
  await assert.rejects(same['sibling-add']({ address: 'x' }), /same key/);
  fsm.rmSync(home, { recursive: true, force: true });
});
