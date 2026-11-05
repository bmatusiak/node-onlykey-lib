'use strict';

/*
 * The MCP plan's run on a device (edge/src/plan.js, Step 4b), on the fake key, with the device's own Edge host in
 * process as the budget client's channel (approve.approveRequest, as edge-l7.test.js). Fingerprints first, data after
 * (Brad, 2026-11-04): one budget sized to the plan under the agent's own card, one approval of the fingerprints, then the
 * data - every item checked before anything is signed - each item one paid use and its receipt, and every result told at
 * the end. A mismatch, a Decline, a plan_finish before the data and another agent's card each end it with nothing signed.
 */
const test = require('node:test');
const assert = require('node:assert');
const { approve, client, plan: planLib, codes, chain } = require('../src');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');
const { testCard, cardOfFor } = require('./helpers/cards');

/* the MCP agent that built the plans (its id: the SHA-256 of its agent_key - mcp.js hello) and another one */
const AGENT = 'a1'.repeat(32);
const OTHER = 'b2'.repeat(32);

/* plans are asked under the agent's own card (approve.js; plan.card): its ssh key and stored slot 3 */
let cardOf = null;
test.before(async () => {
  cardOf = cardOfFor(
    await testCard({ label: 'agent', ssh: 'ssh://test@example.com', slots: [3], agent: AGENT }),
    await testCard({ label: 'computer', ssh: 'ssh://test@example.com' }),
  );
});

function host(edge, { answer = 'approve', views = [], agent = AGENT } = {}) {
  const seen = new Set();
  return {
    async send(msg) {
      const r = await approve.approveRequest(msg, {
        edge, from: `agent:${agent}`, seen, cardOf, agent,
        ask: async (view) => { views.push(view); return answer; },
        verifyCopy: async () => ({ ok: true, head: (await edge.head()).head }),
        timeoutMs: 2000,
      });
      return r.dropped ? null : r;
    },
  };
}

async function readyKey() {
  const transport = fakeKey();
  const edge = edgeOver(transport);
  await edge.receipt(0, 0, new Uint8Array(32));
  return { transport, edge };
}

/* the key's sign stood in by the fake (it decides the pay); the signature a fixed 64 bytes */
const fakeSigners = (transport, signed = []) => ({
  async ssh(key, data, pay) {
    await pay(new Uint8Array([...data, ...require('../../src/protocol/agent').identityHash(key.derive)]), (bytes) => { transport.use(bytes, { slot: planLib.SIGN_CODE }); signed.push(Buffer.from(data).toString()); return new Uint8Array(64).fill(7); });
    return { signature: Buffer.alloc(64, 7).toString('base64'), encoding: 'base64' };
  },
  gpg: planLib.planSigners({ okcrypto: null }).gpg,
});

/* the room's side: updates in order, and the data / finish the agent sends */
function room() {
  const updates = [];
  const listeners = new Set();
  const changed = [];
  return {
    updates,
    update: async (u) => { updates.push(u); for (const r of changed.splice(0)) r(); },
    subscribe: (l) => { listeners.add(l); return () => listeners.delete(l); },
    tell: (e) => { for (const l of [...listeners]) l(e); },
    state: (s) => new Promise((resolve) => {
      const look = () => (updates.some((u) => u.state === s) ? resolve() : changed.push(look));
      look();
    }),
  };
}

const fp = (text) => planLib.fingerprintOf(new TextEncoder().encode(text));
const PLAN = {
  id: 'p1', title: 'sign the release notes', agent: { id: AGENT, name: 'test agent' }, card: 'agent',
  items: [
    { item: 1, op: 'sign', key: { kind: 'ssh', identity: 'ssh://test@example.com' }, reason: 'the notes', fingerprint: fp('notes v1') },
    { item: 2, op: 'sign', key: { kind: 'ssh', identity: 'test@example.com' }, reason: 'the tag', fingerprint: fp('tag v1') },
  ],
};
const run = (plan, edge, transport, r, o = {}) => planLib.runPlan({
  plan, client: client.createEdgeClient({ edge, channel: host(edge, o) }), signers: o.signers || fakeSigners(transport, o.signed), update: r.update, subscribe: r.subscribe, progress: o.progress,
});
async function paidLinks(edge) {
  const h = await edge.head();
  return (await edge.pickup(h.oldest, h.seq - h.oldest + 1)).map((x) => chain.decodeLink(x.link)).filter((f) => f.op === codes.OP.SIGN && f.decision === codes.DECISION.SELF_PRESS);
}

test('a plan: the fingerprints approved (no data yet), then the data, each checked, signed in order, every result told at the end - each use receipted, the budget ended', async () => {
  const { transport, edge } = await readyKey();
  const views = [];
  const signed = [];
  const r = room();
  const end = run(PLAN, edge, transport, r, { views, signed });
  await r.state('running');
  assert.equal(views.length, 1, 'one sheet');
  assert.match(views[0].reason, new RegExp(`^sign the release notes - 2 signs: the notes \\(${fp('notes v1').slice(0, 16)}\\); the tag \\(${fp('tag v1').slice(0, 16)}\\)$`), 'the sheet names each fingerprint');
  assert.deepEqual(views[0].scopes.map((s) => [s.identity, s.cap]), [['ssh://test@example.com', 2]], 'one scope: both items name the same key');
  r.tell({ ev: 'data', item: 2, data: 'tag v1' });
  assert.deepEqual(signed, [], 'nothing signed before every item has its data');
  r.tell({ ev: 'data', item: 1, data: 'notes v1' });
  assert.equal(await end, 'done');
  assert.deepEqual(signed, ['notes v1', 'tag v1'], 'in item order');
  assert.deepEqual(r.updates.filter((u) => u.state).map((u) => u.state), ['running', 'done']);
  assert.ok(r.updates.slice(0, -1).every((u) => !u.results), 'no result before the end');
  const last = r.updates[r.updates.length - 1];
  assert.deepEqual(last.results.map((x) => [x.item, Boolean(x.signature)]), [[1, true], [2, true]]);
  assert.equal(last.receipts.length, 2, 'a receipt per use');
  assert.equal((await paidLinks(edge)).length, 2);
  const h = await edge.head();
  const links = (await edge.pickup(h.oldest, h.seq - h.oldest + 1)).map((x) => chain.decodeLink(x.link));
  assert.ok(links.some((f) => f.op === codes.OP.GRANT_END), 'the budget ended');
  assert.deepEqual(h.live || [], [], 'nothing left live');
});

test('the host follows the budget: progress after each receipt and once at its end; a budget its last receipt completed is not revoked again', async () => {
  const { transport, edge } = await readyKey();
  const r = room();
  const seen = [];
  const revoke = edge.revoke.bind(edge);
  let revokes = 0;
  edge.revoke = (id) => { revokes++; return revoke(id); };
  const end = run(PLAN, edge, transport, r, { progress: async () => { const h = await edge.head(); seen.push(h.live && h.live.length ? 'live' : 'ended'); } });
  await r.state('running');
  r.tell({ ev: 'data', item: 1, data: 'notes v1' });
  r.tell({ ev: 'data', item: 2, data: 'tag v1' });
  assert.equal(await end, 'done');
  assert.deepEqual(seen, ['live', 'ended', 'ended'], 'after receipt 1 (still live), receipt 2 (the key completed it), and the end');
  assert.equal(revokes, 0, 'the key wrote the grant-end at the last receipt - nothing to revoke');
});

test('data that does not match its approved fingerprint: nothing is signed - not even the items that match - and the budget ends', async () => {
  const { transport, edge } = await readyKey();
  const signed = [];
  const r = room();
  const end = run(PLAN, edge, transport, r, { signed });
  await r.state('running');
  r.tell({ ev: 'data', item: 1, data: 'notes v1' });
  r.tell({ ev: 'data', item: 2, data: 'tag v2 - not what was approved' });
  assert.equal(await end, 'failed');
  assert.deepEqual(signed, []);
  assert.match(r.updates[r.updates.length - 1].why, /item 2's data does not match its approved fingerprint .* nothing signed/);
  assert.equal((await paidLinks(edge)).length, 0, 'the key paid nothing');
  assert.deepEqual((await edge.head()).live || [], [], 'the budget ended');
});

test('a plan the owner declines: no budget, the plan is declined', async () => {
  const { transport, edge } = await readyKey();
  const r = room();
  assert.equal(await run(PLAN, edge, transport, r, { answer: 'decline' }), 'declined');
  assert.deepEqual(r.updates.map((u) => u.state), ['declined']);
  assert.deepEqual((await edge.head()).live || [], []);
});

test('plan_finish before every item\'s data came: nothing is signed, the budget ends, the plan is ended', async () => {
  const { transport, edge } = await readyKey();
  const signed = [];
  const r = room();
  const end = run(PLAN, edge, transport, r, { signed });
  await r.state('running');
  r.tell({ ev: 'data', item: 1, data: 'notes v1' });
  r.tell({ ev: 'finish' });
  assert.equal(await end, 'ended');
  assert.deepEqual(signed, []);
  assert.match(r.updates[r.updates.length - 1].why, /finished by the agent before the data of item\(s\) 2 came - nothing signed/);
  assert.deepEqual((await edge.head()).live || [], [], 'the budget ended');
});

test('a stored RSA slot: the scope names the slot and no identity, the key signs the digest with the signature\'s length asked (4096 bits: 512 bytes)', async () => {
  const { transport, edge } = await readyKey();
  const views = [];
  const asked = [];
  const okcrypto = {
    async sign(slot, data, opts) { asked.push({ slot, length: data.length, expectBytes: opts.expectBytes, paid: opts.paid }); transport.use(data, { slot }); return new Uint8Array(512).fill(5); },
  };
  const digest = new Uint8Array(64).fill(9);
  const plan = {
    id: 'p3', title: 'sign ok-edge 0.0.15', agent: { id: AGENT, name: 'release signer' }, card: 'agent',
    items: [
      { item: 1, op: 'sign', key: { kind: 'rsa', slot: 3, bits: 4096 }, reason: 'APK v2', fingerprint: planLib.fingerprintOf(digest) },
      { item: 2, op: 'sign', key: { kind: 'rsa', slot: 3, bits: 4096 }, reason: 'APK v3', fingerprint: planLib.fingerprintOf(new Uint8Array(64).fill(8)) },
    ],
  };
  const r = room();
  const end = run(plan, edge, transport, r, { views, signers: planLib.planSigners({ okcrypto }) });
  await r.state('running');
  assert.deepEqual(views[0].scopes, [{ op: 'sign', slot: 3, cap: 2 }], 'one stored-slot scope, no identity');
  r.tell({ ev: 'data', item: 1, data: Buffer.from(digest).toString('base64'), encoding: 'base64' });
  r.tell({ ev: 'data', item: 2, data: Buffer.alloc(64, 8).toString('base64'), encoding: 'base64' });
  assert.equal(await end, 'done');
  /* paid: the key self-presses, so the lib says no press (box, 2026-11-04: an unpaid one raised a code no sheet showed) */
  assert.deepEqual(asked, [{ slot: 3, length: 64, expectBytes: 512, paid: true }, { slot: 3, length: 64, expectBytes: 512, paid: true }]);
  const last = r.updates[r.updates.length - 1];
  assert.equal(Buffer.from(last.results[0].signature, 'base64').length, 512);
  assert.equal((await paidLinks(edge)).length, 2, 'both paid by the budget');
});

test('a sign the key paid whose answer was lost: its receipt is still filed (R16), so the next item runs; the plan ends failed', async () => {
  const { transport, edge } = await readyKey();
  let n = 0;
  /* item 1: the key pays, the answer never comes; item 2: as usual */
  const okcrypto = {
    async sign(slot, data) {
      transport.use(data, { slot });
      if (++n === 1) throw new Error('vendor-bridge: no answer in 30000 ms');
      return new Uint8Array(512).fill(5);
    },
  };
  const d = [new Uint8Array(64).fill(1), new Uint8Array(64).fill(2)];
  const key = { kind: 'rsa', slot: 3, bits: 4096 };
  const plan = { id: 'p4', title: 'lost answer', agent: { id: AGENT, name: 'release signer' }, card: 'agent',
    items: d.map((x, i) => ({ item: i + 1, op: 'sign', key, reason: `sig ${i + 1}`, fingerprint: planLib.fingerprintOf(x) })) };
  const r = room();
  const end = run(plan, edge, transport, r, { signers: planLib.planSigners({ okcrypto }) });
  await r.state('running');
  d.forEach((x, i) => r.tell({ ev: 'data', item: i + 1, data: Buffer.from(x).toString('base64'), encoding: 'base64' }));
  assert.equal(await end, 'failed');
  const last = r.updates[r.updates.length - 1];
  assert.match(last.results[0].refusal, /no answer in 30000 ms/);
  assert.ok(last.results[1].signature, 'item 2 signed after item 1\'s receipt');
  assert.deepEqual(last.receipts.map((x) => x.code), ['AGENT_ERROR', 'OK'], 'both paid uses receipted');
  assert.equal((await edge.head()).owed, false, 'nothing owed at the end');
});

test('the agent card is the agent\'s own: another agent\'s card, or a computer\'s, opens no budget', async () => {
  for (const [card, agent, why] of [['agent', OTHER, /another agent's card/], ['computer', AGENT, /an MCP agent asks under a card made for it/]]) {
    const { transport, edge } = await readyKey();
    const views = [];
    const r = room();
    assert.equal(await run({ ...PLAN, card }, edge, transport, r, { views, agent }), 'failed');
    assert.equal(views.length, 0, 'refused before the sheet');
    assert.match(r.updates[0].why, why);
  }
});

test('a slot the card does not hold opens no budget', async () => {
  const { transport, edge } = await readyKey();
  const r = room();
  const plan = { ...PLAN, items: [{ item: 1, op: 'sign', key: { kind: 'rsa', slot: 2, bits: 2048 }, reason: 'x', fingerprint: fp('x') }] };
  assert.equal(await run(plan, edge, transport, r), 'failed');
  assert.match(r.updates[0].why, /the stored slot 2 is not on this card/);
});

test('a plan with an item a device cannot run fails before any budget: a decrypt, a key that is no key, an item with no fingerprint', async () => {
  const { transport, edge } = await readyKey();
  const views = [];
  const r = room();
  const plan = {
    id: 'p2', title: 'mixed', agent: { id: AGENT, name: 'test agent' }, card: 'agent',
    items: [
      { item: 1, op: 'decrypt', key: { kind: 'gpg', identity: 'A <a@x>' }, reason: 'read it', fingerprint: fp('x') },
      { item: 2, op: 'sign', key: { kind: 'pgp', identity: 'A <a@x>' }, reason: 'bad kind', fingerprint: fp('x') },
      { item: 3, op: 'sign', key: { kind: 'ssh', identity: 'ssh://test@example.com' }, reason: 'no fingerprint' },
      { item: 4, op: 'sign', key: { kind: 'ssh', identity: 'ssh://test@example.com' }, reason: 'fine', fingerprint: fp('z') },
    ],
  };
  assert.equal(await run(plan, edge, transport, r, { views }), 'failed');
  assert.equal(views.length, 0, 'no sheet');
  const results = Object.fromEntries(r.updates[0].results.map((x) => [x.item, x]));
  assert.match(results[1].refusal, /decrypt is not run by a device yet/);
  assert.match(results[2].refusal, /a key is ssh, gpg or rsa/);
  assert.match(results[3].refusal, /no fingerprint/);
  assert.equal(results[4], undefined, 'the runnable one is not refused - the plan as a whole is');
});

test('the keys an item names, as Edge names them', () => {
  assert.equal(planLib.keyOf({ kind: 'ssh', identity: 'git@github.com' }).name, 'ssh://git@github.com');
  assert.equal(planLib.keyOf({ kind: 'ssh', identity: 'ssh://github.com' }).name, 'ssh://github.com');
  assert.equal(planLib.keyOf({ kind: 'gpg', identity: 'gpg://Me <me@x>' }).name, 'gpg://Me <me@x>');
  assert.deepEqual(planLib.keyOf({ kind: 'rsa', slot: 3, bits: 4096 }), { kind: 'rsa', name: 'slot 3', slot: 3, bits: 4096 });
  assert.throws(() => planLib.keyOf({ kind: 'ssh', identity: 'ssh://a@b:22/x' }), /not an ssh identity/);
  assert.throws(() => planLib.keyOf({ kind: 'rsa', slot: 5, bits: 4096 }), /stored slot 1-4/);
  assert.throws(() => planLib.keyOf({ kind: 'rsa', slot: 3 }), /names its size/);
});
