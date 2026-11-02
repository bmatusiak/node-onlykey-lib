'use strict';

/*
 * The MCP plan's run on a device (edge/src/plan.js, Step 4b), on the fake key, with the device's own Edge host in
 * process as the budget client's channel (approve.approveRequest, as edge-l7.test.js): one budget sized to the plan,
 * one approval, each item one paid use and its receipt, a placeholder waiting inside the open budget for its fill,
 * plan_finish dropping what still waits, a Decline ending it with no budget.
 */
const test = require('node:test');
const assert = require('node:assert');
const { approve, client, plan: planLib, codes, chain } = require('../src');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

function host(edge, { answer = 'approve', views = [] } = {}) {
  const seen = new Set();
  return {
    async send(msg) {
      const r = await approve.approveRequest(msg, {
        edge, from: 'agent:test', seen,
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

/* the room's side: updates in order, and the fill / finish the agent sends */
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

const PLAN = {
  id: 'p1', title: 'sign the release notes', agent: { id: 'a1', name: 'test agent' },
  items: [
    { item: 1, op: 'sign', key: { kind: 'ssh', identity: 'ssh://test@example.com' }, reason: 'the notes', data: 'notes v1' },
    { item: 2, op: 'sign', key: { kind: 'ssh', identity: 'test@example.com' }, reason: 'the tag, once it is made', data: null, held: true },
  ],
};

test('a plan: one budget sized to it, one approval, item 1 signed, the placeholder waits (paused) for its fill, then done - every use receipted, the budget ended', async () => {
  const { transport, edge } = await readyKey();
  const views = [];
  const r = room();
  const signed = [];
  const run = planLib.runPlan({ plan: PLAN, client: client.createEdgeClient({ edge, channel: host(edge, { views }) }), signers: fakeSigners(transport, signed), update: r.update, subscribe: r.subscribe });
  await r.state('paused');
  assert.equal(views.length, 1, 'one sheet');
  assert.match(views[0].reason, /^sign the release notes - 2 signs: the notes; \(later\) the tag/);
  assert.deepEqual(views[0].scopes.map((s) => [s.identity, s.cap]), [['ssh://test@example.com', 2]], 'one scope: both items name the same key');
  r.tell({ ev: 'fill', item: 2, data: 'tag v1' });
  assert.equal(await run, 'done');
  assert.deepEqual(signed, ['notes v1', 'tag v1']);
  const states = r.updates.filter((u) => u.state).map((u) => u.state);
  assert.deepEqual(states, ['running', 'paused', 'running', 'done']);
  const results = r.updates.flatMap((u) => u.results || []);
  assert.deepEqual(results.map((x) => [x.item, Boolean(x.signature)]), [[1, true], [2, true]]);
  const last = r.updates[r.updates.length - 1];
  assert.equal(last.receipts.length, 2, 'a receipt per use');
  /* the key: two paid uses, their receipts, and the budget's end */
  const h = await edge.head();
  const links = (await edge.pickup(h.oldest, h.seq - h.oldest + 1)).map((x) => chain.decodeLink(x.link));
  assert.equal(links.filter((f) => f.op === codes.OP.SIGN && f.decision === codes.DECISION.SELF_PRESS).length, 2);
  assert.ok(links.some((f) => f.op === codes.OP.GRANT_END), 'the budget ended');
  assert.deepEqual(h.live || [], [], 'nothing left live');
});

test('a plan the owner declines: no budget, the plan is declined', async () => {
  const { transport, edge } = await readyKey();
  const r = room();
  const end = await planLib.runPlan({ plan: PLAN, client: client.createEdgeClient({ edge, channel: host(edge, { answer: 'decline' }) }), signers: fakeSigners(transport), update: r.update, subscribe: r.subscribe });
  assert.equal(end, 'declined');
  assert.deepEqual(r.updates.map((u) => u.state), ['declined']);
  assert.deepEqual((await edge.head()).live || [], []);
});

test('plan_finish while a placeholder waits: it is dropped, the budget ends, the plan is ended', async () => {
  const { transport, edge } = await readyKey();
  const r = room();
  const run = planLib.runPlan({ plan: PLAN, client: client.createEdgeClient({ edge, channel: host(edge) }), signers: fakeSigners(transport), update: r.update, subscribe: r.subscribe });
  await r.state('paused');
  r.tell({ ev: 'finish' });
  assert.equal(await run, 'ended');
  const results = r.updates.flatMap((u) => u.results || []);
  assert.match(results.find((x) => x.item === 2).refusal, /finished before its data came/);
  assert.deepEqual((await edge.head()).live || [], [], 'the budget ended');
});

test('what a device cannot run is refused per item, before the budget: a decrypt, a key that is no key; a gpg identity this device does not keep is refused at its turn and the rest still runs', async () => {
  const { transport, edge } = await readyKey();
  const r = room();
  const views = [];
  const plan = {
    id: 'p2', title: 'mixed', agent: { id: 'a1', name: 'test agent' },
    items: [
      { item: 1, op: 'decrypt', key: { kind: 'gpg', identity: 'A <a@x>' }, reason: 'read it', data: 'x' },
      { item: 2, op: 'sign', key: { kind: 'pgp', identity: 'A <a@x>' }, reason: 'bad kind', data: 'x' },
      { item: 3, op: 'sign', key: { kind: 'gpg', identity: 'A <a@x>' }, reason: 'the gpg one', data: 'y' },
      { item: 4, op: 'sign', key: { kind: 'ssh', identity: 'ssh://test@example.com' }, reason: 'the ssh one', data: 'z' },
    ],
  };
  const end = await planLib.runPlan({ plan, client: client.createEdgeClient({ edge, channel: host(edge, { views }) }), signers: fakeSigners(transport), update: r.update, subscribe: r.subscribe });
  assert.equal(end, 'done');
  assert.deepEqual(views[0].scopes.map((s) => s.identity), ['gpg://A <a@x>', 'ssh://test@example.com']);
  const results = Object.fromEntries(r.updates.flatMap((u) => u.results || []).map((x) => [x.item, x]));
  assert.match(results[1].refusal, /decrypt is not run by a device yet/);
  assert.match(results[2].refusal, /a key is ssh or gpg/);
  assert.match(results[3].refusal, /keeps no agent identity for gpg "A <a@x>"/);
  assert.ok(results[4].signature);
  assert.equal(r.updates[r.updates.length - 1].receipts.length, 1, 'only the use the key paid is receipted');
});

test('the keys an item names, as Edge names them', () => {
  assert.equal(planLib.keyOf({ kind: 'ssh', identity: 'git@github.com' }).name, 'ssh://git@github.com');
  assert.equal(planLib.keyOf({ kind: 'ssh', identity: 'ssh://github.com' }).name, 'ssh://github.com');
  assert.equal(planLib.keyOf({ kind: 'gpg', identity: 'gpg://Me <me@x>' }).name, 'gpg://Me <me@x>');
  assert.throws(() => planLib.keyOf({ kind: 'ssh', identity: 'ssh://a@b:22/x' }), /not an ssh identity/);
});
