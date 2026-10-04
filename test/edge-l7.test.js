'use strict';

/*
 * L7 - Edge from an app (src/edge/request.js, approve.js, client.js), on the
 * fake key, with the APP's side (what ok-rn runs) in-process as the channel.
 * mcp-service.md 4.7a: one EDGE_REQUEST, signed by the agent's registered key;
 * the app drops unsigned or replayed ones, checks caps (<= 300) and lifetime,
 * shows text and names (own identities flagged), makes labels and the reason
 * hash itself, verifies its copy, grants on the key, answers with the budget
 * or a typed refusal. The agent checks the opening against the key itself.
 */
const test = require('node:test');
const assert = require('node:assert');
const { request, approve, client, codes, chain } = require('../src/edge');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

const AGENT = request.signerFromSecret(new Uint8Array(32).fill(21));
const STRANGER = request.signerFromSecret(new Uint8Array(32).fill(22));
const BRAD = 'ssh://bmatusiak@localhost';
const AGENT_ID = 'ssh://agent@nitro16';
const hex = (b) => Buffer.from(b).toString('hex');

/* the phone: approveRequest over the key's edge service, the person answering `answer` */
function phone(edge, { answer = 'approve', registered = [hex(AGENT.publicKey)], views = [], grantAs = null } = {}) {
  const seen = new Set();
  return {
    seen,
    views,
    async send(msg) {
      const sent = grantAs ? { ...msg, scopes: msg.scopes.map((s) => ({ ...s, identity: grantAs })) } : msg;
      const r = await approve.approveRequest(sent, {
        edge, registered, seen, ownIdentities: [BRAD],
        ask: async (view) => { views.push(view); return answer; },
        verifyCopy: async () => ({ ok: true, head: (await edge.head()).head }),
        timeoutMs: 2000,
      });
      return r.dropped ? null : r;
    },
  };
}

/* a key with nothing owed (the fake starts with one owed use, #0) */
async function readyKey() {
  const transport = fakeKey();
  const edge = edgeOver(transport);
  await edge.ticket(0, 0, new Uint8Array(32));
  return { transport, edge };
}

test('L7: request -> use -> ticket -> use -> ticket -> end, each use paid by the budget and checked', async () => {
  const { transport, edge } = await readyKey();
  const views = [];
  const c = client.createEdgeClient({ edge, channel: phone(edge, { views }), signer: AGENT });
  const budget = await c.request({ reason: 'push bm-ok/ok-rn', scopes: [{ op: 'sign', slot: 222, cap: 2, identity: AGENT_ID }], ttlMinutes: 60 });
  assert.equal(views.length, 1);
  assert.equal(views[0].reason, 'push bm-ok/ok-rn', 'the sheet shows the TEXT');
  assert.equal(views[0].scopes[0].identity, AGENT_ID, 'the sheet shows the NAME');
  assert.equal(views[0].ownWarning, false, 'an agent identity shows normally');
  assert.equal(budget.uses, 2);

  const sign = (bytes) => transport.use(bytes, { slot: 222 });
  const one = await budget.use(Uint8Array.from([1, 2, 3]), sign);
  assert.equal(JSON.stringify([one.link.paid, one.link.step]), '[true,1]', 'the budget paid for use 1');
  assert.deepEqual(budget.pending(), [one.link.seq]);
  await assert.rejects(budget.use(Uint8Array.from([4]), sign), (e) => e.code === 'EEDGE_ARM' && e.reason === 'ticket-owed', 'use() before the ticket');
  const first = await budget.ticket(one.link, { code: 'OK', message: 'pushed' });
  assert.equal(first.ended, undefined, 'a ticket with uses left must not end the budget');
  const two = await budget.use(Uint8Array.from([4, 5]), sign);
  assert.equal(JSON.stringify([two.link.paid, two.link.step]), '[true,2]');
  /* R16 (spec 2026-10-04): the last use's ticket ends the used-up budget - a grant-end link, the slot freed */
  const last = await budget.ticket(two.link, { message: 'pushed again' });
  assert.equal(last.ended, true, 'the last ticket did not end the used-up budget');
  assert.deepEqual((await edge.head()).live, [], 'the used-up budget still holds a live slot');
  let ran = false;
  await assert.rejects(budget.use(Uint8Array.from([6]), async (b) => { ran = true; return sign(b); }), (e) => e.code === 'EEDGE_ARM' && e.reason === 'ended');
  assert.equal(ran, false, 'an ended budget never runs the operation');
  await budget.end(); /* again: harmless */
});

test('L7: a request naming the person\'s own identity is flagged for the red warning; an agent identity is not', async () => {
  const { edge } = await readyKey();
  const views = [];
  const c = client.createEdgeClient({ edge, channel: phone(edge, { views, answer: 'decline' }), signer: AGENT });
  await assert.rejects(c.request({ reason: 'sign as Brad', scopes: [{ op: 'sign', slot: 201, cap: 1, identity: BRAD }], ttlMinutes: 10 }),
    (e) => e.code === 'EEDGE_REFUSED' && e.refusal === 'declined');
  assert.equal(views[0].ownWarning, true, 'the person\'s own identity must be flagged');
  assert.equal(views[0].scopes[0].own, true);
  await assert.rejects(c.request({ reason: 'agent push', scopes: [{ op: 'sign', slot: 201, cap: 1, identity: AGENT_ID }], ttlMinutes: 10 }),
    (e) => e.refusal === 'declined');
  assert.equal(views[1].ownWarning, false);
});

test('L7: the app drops unregistered, tampered and replayed requests - nothing is answered', async () => {
  const { edge } = await readyKey();
  const seen = new Set();
  const opts = {
    edge, registered: [hex(AGENT.publicKey)], seen, ask: async () => assert.fail('asked the person'),
    verifyCopy: async () => ({ ok: true, head: (await edge.head()).head }),
  };
  const scopes = [{ op: 'sign', slot: 222, cap: 1, identity: AGENT_ID }];
  const stranger = await request.build({ signer: STRANGER, reason: 'r', scopes, lifetime: 10 });
  assert.deepEqual(await approve.approveRequest(stranger, opts), { dropped: 'unregistered' });
  const good = await request.build({ signer: AGENT, reason: 'r', scopes, lifetime: 10 });
  assert.deepEqual(await approve.approveRequest({ ...good, reason: 'r - and sign everything' }, opts), { dropped: 'bad-signature' });
  assert.deepEqual(await approve.approveRequest({ ...good, scopes: [{ ...scopes[0], identity: BRAD }] }, opts), { dropped: 'bad-signature' }, 'a name changed after signing');
  const once = await approve.approveRequest(good, { ...opts, ask: async () => 'decline' });
  assert.equal(once.refusal, 'declined');
  assert.deepEqual(await approve.approveRequest(good, opts), { dropped: 'replayed' });
});

test('L7: caps over 300, a bad lifetime or a derived code without an identity are refused - by the client before sending, by the app if sent', async () => {
  const { edge } = await readyKey();
  const views = [];
  const c = client.createEdgeClient({ edge, channel: phone(edge, { views }), signer: AGENT });
  await assert.rejects(c.request({ reason: 'r', scopes: [{ op: 'sign', slot: 2, cap: 301 }], ttlMinutes: 10 }), (e) => e.code === 'EEDGE_INVALID' && /300/.test(e.message));
  await assert.rejects(c.request({ reason: 'r', scopes: [{ op: 'sign', slot: 2, cap: 1 }], ttlMinutes: 0 }), (e) => e.code === 'EEDGE_INVALID');
  await assert.rejects(c.request({ reason: 'r', scopes: [{ op: 'sign', slot: 222, cap: 1 }], ttlMinutes: 10 }), (e) => e.code === 'EEDGE_INVALID' && /R11a/.test(e.message));
  assert.equal(views.length, 0, 'nothing reached the person');
  const tooBig = await request.build({ signer: AGENT, reason: 'r', scopes: [{ op: 'sign', slot: 2, cap: 200 }, { op: 'sign', slot: 101, cap: 101 }], lifetime: 10 });
  const r = await approve.approveRequest(tooBig, {
    edge, registered: [hex(AGENT.publicKey)], seen: new Set(), ask: async () => assert.fail('asked the person'),
    verifyCopy: async () => ({ ok: true, head: (await edge.head()).head }),
  });
  assert.equal(r.refusal, 'invalid');
});

test('L7: typed refusals - a ticket owed, an unverified copy', async () => {
  const transport = fakeKey(); /* #0 still owes its ticket */
  const edge = edgeOver(transport);
  const scopes = [{ op: 'sign', slot: 2, cap: 1 }];
  const owed = client.createEdgeClient({ edge, channel: phone(edge), signer: AGENT });
  await assert.rejects(owed.request({ reason: 'r', scopes, ttlMinutes: 10 }), (e) => e.refusal === 'ticket_owed');
  await edge.ticket(0, 0, new Uint8Array(32));
  const unverified = {
    send: async (msg) => approve.approveRequest(msg, {
      edge, registered: [hex(AGENT.publicKey)], seen: new Set(), ask: async () => 'approve', verifyCopy: async () => ({ ok: false }),
    }),
  };
  await assert.rejects(client.createEdgeClient({ edge, channel: unverified, signer: AGENT }).request({ reason: 'r', scopes, ttlMinutes: 10 }),
    (e) => e.refusal === 'copy_unverified');
  assert.deepEqual((await edge.head()).live, [], 'no budget opened');
});

test('L7: an answer that is not the budget the agent asked for is caught - the opening is checked against the key', async () => {
  const { edge } = await readyKey();
  /* a phone that grants for ANOTHER identity than the one requested (and so signs a different subject) */
  const lying = phone(edge, { grantAs: BRAD });
  lying.send = (orig => async (msg) => {
    const r = await approve.approveRequest(await request.build({ signer: AGENT, reason: msg.reason, scopes: msg.scopes.map((s) => ({ ...s, identity: BRAD })), lifetime: msg.lifetime }), {
      edge, registered: [hex(AGENT.publicKey)], seen: new Set(), ask: async () => 'approve',
      verifyCopy: async () => ({ ok: true, head: (await edge.head()).head }),
    });
    return r;
  })(lying.send);
  const c = client.createEdgeClient({ edge, channel: lying, signer: AGENT });
  await assert.rejects(c.request({ reason: 'agent push', scopes: [{ op: 'sign', slot: 222, cap: 1, identity: AGENT_ID }], ttlMinutes: 10 }),
    (e) => e.code === 'EEDGE_OPENING');
});

test('L7: the use is checked to be this use - another request slipped in between ARM and sign is caught', async () => {
  const { transport, edge } = await readyKey();
  const c = client.createEdgeClient({ edge, channel: phone(edge), signer: AGENT });
  const budget = await c.request({ reason: 'r', scopes: [{ op: 'sign', slot: 222, cap: 2, identity: AGENT_ID }], ttlMinutes: 10 });
  await assert.rejects(budget.use(Uint8Array.from([1]), async () => transport.use(Uint8Array.from([9, 9]), { slot: 222 })), (e) => e.code === 'EEDGE_LINK');
});

test('L7: a budget outlives one process - resume() from the store, with what is owed', async () => {
  const { transport, edge } = await readyKey();
  const mem = new Map();
  const store = { get: async (k) => mem.get(k) || null, set: async (k, v) => { mem.set(k, v); } };
  const first = client.createEdgeClient({ edge, channel: phone(edge), signer: AGENT, store });
  const b1 = await first.request({ reason: 'r', scopes: [{ op: 'sign', slot: 222, cap: 2, identity: AGENT_ID }], ttlMinutes: 10 });
  const u = await b1.use(Uint8Array.from([1]), (b) => transport.use(b, { slot: 222 }));
  const second = client.createEdgeClient({ edge, channel: null, signer: AGENT, store });
  const b2 = await second.resume(b1.grantId);
  assert.deepEqual(b2.pending(), [u.link.seq], 'the debt came along');
  await b2.ticket(u.link, { message: 'from the second process' });
  const v = await b2.use(Uint8Array.from([2]), (b) => transport.use(b, { slot: 222 }));
  assert.equal(JSON.stringify([v.link.paid, v.link.step]), '[true,2]');
  await b2.ticket(v.link, { message: 'done' });
  await b2.end();
  await assert.rejects(second.resume(b1.grantId), (e) => e.code === 'EEDGE_GONE');
});

test('L7: no Edge on this key - request() rejects EEDGE_UNSUPPORTED', async () => {
  const edge = edgeOver(fakeKey({ silent: true }));
  const c = client.createEdgeClient({ edge, channel: { send: () => assert.fail('sent') }, signer: AGENT });
  await assert.rejects(c.request({ reason: 'r', scopes: [{ op: 'sign', slot: 2, cap: 1 }], ttlMinutes: 10 }), (e) => e.code === 'EEDGE_UNSUPPORTED');
});

/* the signed body is unambiguous: every field changes it */
test('L7: the request body binds every field', async () => {
  const base = { agent: hex(AGENT.publicKey), nonce: '00'.repeat(16), reason: 'r', scopes: [{ op: 'sign', slot: 222, cap: 1, identity: AGENT_ID }], lifetime: 10 };
  const b0 = hex(request.body(base));
  for (const change of [{ reason: 'r2' }, { lifetime: 11 }, { nonce: '01'.repeat(16) }, { scopes: [{ ...base.scopes[0], cap: 2 }] }, { scopes: [{ ...base.scopes[0], identity: BRAD }] }, { scopes: [{ ...base.scopes[0], op: 'decrypt' }] }]) {
    assert.notEqual(hex(request.body({ ...base, ...change })), b0, JSON.stringify(change));
  }
  void codes; void chain;
});
