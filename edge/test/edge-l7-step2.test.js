'use strict';

/*
 * L7 step 2 - EDGE_REQUEST over the Bluetooth vendor channel (edge/src/wire.js),
 * continue, and registering the agent's key (mcp-service.md 4.7a, 2026-10-03).
 * On the fake key, with the APP's side (what ok-rn runs) in-process.
 */
const test = require('node:test');
const assert = require('node:assert');
const { request, approve, client, grants, wire, codes, chain } = require('../src');
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

const AGENT = request.signerFromSecret(new Uint8Array(32).fill(21));
const OTHER = request.signerFromSecret(new Uint8Array(32).fill(23));
const BRAD = 'ssh://bmatusiak@localhost';
const AGENT_ID = 'ssh://agent@nitro16';
const hex = (b) => Buffer.from(b).toString('hex');
const enc = (s) => new TextEncoder().encode(s);

/* the phone: registration and requests, keeping its own record of the budgets it opened (for continue) */
function phone(edge, { answer = 'approve', registered = [], views = [], grants: granted = [] } = {}) {
  const seen = new Set();
  const budgets = new Map();
  const asked = { register: [] };
  return {
    registered, views, budgets, asked,
    async send(msg) {
      if (msg.type === request.REGISTER_TYPE) {
        const r = await approve.approveRegister(msg, { edge, registered, seen, ask: async (v) => { asked.register.push(v); return answer; }, timeoutMs: 2000 });
        if (r.dropped) return null;
        if (r.ok && !r.already) registered.push(r.agent);
        return r;
      }
      const spy = { ...edge, grant: async (args) => { granted.push(args); return edge.grant(args); } };
      const r = await approve.approveRequest(msg, {
        edge: spy, registered, seen, ownIdentities: [BRAD],
        ask: async (view) => { views.push(view); return answer; },
        verifyCopy: async () => ({ ok: true, head: (await edge.head()).head }),
        budgetOf: (id) => budgets.get(id) || null,
        timeoutMs: 2000,
      });
      if (r.dropped) return null;
      if (r.ok) budgets.set(r.budget.grantId, { agent: msg.agent, scopes: msg.scopes });
      return r;
    },
  };
}

async function readyKey() {
  const transport = fakeKey();
  const edge = edgeOver(transport);
  await edge.receipt(0, 0, new Uint8Array(32));
  return { transport, edge };
}

function memoryStore() {
  const m = new Map();
  return { get: async (k) => m.get(k) || null, set: async (k, v) => { m.set(k, v); } };
}

test('wire: a message cut into 64-byte OKEDGE_REQUEST reports and put back together', () => {
  const msg = { type: 'EDGE_REQUEST', reason: 'push bm-ok/ok-rn - ünïcödé ✓ '.repeat(8), scopes: [{ op: 'sign', slot: 222, cap: 3 }] };
  const frames = wire.encode(wire.KIND.REQUEST, msg);
  assert.ok(frames.length > 1, 'more than one piece');
  for (const f of frames) {
    assert.equal(f.length, 64);
    assert.deepEqual([...f.slice(0, 5)], [0xff, 0xff, 0xff, 0xff, 0xf7]);
    assert.ok(wire.isEdgeRequestFrame(f));
  }
  const asm = wire.createAssembler();
  let got = null;
  for (const f of frames) got = asm.push(f) || got;
  assert.deepEqual(got, { kind: wire.KIND.REQUEST, message: msg });
  /* a piece out of order drops what was gathered */
  const asm2 = wire.createAssembler();
  assert.equal(asm2.push(frames[0]), null);
  assert.deepEqual(asm2.push(frames[2]), { error: 'out-of-order' });
  /* any other vendor message is not one */
  const okedge = new Uint8Array(64); okedge.set([0xff, 0xff, 0xff, 0xff, 0xf8]);
  assert.equal(wire.isEdgeRequestFrame(okedge), false);
  assert.equal(wire.createAssembler().push(okedge), null);
});

test('wire: the channel sends the request and waits for the app\'s answer; no answer = null', async () => {
  const listeners = new Set();
  const written = [];
  const answerWith = (msg) => { for (const f of wire.encode(wire.KIND.ANSWER, msg)) for (const l of listeners) l({ iface: 2, data: f }); };
  const asm = wire.createAssembler();
  let reply = { ok: false, refusal: 'declined' };
  const transport = {
    on(ev, l) { listeners.add(l); return () => listeners.delete(l); },
    async write(iface, f) {
      written.push(f);
      const got = asm.push(f);
      if (got && got.kind === wire.KIND.REQUEST && reply) setTimeout(() => answerWith(reply), 5);
    },
  };
  const ch = wire.createWireChannel(transport, { timeoutMs: 200 });
  assert.deepEqual(await ch.send({ type: 'EDGE_REQUEST', reason: 'r' }), { ok: false, refusal: 'declined' });
  reply = null;
  assert.equal(await ch.send({ type: 'EDGE_REQUEST', reason: 'r' }), null);
  assert.equal(listeners.size, 0, 'unsubscribed after each');
});

test('register: an unregistered agent is answered nothing; registered once with the person\'s approval, it may ask', async () => {
  const { edge } = await readyKey();
  const p = phone(edge);
  const c = client.createEdgeClient({ edge, channel: p, signer: AGENT });
  const ask = { reason: 'push', scopes: [{ op: 'sign', slot: 222, cap: 1, identity: AGENT_ID }], ttlMinutes: 10 };
  await assert.rejects(c.request(ask), { code: 'EEDGE_NO_ANSWER' });
  assert.equal(p.views.length, 0, 'the sheet never saw it');
  assert.deepEqual(await c.register('agent service on NITRO16'), { already: false });
  assert.deepEqual(p.asked.register, [{ agent: hex(AGENT.publicKey), name: 'agent service on NITRO16', fingerprint: request.fingerprint(hex(AGENT.publicKey)) }]);
  /* registered with a press: the key linked it, this agent's key as the subject */
  const h = await edge.head();
  const [l] = await edge.pickup(h.seq, 1);
  const f = chain.decodeLink(l.link);
  assert.equal(f.op, codes.OP.AGENT_ADD);
  assert.equal(f.flags & codes.FLAG.PRESS_OBSERVED, codes.FLAG.PRESS_OBSERVED, 'the press flag');
  assert.equal(hex(f.subject), hex(grants.agentSubject(AGENT.publicKey)));
  assert.deepEqual(await c.register('agent service on NITRO16'), { already: true }, 'a second time: already registered, no sheet');
  assert.equal(p.asked.register.length, 1);
  const b = await c.request(ask);
  assert.equal(b.uses, 1);
});

test('register: declined, a bad signature and a replay', async () => {
  const seen = new Set();
  const edge = { agentAdd: async () => assert.fail('pressed for a registration that was not approved') };
  const msg = await request.buildRegister({ signer: AGENT, name: 'a' });
  assert.deepEqual(await approve.approveRegister({ ...msg, name: 'b' }, { edge, seen, ask: async () => 'approve' }), { dropped: 'bad-signature' });
  assert.deepEqual(await approve.approveRegister({ ...msg, agent: hex(OTHER.publicKey) }, { edge, seen, ask: async () => 'approve' }), { dropped: 'bad-signature' }, 'a key it cannot sign for');
  assert.deepEqual(await approve.approveRegister(msg, { edge, seen, ask: async () => 'decline' }), { ok: false, refusal: 'declined' });
  assert.deepEqual(await approve.approveRegister(msg, { edge, seen, ask: async () => 'approve' }), { dropped: 'replayed' });
});

test('the lifetime is required - a request without one is not read', async () => {
  const { edge } = await readyKey();
  const msg = await request.build({ signer: AGENT, reason: 'r', scopes: [{ op: 'sign', slot: 1, cap: 1 }], lifetime: 10 });
  const { lifetime, ...without } = msg;
  assert.equal(lifetime, 10);
  const r = await approve.approveRequest(without, {
    edge, registered: [hex(AGENT.publicKey)], seen: new Set(), ask: async () => assert.fail('asked the person'), verifyCopy: async () => assert.fail('read the copy'),
  });
  assert.deepEqual(r, { dropped: 'malformed' });
});

test('continue: "continues <budget>" - the same scopes, new uses and lifetime, opened with a press like a new budget', async () => {
  const { edge } = await readyKey();
  const p = phone(edge, { registered: [hex(AGENT.publicKey)] });
  const store = memoryStore();
  const c = client.createEdgeClient({ edge, channel: p, signer: AGENT, store });
  const first = await c.request({ reason: 'release 0.0.6', scopes: [{ op: 'sign', slot: 222, cap: 2, identity: AGENT_ID }, { op: 'sign', slot: 2, cap: 1 }], ttlMinutes: 30 });
  await first.end();
  const next = await c.continue(first.grantId, { caps: [5, 1], ttlMinutes: 120 });
  assert.notEqual(next.grantId, first.grantId, 'a new budget');
  assert.equal(next.uses, 6);
  const v = p.views[1];
  assert.equal(v.continues, first.grantId, 'the sheet says what it continues');
  assert.equal(v.lifetime, 120);
  assert.deepEqual(v.scopes.map((s) => [s.op, s.slot, s.identity, s.cap]), [['sign', 222, AGENT_ID, 5], ['sign', 2, undefined, 1]]);
  assert.equal(p.views[0].continues, null, 'a new budget continues nothing');
});

test('continue: the app refuses one that changes the scopes, names a budget it never opened, or another agent\'s', async () => {
  const { edge } = await readyKey();
  const p = phone(edge, { registered: [hex(AGENT.publicKey), hex(OTHER.publicKey)] });
  const c = client.createEdgeClient({ edge, channel: p, signer: AGENT, store: memoryStore() });
  const first = await c.request({ reason: 'r', scopes: [{ op: 'sign', slot: 222, cap: 1, identity: AGENT_ID }], ttlMinutes: 10 });
  const send = async (signer, scopes, cont) => p.send(await request.build({ signer, reason: 'r', scopes, lifetime: 10, continueOf: cont }));
  const brad = await send(AGENT, [{ op: 'sign', slot: 222, cap: 1, identity: BRAD }], first.grantId);
  assert.equal(brad.refusal, 'invalid');
  assert.match(brad.detail, /keeps the scopes/);
  const wider = await send(AGENT, [{ op: 'sign', slot: 222, cap: 1, identity: AGENT_ID }, { op: 'decrypt', slot: 1, cap: 1 }], first.grantId);
  assert.match(wider.detail, /keeps the scopes/);
  assert.match((await send(AGENT, [{ op: 'sign', slot: 222, cap: 1, identity: AGENT_ID }], 0xdead)).detail, /no budget/);
  assert.match((await send(OTHER, [{ op: 'sign', slot: 222, cap: 1, identity: AGENT_ID }], first.grantId)).detail, /another agent/);
  /* the continue is signed: changing what it continues breaks the signature */
  const good = await request.build({ signer: AGENT, reason: 'r', scopes: [{ op: 'sign', slot: 222, cap: 1, identity: AGENT_ID }], lifetime: 10, continueOf: first.grantId });
  assert.equal(await p.send({ ...good, continue: first.grantId + 1 }), null);
});

test('the app makes the labels and the reason hash itself - hashes carried by the request are never used', async () => {
  const { edge } = await readyKey();
  const granted = [];
  const p = phone(edge, { registered: [hex(AGENT.publicKey)], grants: granted });
  const reason = 'push bm-ok/ok-rn';
  const scopes = [{ op: 'sign', slot: 222, cap: 2, identity: AGENT_ID }];
  const msg = await request.build({ signer: AGENT, reason, scopes, lifetime: 60 });
  /* forged hashes riding along: a reason hash, labels, a label per scope (BRAD's) - outside the signed body, so the signature still holds */
  const FORGED_REASON = hex(sha256(enc('sign everything')));
  const FORGED_LABEL = hex(grants.identityLabel(BRAD));
  const forged = { ...msg, reasonHash: FORGED_REASON, labels: [FORGED_LABEL], scopes: msg.scopes.map((s) => ({ ...s, label: FORGED_LABEL })) };
  assert.equal(request.verify(forged, { registered: p.registered, seen: new Set() }).ok, true, 'the extras do not break the signature');
  const r = await p.send(forged);
  assert.equal(r.ok, true);

  /* what the app handed the key: the reason hash of the TEXT, and scopes carrying the NAME only */
  const [args] = granted;
  assert.equal(hex(args.reasonHash), hex(sha256(enc(reason))));
  assert.deepEqual(args.scopes, [{ op: codes.OP.SIGN, slot: 222, cap: 2, identity: AGENT_ID }], 'no label, no hash - the name only');
  assert.equal('reasonHash' in forged && hex(args.reasonHash) !== FORGED_REASON, true);

  /* what the KEY recorded: the opening's subject matches the hashes made from the text and the name ... */
  const [opened] = await edge.pickup(r.budget.seq, 1);
  const [prev] = await edge.pickup(r.budget.seq - 1, 1);
  const { publicKey, deviceId } = await edge.publicKey();
  const check = (scopesForCheck, reasonHash) => grants.verifyBudgetOpening({
    deviceId, publicKey, link: opened.link, prevHead: prev.head,
    head: Buffer.from(r.budget.checkpoint.head, 'hex'), signature: Buffer.from(r.budget.checkpoint.signature, 'hex'),
    scopes: scopesForCheck, reasonHash, genesis: Buffer.from(r.budget.genesis, 'hex'), uses: 2, lifetime: 60,
  });
  assert.equal(check(request.grantScopes(msg), request.reasonHash(reason)).ok, true);
  /* ... and NOT the forged ones */
  assert.equal(check(request.grantScopes(msg), sha256(enc('sign everything'))).reason, 'subject-mismatch', 'not the forged reason hash');
  assert.equal(check([{ ...request.grantScopes(msg)[0], identity: BRAD }], request.reasonHash(reason)).reason, 'subject-mismatch', 'not the forged label');
});

test('a sheet that could not offer Approve (the copy did not verify) answers copy_unverified - nothing reaches the key', async () => {
  const { edge } = await readyKey();
  const msg = await request.build({ signer: AGENT, reason: 'r', scopes: [{ op: 'sign', slot: 1, cap: 1 }], lifetime: 10 });
  const r = await approve.approveRequest(msg, {
    edge: { ...edge, grant: async () => assert.fail('sent to the key') }, registered: [hex(AGENT.publicKey)], seen: new Set(),
    ask: async () => 'copy_unverified', verifyCopy: async () => assert.fail('the copy is checked again only after a Yes'),
  });
  assert.deepEqual(r, { ok: false, refusal: 'copy_unverified' });
});

test('the key giving up on the press ("Timeout occured ...") is a timeout - registration ends in "timeout", not a hunt for a link never written', async () => {
  /* a key that answers AGENT_ADD with the firmware's timeout sentence, as when nobody presses for 25 s */
  const listeners = new Set();
  const transport = {
    name: 'timeout-key', async open() {}, async close() {}, isOpen: () => true, request: async () => { throw new Error('unused'); },
    on(ev, l) { if (ev === 'report') listeners.add(l); return () => listeners.delete(l); },
    async write() {
      const r = new Uint8Array(64);
      r.set(enc('Timeout occured while waiting for confirmation on OnlyKey'));
      setTimeout(() => { for (const l of listeners) l({ iface: 2, data: r }); }, 5);
    },
  };
  let edge = null;
  require('../plugin')({ transport }, (err, s) => { if (err) throw err; edge = s.edge; });
  await assert.rejects(edge.agentAdd(new Uint8Array(32).fill(7), { timeoutMs: 2000 }), { code: 'ETIMEDOUT' });
  const msg = await request.buildRegister({ signer: AGENT, name: 'agent' });
  const r = await approve.approveRegister(msg, { edge, seen: new Set(), ask: async () => 'approve', timeoutMs: 2000 });
  assert.equal(r.refusal, 'timeout');
});

test('continue: a continue of a LIVE budget is refused still_live; client.continue ends the old one first, and only the new budget pays', async () => {
  const { transport, edge } = await readyKey();
  const p = phone(edge, { registered: [hex(AGENT.publicKey)] });
  const c = client.createEdgeClient({ edge, channel: p, signer: AGENT, store: memoryStore() });
  const scopes = [{ op: 'sign', slot: 222, cap: 2, identity: AGENT_ID }];
  const first = await c.request({ reason: 'release', scopes, ttlMinutes: 30 });
  /* sent by hand while it is live: refused, before the sheet */
  const views = p.views.length;
  const live = await p.send(await request.build({ signer: AGENT, reason: 'release', scopes, lifetime: 30, continueOf: first.grantId }));
  assert.equal(live.refusal, 'still_live');
  assert.equal(p.views.length, views, 'a still-live continue never reached the sheet');
  /* the client's continue: revoke (no press), then the request */
  const next = await c.continue(first.grantId, { ttlMinutes: 60 });
  assert.deepEqual((await edge.head()).live, [next.grantId], 'only the continuation is live');
  const used = await next.use(Uint8Array.from([9, 9]), (b) => transport.use(b, { slot: 222 }));
  assert.equal(used.link.paid, true);
  assert.equal(used.link.paidBy, next.grantId, 'the new budget paid, not the old one');
});

test('the sheet is told what already covers the request: "this agent already has N uses left on <identity>"', async () => {
  const { edge } = await readyKey();
  const covered = [{ identity: AGENT_ID, slot: 222, usesLeft: 3, endsAt: 1700000000000, grantId: 7, sameAgent: true }];
  const views = [];
  const msg = await request.build({ signer: AGENT, reason: 'r', scopes: [{ op: 'sign', slot: 222, cap: 1, identity: AGENT_ID }], lifetime: 10 });
  await approve.approveRequest(msg, {
    edge, registered: [hex(AGENT.publicKey)], seen: new Set(), coverOf: async (m) => (m === msg ? covered : []),
    ask: async (v) => { views.push(v); return 'decline'; }, verifyCopy: async () => assert.fail('declined'),
  });
  assert.deepEqual(views[0].covered, covered);
});

test('R15c: an agent counts only with its pressed AGENT_ADD link in the VERIFIED copy', () => {
  const key = hex(AGENT.publicKey);
  const row = (o) => ({ verified: true, fields: { seq: 90, op: codes.OP.AGENT_ADD, flags: codes.FLAG.PRESS_OBSERVED, subject: grants.agentSubject(AGENT.publicKey), ...o } });
  assert.equal(approve.agentInCopy([row({})], key), 90, 'its link, pressed and verified');
  assert.equal(approve.agentInCopy([], key), null, 'no link: planted in storage, or kept from before the press');
  assert.equal(approve.agentInCopy([{ ...row({}), verified: false }], key), null, 'a link the copy does not verify does not count');
  assert.equal(approve.agentInCopy([row({ flags: 0 })], key), null, 'no press flag');
  assert.equal(approve.agentInCopy([row({ subject: grants.agentSubject(OTHER.publicKey) })], key), null, 'another agent\'s link');
  assert.equal(approve.agentInCopy([row({ op: codes.OP.LOSS })], key), null, 'another kind of link');
});
