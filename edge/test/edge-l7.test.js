'use strict';

/*
 * L7 - Edge from an app (edge/src/request.js, approve.js, client.js), on the
 * fake key, with the APP's side (what ok-rn runs) in-process as the channel.
 * APP.md: one EDGE_REQUEST from a paired computer (no agent key since
 * 2026-10-08 - Brad: "so the claude key thing is overkill"; the pairing is the gate);
 * the app drops malformed or replayed ones, checks caps (<= 300) and lifetime,
 * shows text and names, makes labels and the reason
 * hash itself, verifies its copy, grants on the key, answers with the budget
 * or a typed refusal. The agent checks the opening against the key itself.
 */
const test = require('node:test');
const assert = require('node:assert');
const { request, approve, client, codes, chain, grants } = require('../src');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

const BRAD = 'ssh://bmatusiak@localhost';
const AGENT_ID = 'ssh://agent@nitro16';

/* the phone: approveRequest over the key's edge service, the person answering `answer` */
function phone(edge, { answer = 'approve', from = 'pc-nitro16', views = [], grantAs = null } = {}) {
  const seen = new Set();
  return {
    seen,
    views,
    async send(msg) {
      const sent = grantAs ? { ...msg, scopes: msg.scopes.map((s) => ({ ...s, identity: grantAs })) } : msg;
      const r = await approve.approveRequest(sent, {
        edge, from, seen,
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
  await edge.receipt(0, 0, new Uint8Array(32));
  return { transport, edge };
}

test('a receipt the key took but whose answer was lost: the next receipt clears it from the key word, and work goes on', async () => {
  const { transport, edge } = await readyKey();
  const c = client.createEdgeClient({ edge, channel: phone(edge) });
  const budget = await c.request({ reason: 'push', scopes: [{ op: 'sign', slot: 222, cap: 3, identity: AGENT_ID }], ttlMinutes: 60 });
  const sign = (bytes) => transport.use(bytes, { slot: 222 });
  const one = await budget.use(Uint8Array.from([1]), sign);
  /* the key links the receipt; the client never hears back (the A13, 2026-10-05) */
  await edge.receipt(one.link.seq, 0, new Uint8Array(32));
  assert.deepEqual(budget.pending(), [one.link.seq], 'the client still counts it owed');
  const r = await budget.receipt(one.link, { message: 'pushed' });
  assert.equal(r.lostAnswer, true);
  assert.deepEqual(budget.pending(), []);
  const two = await budget.use(Uint8Array.from([2]), sign);
  assert.equal(two.link.paid, true, 'the next use is paid - the head the client kept is from the key');
  /* a seq the client never counted owed is still refused */
  await assert.rejects(budget.receipt({ seq: 9999 }, { message: 'x' }));
});

test('L7: request -> use -> receipt -> use -> receipt -> end, each use paid by the budget and checked', async () => {
  const { transport, edge } = await readyKey();
  const views = [];
  const c = client.createEdgeClient({ edge, channel: phone(edge, { views }) });
  const budget = await c.request({ reason: 'push bm-ok/ok-rn', scopes: [{ op: 'sign', slot: 222, cap: 2, identity: AGENT_ID }], ttlMinutes: 60 });
  assert.equal(views.length, 1);
  assert.equal(views[0].reason, 'push bm-ok/ok-rn', 'the sheet shows the TEXT');
  assert.equal(views[0].scopes[0].identity, AGENT_ID, 'the sheet shows the NAME');
  assert.equal(budget.uses, 2);

  const sign = (bytes) => transport.use(bytes, { slot: 222 });
  const one = await budget.use(Uint8Array.from([1, 2, 3]), sign);
  assert.equal(JSON.stringify([one.link.paid, one.link.step]), '[true,1]', 'the budget paid for use 1');
  assert.deepEqual(budget.pending(), [one.link.seq]);
  await assert.rejects(budget.use(Uint8Array.from([4]), sign), (e) => e.code === 'EEDGE_TX' && e.reason === 'receipt-owed', 'use() before the receipt');
  const first = await budget.receipt(one.link, { code: 'OK', message: 'pushed' });
  assert.equal(first.ended, undefined, 'a receipt with uses left must not end the budget');
  const two = await budget.use(Uint8Array.from([4, 5]), sign);
  assert.equal(JSON.stringify([two.link.paid, two.link.step]), '[true,2]');
  /* R16 (spec 2026-10-04): the last use's receipt ends the used-up budget - a grant-end link, the slot freed */
  const last = await budget.receipt(two.link, { message: 'pushed again' });
  assert.equal(last.ended, true, 'the last receipt did not end the used-up budget');
  assert.deepEqual((await edge.head()).live, [], 'the used-up budget still holds a live slot');
  let ran = false;
  await assert.rejects(budget.use(Uint8Array.from([6]), async (b) => { ran = true; return sign(b); }), (e) => e.code === 'EEDGE_TX' && e.reason === 'ended');
  assert.equal(ran, false, 'an ended budget never runs the operation');
  await budget.end(); /* again: harmless */
});

/* no "yours" mark since 2026-10-08 (Brad: "the agent can look at my keychain ... it can ask me to use it") */
test('L7: a request naming the person\'s own identity shows like any other - the identity on the sheet, no warning', async () => {
  const { edge } = await readyKey();
  const views = [];
  const c = client.createEdgeClient({ edge, channel: phone(edge, { views, answer: 'decline' }) });
  await assert.rejects(c.request({ reason: 'sign as Brad', scopes: [{ op: 'sign', slot: 201, cap: 1, identity: BRAD }], ttlMinutes: 10 }),
    (e) => e.code === 'EEDGE_REFUSED' && e.refusal === 'declined');
  assert.equal(views[0].scopes[0].identity, BRAD, 'the sheet names the identity asked for');
  assert.equal('ownWarning' in views[0], false);
  assert.equal('own' in views[0].scopes[0], false);
});

/* who asks is the pairing since 2026-10-08 (Brad: "lets cut it out"): no signature to check, so the app drops only malformed and replayed */
test('L7: the app drops malformed and replayed requests - nothing is answered', async () => {
  const { edge } = await readyKey();
  const seen = new Set();
  const opts = {
    edge, from: 'pc-nitro16', seen, ask: async () => assert.fail('asked the person'),
    verifyCopy: async () => ({ ok: true, head: (await edge.head()).head }),
  };
  const scopes = [{ op: 'sign', slot: 222, cap: 1, identity: AGENT_ID }];
  const good = await request.build({ reason: 'r', scopes, lifetime: 10 });
  assert.equal('agent' in good || 'signature' in good, false, 'a request carries no agent key and no signature');
  assert.deepEqual(await approve.approveRequest({ ...good, nonce: 'zz' }, opts), { dropped: 'malformed' });
  assert.deepEqual(await approve.approveRequest({ ...good, lifetime: '10' }, opts), { dropped: 'malformed' });
  assert.deepEqual(await approve.approveRequest({ ...good, type: 'EDGE_NOTE' }, opts), { dropped: 'malformed' });
  assert.deepEqual(await approve.approveRequest({ ...good, continue: -1 }, opts), { dropped: 'malformed' });
  const once = await approve.approveRequest(good, { ...opts, ask: async () => 'decline' });
  assert.equal(once.refusal, 'declined');
  assert.deepEqual(await approve.approveRequest(good, opts), { dropped: 'replayed' });
  assert.deepEqual(await approve.approveRequest({ ...good, nonce: good.nonce.toUpperCase() }, opts), { dropped: 'replayed' }, 'a nonce is the same in either case');
});

test('L7: caps over 300, a bad lifetime or a derived code without an identity are refused - by the client before sending, by the app if sent', async () => {
  const { edge } = await readyKey();
  const views = [];
  const c = client.createEdgeClient({ edge, channel: phone(edge, { views }) });
  await assert.rejects(c.request({ reason: 'r', scopes: [{ op: 'sign', slot: 2, cap: 301 }], ttlMinutes: 10 }), (e) => e.code === 'EEDGE_INVALID' && /300/.test(e.message));
  await assert.rejects(c.request({ reason: 'r', scopes: [{ op: 'sign', slot: 2, cap: 1 }], ttlMinutes: 0 }), (e) => e.code === 'EEDGE_INVALID');
  await assert.rejects(c.request({ reason: 'r', scopes: [{ op: 'sign', slot: 222, cap: 1 }], ttlMinutes: 10 }), (e) => e.code === 'EEDGE_INVALID' && /R11a/.test(e.message));
  assert.equal(views.length, 0, 'nothing reached the person');
  const tooBig = await request.build({ reason: 'r', scopes: [{ op: 'sign', slot: 2, cap: 200 }, { op: 'sign', slot: 101, cap: 101 }], lifetime: 10 });
  const r = await approve.approveRequest(tooBig, {
    edge, seen: new Set(), ask: async () => assert.fail('asked the person'),
    verifyCopy: async () => ({ ok: true, head: (await edge.head()).head }),
  });
  assert.equal(r.refusal, 'invalid');
});

test('L7: typed refusals - a receipt owed, an unverified copy', async () => {
  const transport = fakeKey(); /* #0 still owes its receipt */
  const edge = edgeOver(transport);
  const scopes = [{ op: 'sign', slot: 2, cap: 1 }];
  const owed = client.createEdgeClient({ edge, channel: phone(edge) });
  await assert.rejects(owed.request({ reason: 'r', scopes, ttlMinutes: 10 }), (e) => e.refusal === 'receipt_owed');
  await edge.receipt(0, 0, new Uint8Array(32));
  const unverified = {
    send: async (msg) => approve.approveRequest(msg, {
      edge, seen: new Set(), ask: async () => 'approve', verifyCopy: async () => ({ ok: false }),
    }),
  };
  await assert.rejects(client.createEdgeClient({ edge, channel: unverified }).request({ reason: 'r', scopes, ttlMinutes: 10 }),
    (e) => e.refusal === 'copy_unverified');
  assert.deepEqual((await edge.head()).live, [], 'no budget opened');
});

test('L7: an answer that is not the budget the agent asked for is caught - the opening is checked against the key', async () => {
  const { edge } = await readyKey();
  /* a phone that grants for ANOTHER identity than the one requested (and so signs a different subject) */
  const lying = phone(edge, { grantAs: BRAD });
  lying.send = (orig => async (msg) => {
    const r = await approve.approveRequest(await request.build({ reason: msg.reason, scopes: msg.scopes.map((s) => ({ ...s, identity: BRAD })), lifetime: msg.lifetime }), {
      edge, seen: new Set(), ask: async () => 'approve',
      verifyCopy: async () => ({ ok: true, head: (await edge.head()).head }),
    });
    return r;
  })(lying.send);
  const c = client.createEdgeClient({ edge, channel: lying });
  await assert.rejects(c.request({ reason: 'agent push', scopes: [{ op: 'sign', slot: 222, cap: 1, identity: AGENT_ID }], ttlMinutes: 10 }),
    (e) => e.code === 'EEDGE_OPENING');
});

test('L7 + R13a: another request slipped in between TX start and sign is REFUSED by the key - no link, the TX start used up, counted (2026-10-06)', async () => {
  const { transport, edge } = await readyKey();
  const c = client.createEdgeClient({ edge, channel: phone(edge) });
  const budget = await c.request({ reason: 'r', scopes: [{ op: 'sign', slot: 222, cap: 2, identity: AGENT_ID }], ttlMinutes: 10 });
  const before = await edge.head();
  await assert.rejects(budget.use(Uint8Array.from([1]), async () => transport.use(Uint8Array.from([9, 9]), { slot: 222 })), (e) => e.kind === 'edge' && /EDGE:1C/.test(e.message));
  const after = await edge.head();
  assert.equal(after.seq, before.seq, 'no link');
  assert.equal(after.refusedTx, before.refusedTx + 1, 'HEAD byte 60 counts the refused sign');
  assert.equal(transport.started(), false, 'the TX start is used up - TX start again');
  /* the budget still pays a use that matches its TX start */
  const u = await budget.use(Uint8Array.from([2]), (x) => transport.use(x, { slot: 222 }));
  assert.equal(u.link.paid, true);
});

/*
 * Brad, 2026-10-08: refusing this sign was a misreading of "budget or no go" (which only
 * means nothing goes on the chain without a budget behind it). With the budget held, no
 * budget pays: it is an ordinary press - no record, not a refusal - and the TX start is spent.
 */
test('announce a sign, hold the budget, then sign - an ordinary press: no record, not counted, the announcement used up', async () => {
  const { transport, edge } = await readyKey();
  const c = client.createEdgeClient({ edge, channel: phone(edge) });
  const budget = await c.request({ reason: 'r', scopes: [{ op: 'sign', slot: 222, cap: 2, identity: AGENT_ID }], ttlMinutes: 10 });
  const bytes = Uint8Array.from([7, 7]);
  const before = await edge.head();
  await edge.txStart(before.head, grants.requestSubject(bytes));
  await edge.hold(budget.grantId);
  const held = await edge.head();
  assert.deepEqual(transport.use(bytes, { slot: 222 }), { seq: null, paid: false });
  const after = await edge.head();
  assert.equal(after.seq, held.seq, 'no record');
  assert.equal(after.refusedTx, held.refusedTx, 'not a refusal');
  assert.equal(transport.started(), false, 'the announcement is used up');
});

test('L7: a budget outlives one process - resume() from the store, with what is owed', async () => {
  const { transport, edge } = await readyKey();
  const mem = new Map();
  const store = { get: async (k) => mem.get(k) || null, set: async (k, v) => { mem.set(k, v); } };
  const first = client.createEdgeClient({ edge, channel: phone(edge), store });
  const b1 = await first.request({ reason: 'r', scopes: [{ op: 'sign', slot: 222, cap: 2, identity: AGENT_ID }], ttlMinutes: 10 });
  const u = await b1.use(Uint8Array.from([1]), (b) => transport.use(b, { slot: 222 }));
  const second = client.createEdgeClient({ edge, channel: null, store });
  const b2 = await second.resume(b1.grantId);
  assert.deepEqual(b2.pending(), [u.link.seq], 'the debt came along');
  await b2.receipt(u.link, { message: 'from the second process' });
  const v = await b2.use(Uint8Array.from([2]), (b) => transport.use(b, { slot: 222 }));
  assert.equal(JSON.stringify([v.link.paid, v.link.step]), '[true,2]');
  await b2.receipt(v.link, { message: 'done' });
  await b2.end();
  await assert.rejects(second.resume(b1.grantId), (e) => e.code === 'EEDGE_GONE');
});

test('L7: no Edge on this key - request() rejects EEDGE_UNSUPPORTED', async () => {
  const edge = edgeOver(fakeKey({ silent: true }));
  const c = client.createEdgeClient({ edge, channel: { send: () => assert.fail('sent') } });
  await assert.rejects(c.request({ reason: 'r', scopes: [{ op: 'sign', slot: 2, cap: 1 }], ttlMinutes: 10 }), (e) => e.code === 'EEDGE_UNSUPPORTED');
});

/*
 * R16, the client's side (spec APP.md, Budgets, 2026-10-06): it
 * receipts first, then ends - and an owed receipt is always fileable, even after
 * the budget ended (a lock, its lifetime), with no budget and no settle.
 */
test('end is refused while a use owes its receipt', async () => {
  const { transport, edge } = await readyKey();
  const c = client.createEdgeClient({ edge, channel: phone(edge) });
  const budget = await c.request({ reason: 'push', scopes: [{ op: 'sign', slot: 222, cap: 3, identity: AGENT_ID }], ttlMinutes: 60 });
  const one = await budget.use(Uint8Array.from([1]), (bytes) => transport.use(bytes, { slot: 222 }));
  await assert.rejects(budget.end(), { code: 'EEDGE_OWED' });
  await budget.receipt(one.link, { message: 'pushed' });
  await budget.end();
  assert.equal((await edge.head()).live.includes(budget.grantId), false, 'ended once the receipt was in');
});

test('an owed receipt is filed after the budget ended - no budget, no settle', async () => {
  const { transport, edge } = await readyKey();
  const c = client.createEdgeClient({ edge, channel: phone(edge) });
  const budget = await c.request({ reason: 'push', scopes: [{ op: 'sign', slot: 222, cap: 3, identity: AGENT_ID }], ttlMinutes: 60 });
  const one = await budget.use(Uint8Array.from([1]), (bytes) => transport.use(bytes, { slot: 222 }));
  transport.restart(); /* a lock or reboot: live budgets are gone, the debt is not */
  assert.equal((await edge.head()).live.includes(budget.grantId), false);
  assert.equal((await edge.head()).owed, 1, 'the key still owes it');
  await c.receiptOwed(one.link.seq, { message: 'pushed before the lock' });
  assert.equal((await edge.head()).owed, 0, 'filed without the budget');
});

/*
 * SETTLE ENDS THE BUDGET (Brad, 2026-10-10: "its more secure to just end the budget instead of
 * allowing it to be continue to be used; this will force a new budget to be created by the agent").
 * Before, the debt was cleared and the same budget went on paying - a press that let the agent
 * past its receipt. Now the settle ends every live budget first, each with its grant-end link.
 */
/*
 * A FULFILLED BUDGET COMPLETES ITSELF (Brad, 2026-10-10: "budgets should auto complete once
 * fufilled"): the receipt for its last open use makes the KEY write the grant-end link - no
 * revoke from the host - and the link says it completed. A revoke says revoked.
 */
test('the key ends a budget itself once every use is made and receipted (END.COMPLETED); a revoke says REVOKED', async () => {
  const { transport, edge } = await readyKey();
  let revokes = 0;
  const watched = { ...edge, revoke: async (...a) => { revokes += 1; return edge.revoke(...a); } };
  const c = client.createEdgeClient({ edge: watched, channel: phone(edge) });
  const budget = await c.request({ reason: 'one push', scopes: [{ op: 'sign', slot: 222, cap: 1, identity: AGENT_ID }], ttlMinutes: 60 });
  const one = await budget.use(Uint8Array.from([1]), (bytes) => transport.use(bytes, { slot: 222 }));
  assert.equal((await edge.head()).live.includes(budget.grantId), true, 'spent but not yet receipted: still live');
  const r = await budget.receipt(one.link, { message: 'pushed' });
  assert.equal(r.ended, true);
  const hd = await edge.head();
  assert.equal(hd.live.includes(budget.grantId), false, 'the fulfilled budget is over');
  const end = chain.decodeLink((await edge.pickup(hd.seq, 1))[0].link);
  assert.deepEqual([end.op, end.grantId, end.decision], [codes.OP.GRANT_END, budget.grantId, codes.END.COMPLETED], 'the key ended it, as completed');
  assert.equal(revokes, 0, 'the host sent no revoke');
  assert.deepEqual(Buffer.from(r.head), Buffer.from(hd.head), 'the receipt answer is the head after the end link');

  const b2 = await c.request({ reason: 'stopped early', scopes: [{ op: 'sign', slot: 222, cap: 2, identity: AGENT_ID }], ttlMinutes: 60 });
  await b2.end();
  const hd2 = await edge.head();
  const end2 = chain.decodeLink((await edge.pickup(hd2.seq, 1))[0].link);
  assert.deepEqual([end2.op, end2.grantId, end2.decision], [codes.OP.GRANT_END, b2.grantId, codes.END.REVOKED]);
});

test('a settle ends every live budget first (grant-end links), then the receipt - more uses need a new budget', async () => {
  const { transport, edge } = await readyKey();
  const c = client.createEdgeClient({ edge, channel: phone(edge) });
  const budget = await c.request({ reason: 'sign the release', scopes: [{ op: 'sign', slot: 222, cap: 3, identity: AGENT_ID }], ttlMinutes: 60 });
  await budget.use(Uint8Array.from([1]), (bytes) => transport.use(bytes, { slot: 222 }));
  assert.equal((await edge.head()).owed, 1, 'the use owes - the signer died before its receipt');
  await edge.settle();
  const hd = await edge.head();
  assert.equal(hd.owed, 0, 'the debt is cleared');
  assert.equal(hd.live.includes(budget.grantId), false, 'and the budget is over');
  const [end, settled] = (await edge.pickup(hd.seq - 1, 2)).map((r) => chain.decodeLink(r.link));
  assert.deepEqual([end.op, end.grantId, end.decision], [codes.OP.GRANT_END, budget.grantId, codes.END.SETTLED], 'its grant-end link first, ended as settled');
  assert.deepEqual([settled.op, settled.decision], [codes.OP.RECEIPT, 0x8f], 'then the settle, a needs-review receipt');
  await assert.rejects(budget.use(Uint8Array.from([2]), (bytes) => transport.use(bytes, { slot: 222 })), 'the old budget pays for nothing');
});

test('a receipt whose answer never came is NEVER sent twice: the key is asked instead (Brad, 2026-10-06)', async () => {
  const { transport, edge } = await readyKey();
  const sign = (bytes) => transport.use(bytes, { slot: 222 });
  const lost = () => Object.assign(new Error('Edge: no answer to request 32 within 6000 ms; nothing arrived'), { code: 'ETIMEDOUT' });
  /* the key files it, the answer is lost */
  let sent = 0;
  const filed = { ...edge, receipt: async (...a) => { sent += 1; await edge.receipt(...a); throw lost(); } };
  const c = client.createEdgeClient({ edge: filed, channel: phone(edge) });
  const budget = await c.request({ reason: 'push', scopes: [{ op: 'sign', slot: 222, cap: 3, identity: AGENT_ID }], ttlMinutes: 60 });
  const one = await budget.use(Uint8Array.from([1]), sign);
  const r = await budget.receipt(one.link, { message: 'pushed' });
  assert.equal(r.lostAnswer, true, 'the key\'s newest link is this receipt');
  assert.equal(sent, 1, 'the RECEIPT went out once');
  assert.deepEqual(budget.pending(), []);
  /* the request never reached the key: the error stands - and still went out once */
  let sent2 = 0;
  const never = { ...edge, receipt: async () => { sent2 += 1; throw lost(); } };
  const c2 = client.createEdgeClient({ edge: never, channel: phone(edge) });
  const b2 = await c2.request({ reason: 'push', scopes: [{ op: 'sign', slot: 222, cap: 3, identity: AGENT_ID }], ttlMinutes: 60 });
  const two = await b2.use(Uint8Array.from([2]), sign);
  await assert.rejects(b2.receipt(two.link, { message: 'pushed' }), /no answer/);
  assert.equal(sent2, 1, 'no resend');
});

/*
 * A RECEIPT KEEPS ITS CODE (Brad, 2026-10-07: a failed push's receipt showed OK in the
 * budget history). Receipts were filed with the display record, which the plugin wrote
 * as 0 - OK - for every code. Now the byte: TARGET_UNREACHABLE is 0x21 on the key.
 */
test('a receipt keeps its code on the key: TARGET_UNREACHABLE is 0x21, not OK; an unknown code is refused', async () => {
  const { transport, edge } = await readyKey();
  const c = client.createEdgeClient({ edge, channel: phone(edge) });
  const budget = await c.request({ reason: 'push', scopes: [{ op: 'sign', slot: 222, cap: 3, identity: AGENT_ID }], ttlMinutes: 60 });
  const one = await budget.use(Uint8Array.from([1]), (bytes) => transport.use(bytes, { slot: 222 }));
  await budget.receipt(one.link, { code: 'TARGET_UNREACHABLE', message: 'the push did not reach' });
  const h = await edge.head();
  const [t] = await edge.pickup(h.seq, 1);
  assert.equal(chain.decodeLink(t.link).code, 0x21);
  assert.equal(codes.receiptByte('OK'), 0);
  assert.equal(codes.receiptByte('0x21'), 0x21);
  assert.throws(() => codes.receiptByte('NOPE'), RangeError);
  await assert.rejects(edge.receipt(one.link.seq, codes.receiptCode(0x21), new Uint8Array(32)), TypeError); /* the plugin never writes a code object */
});
