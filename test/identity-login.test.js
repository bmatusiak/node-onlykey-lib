'use strict';

/*
 * The login plan (plugins/identity login(); PROPOSAL-login-plan.md; Brad, 2026-10-29: "1 press = logs into our app",
 * "keep it in the identity plugin"): one Edge budget around the login pays exactly the requests the plan names - each
 * announced with a TX start for its own bytes and receipted after; anything else the login asks is an ordinary request;
 * the uses it did not need are ended; a key without the login budget, or no Edge at all, logs in as it always did.
 * The okcrypto here is a fake that runs its use hook the way okcrypto's asUse does.
 */
const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('events');
const { sha256 } = require('../src/vendor/exports/@noble/hashes/sha2.js');
const { randomBytes } = require('../src/vendor/exports/@noble/hashes/utils.js');
const identityPlugin = require('../plugins/identity');
const bucketIdentity = require('../bucket/src/bucket-identity');
const { MSG } = require('../src/protocol/msg');
const { codes } = require('../edge/src');

const utf8 = (s) => new TextEncoder().encode(s);
const hex = (b) => Buffer.from(b).toString('hex');
const SIGN_LABEL = sha256(utf8(bucketIdentity.IDENTITY_LABEL));

/* a fake okcrypto: each request goes through the hook as asUse runs it - announced, sent, receipted - and is recorded */
function fakeOkcrypto() {
  let hook = null;
  const sent = [];
  const send = async (msg, slot, payload) => {
    const use = hook ? hook(msg, slot, payload) : null;
    if (use) await use.before();
    sent.push({ msg, slot, payload: hex(payload), paid: !!use });
    if (use) await use.after();
    return new Uint8Array(64);
  };
  return {
    sent,
    setUseHook(fn) { const was = hook; hook = fn || null; return was; },
    deriveSecret: (label) => send(0xfc, 128, new Uint8Array([1, ...sha256(utf8(label))])),
    agent: { sign: (label, message) => send(MSG.OKSIGN, 201, new Uint8Array([...message, ...label])) },
  };
}
/* a fake Edge: its head moves one link per use and receipt; it records what it was asked */
function fakeEdge({ refuse = null } = {}) {
  let seq = 9;
  const calls = [];
  return {
    calls,
    async head() { return { seq, head: new Uint8Array(32).fill(seq) }; },
    async grant(o) { if (refuse) throw Object.assign(new Error(refuse), { name: 'EdgeError', code: 0x03, status: 'scope-not-allowed' }); calls.push({ grant: o.scopes.map((s) => [s.op, s.slot, s.cap, s.derive || hex(s.label)]) }); seq += 1; return { grantId: seq + 1, seq, checkpoint: { seq } }; },
    async txStart(head, subject) { calls.push({ tx: hex(subject), at: head[0] }); },
    async receipt(ref) { seq += 2; calls.push({ receipt: ref }); },
    async revoke(id) { calls.push({ revoke: id }); },
  };
}
function compose(okcrypto, edge) {
  let out;
  const app = { EventEmitter, services: edge ? { edge } : {} };
  identityPlugin({ app, host: { randomBytes }, okcrypto }, (err, provided) => { if (err) throw err; out = provided.identity; });
  return out;
}

test('login: one budget pays the plan - each named request announced for its own bytes and receipted; others are ordinary', async () => {
  const ok = fakeOkcrypto();
  const edge = fakeEdge();
  const identity = compose(ok, edge);
  const r = await identity.login(async () => {
    await ok.deriveSecret('okedge/bucket/v1/abc');
    await ok.agent.sign(SIGN_LABEL, new Uint8Array(32).fill(7));
    await ok.deriveSecret('something the plan does not name');
    return 'opened';
  }, { reason: 'log in: web app on box', derives: ['okedge/bucket/v1/abc'], signs: 1 });
  assert.equal(r.result, 'opened');
  assert.equal(r.paid, 2);
  assert.deepEqual(edge.calls[0].grant, [[codes.OP.DERIVE, 128, 1, 'okedge/bucket/v1/abc'], [codes.OP.SIGN, 201, 1, hex(SIGN_LABEL)]]);
  /* each TX start is SHA-256 of exactly the request it announces */
  const paidPayloads = ok.sent.filter((s) => s.paid).map((s) => s.payload);
  assert.deepEqual(edge.calls.filter((c) => c.tx).map((c) => c.tx), paidPayloads.map((p) => hex(sha256(Buffer.from(p, 'hex')))));
  assert.equal(edge.calls.filter((c) => c.receipt !== undefined).length, 2, 'a receipt for each paid use');
  assert.equal(ok.sent[2].paid, false, 'a derive the plan does not name is an ordinary request');
  assert.ok(!edge.calls.some((c) => c.revoke), 'every use spent: nothing to end');
});

test('login: a use the login did not need is ended with it; the hook is gone after', async () => {
  const ok = fakeOkcrypto();
  const edge = fakeEdge();
  const identity = compose(ok, edge);
  const r = await identity.login(async () => { await ok.deriveSecret('okedge/bucket/v1/abc'); }, { derives: ['okedge/bucket/v1/abc'], signs: 2 });
  assert.equal(r.paid, 1);
  assert.ok(edge.calls.some((c) => c.revoke === r.budget.grantId), 'the unspent signs were not ended');
  await ok.deriveSecret('okedge/bucket/v1/abc');
  assert.equal(ok.sent[ok.sent.length - 1].paid, false, 'the hook outlived the login');
});

test('login: a key without the login budget logs in as always; no Edge, no budget', async () => {
  const ok = fakeOkcrypto();
  const refused = compose(ok, fakeEdge({ refuse: 'A budget cannot pay for that operation or slot' }));
  const r = await refused.login(async () => { await ok.deriveSecret('x'); return 1; }, { derives: ['x'] });
  assert.deepEqual([r.result, r.budget, r.paid], [1, null, 0]);
  assert.equal(ok.sent[0].paid, false);
  const plain = compose(fakeOkcrypto(), null);
  assert.deepEqual(await plain.login(async () => 2, { derives: ['x'] }), { result: 2, budget: null, paid: 0 });
});
