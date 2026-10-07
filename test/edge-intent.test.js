'use strict';
/*
 * R13b (Brad, 2026-10-06): the use says what it's for BEFORE it happens - the
 * intent is welded into the link (bytes 47-62); the ticket is only the result.
 */
const test = require('node:test');
const assert = require('node:assert');
const { approve, client, chain, grants, request, note, codes } = require('../src/edge');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

const AGENT = request.signerFromSecret(new Uint8Array(32).fill(41));
const registered = [Buffer.from(AGENT.publicKey).toString('hex')];
const ID = 'ssh://agent@nitro16';

async function setup(opts = {}) {
  const transport = fakeKey(opts);
  const edge = edgeOver(transport);
  await edge.ticket(0, 0, new Uint8Array(32));
  const seen = new Set();
  const channel = {
    async send(msg) {
      if (msg.type === note.TYPE) return { ok: true };
      const r = await approve.approveRequest(msg, { edge, registered, seen, ask: async () => 'approve',
        verifyCopy: async () => ({ ok: true, head: (await edge.head()).head }), timeoutMs: 2000 });
      return r.dropped ? null : r;
    },
  };
  const c = client.createEdgeClient({ edge, channel, signer: AGENT });
  const sign = (x) => transport.use(x, { slot: 222 });
  return { transport, edge, c, sign };
}
const linkAt = async (edge, seq) => chain.decodeLink((await edge.pickup(seq, 1))[0].link);

test('intentOf: the first 16 bytes of SHA256("OKEDGE-INTENT-v1" || UTF-8 text) - a fixed vector', () => {
  assert.equal(Buffer.from(grants.intentOf('sign release ok-rn 0.0.6')).toString('hex'), '5913a75b2e6b1bf32d74d007e4d382a1');
  const crypto = require('crypto');
  const want = crypto.createHash('sha256').update(Buffer.concat([Buffer.from('OKEDGE-INTENT-v1'), Buffer.from('push über café', 'utf8')])).digest().subarray(0, 16);
  assert.deepEqual(Buffer.from(grants.intentOf('push über café')), want, 'the text as UTF-8');
});

test('a paid use carries its intent in bytes 47-62, version 1 in 63; HEAD says the key takes intents', async () => {
  const { edge, c, sign } = await setup();
  assert.equal((await edge.head()).canIntent, true);
  const b = await c.request({ reason: 'push', scopes: [{ op: 'sign', slot: 222, cap: 2, identity: ID }], ttlMinutes: 10 });
  const u = await b.use(Uint8Array.from([1]), sign, { reason: 'git push origin master' });
  assert.equal(u.link.paid, true);
  const f = await linkAt(edge, u.link.seq);
  assert.equal(f.decision, codes.DECISION.SELF_PRESS);
  assert.deepEqual(Buffer.from(f.intent), Buffer.from(grants.intentOf('git push origin master')));
  assert.equal(f.version, 1);
  assert.equal(f.reservedZero, true);
});

test('budget or no go (Brad, 2026-10-06, R13b): an ARM with an intent and nothing able to pay is refused - no sign, no link', async () => {
  const { edge, c, sign } = await setup();
  const b = await c.request({ reason: 'push', scopes: [{ op: 'sign', slot: 222, cap: 2, identity: ID }], ttlMinutes: 10 });
  await edge.hold(b.grantId);
  const before = (await edge.head()).seq;
  let signed = false;
  await assert.rejects(b.use(Uint8Array.from([2]), async (x) => { signed = true; return sign(x); }, { reason: 'pressed, but it says why' }), { code: 'EEDGE_ARM' });
  assert.equal(signed, false, 'nothing reached the sign');
  assert.equal((await edge.head()).seq, before, 'no link');
  const h = await edge.head();
  await assert.rejects(edge.arm(h.head, grants.requestSubject(Uint8Array.from([9])), { intent: grants.intentOf('x') }), (e) => e.status === 'nothing-to-arm');
});

test('an ARM is refused while a ticket is owed - intent or not (R13a, R13b)', async () => {
  const { edge, c, sign } = await setup();
  const b = await c.request({ reason: 'push', scopes: [{ op: 'sign', slot: 222, cap: 3, identity: ID }], ttlMinutes: 10 });
  await b.use(Uint8Array.from([3]), sign, { reason: 'one' });
  const h = await edge.head();
  const subject = grants.requestSubject(Uint8Array.from([4]));
  await assert.rejects(edge.arm(h.head, subject, { intent: grants.intentOf('two, without the ticket') }), (e) => e.status === 'ticket-owed');
  await assert.rejects(edge.arm(h.head, subject), (e) => e.status === 'ticket-owed');
});

test('a key that predates R13b: no capability, the v1 ARM, no intent in the link', async () => {
  const { edge, c, sign } = await setup({ intentCap: false });
  assert.equal((await edge.head()).canIntent, false);
  const b = await c.request({ reason: 'push', scopes: [{ op: 'sign', slot: 222, cap: 2, identity: ID }], ttlMinutes: 10 });
  const u = await b.use(Uint8Array.from([5]), sign, { reason: 'git push' });
  assert.equal(u.link.paid, true, 'the v1 token still pays');
  assert.equal((await linkAt(edge, u.link.seq)).intent, null);
});
