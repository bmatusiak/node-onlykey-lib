'use strict';

/*
 * The login plan (plugins/identity login(); Brad, 2026-10-29: "1 press = logs into our app", "keep it in the identity
 * plugin"; 2026-10-30: a manual login first, then the device's LOGIN CARD is certified, "then the card can be rebuilt with
 * cert and used for 1 press login after"). One Edge budget around the login pays exactly the requests on this device's
 * verified card - each announced with a TX start for its own bytes and receipted after; anything else the login asks is
 * an ordinary request; the uses it did not need are ended. No card, another device's card, a card the owner keys do not
 * verify, a key without the login budget or no Edge: the login runs manually, each request asking its own code.
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
const { codes, certify } = require('../edge/src');

const utf8 = (s) => new TextEncoder().encode(s);
const hex = (b) => Buffer.from(b).toString('hex');
const SIGN_LABEL = sha256(utf8(bucketIdentity.IDENTITY_LABEL));
const PUB = new Uint8Array(32).fill(5); /* the identity's public key (agent v1, slot 201) */
const BUCKET = bucketIdentity.bucketLabel(PUB);
const BUCKET_KEY = bucketIdentity.bucketKeyLabel(PUB);

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
    keySite: async () => ({ on: true, site: 'ok-edge.test' }),
    agent: {
      sign: (label, message) => send(MSG.OKSIGN, 201, new Uint8Array([...message, ...label])),
      publicKey: async () => PUB,
    },
  };
}
/* a fake Edge: its head moves one link per use and receipt; it records what it was asked; records verify unless .bad */
function fakeEdge({ refuse = null, device = 7, head = true } = {}) {
  let seq = 9;
  const calls = [];
  return {
    calls,
    async publicKey() { return { deviceId: new Uint8Array(16).fill(device) }; },
    async verifyRecord(rec) { return !rec.bad; },
    budgetAllowed: (rec, scopes) => certify.budgetAllowed(rec, scopes),
    async head() { return { seq, head: head ? new Uint8Array(32).fill(seq) : null }; },
    async grant(o) { if (refuse) throw Object.assign(new Error(refuse), { name: 'EdgeError', code: 0x03, status: 'scope-not-allowed' }); calls.push({ grant: o.scopes.map((s) => [s.op, s.slot, s.cap, s.derive || hex(s.label)]) }); seq += 1; return { grantId: seq + 1, seq, checkpoint: { seq } }; },
    async txStart(h, subject) { calls.push({ tx: hex(subject), at: h[0] }); },
    async receipt(ref, code, msg) { seq += 2; calls.push({ receipt: ref, msg: msg && hex(msg) }); },
    async revoke(id) { calls.push({ revoke: id }); },
  };
}
async function compose(okcrypto, edge) {
  let out;
  const app = { EventEmitter, services: edge ? { edge } : {} };
  identityPlugin({ app, host: { randomBytes }, okcrypto }, (err, provided) => { if (err) throw err; out = provided.identity; });
  await out.load();
  return out;
}
/* this device's card as the bucket keeps it (its certification is the fake's to judge) */
async function cardOf(identity) {
  return { v: 1, kind: 'login-card', thing: certify.loginCard(await identity.loginCard()), certification: {} };
}

test('the login card: rebuilt with no press - this device, this identity, the site, the bucket\'s two derives, the identity\'s signs', async () => {
  const identity = await compose(fakeOkcrypto(), fakeEdge());
  const card = await identity.loginCard();
  assert.deepEqual(card, {
    device: hex(new Uint8Array(16).fill(7)), identity: hex(PUB), site: 'ok-edge.test',
    derives: [BUCKET, BUCKET_KEY], signs: { slot: 201, label: hex(SIGN_LABEL), cap: 2 },
  });
  /* the canonical card is what the key certifies: the same bytes on every host */
  assert.deepEqual([...certify.subjectOf('login-card', card)], [...certify.subjectOf('login-card', { ...card, derives: [BUCKET_KEY, BUCKET] })]);
});

test('login with this device\'s card: one budget pays exactly the card\'s requests - each announced for its own bytes and receipted', async () => {
  const ok = fakeOkcrypto();
  const edge = fakeEdge();
  const identity = await compose(ok, edge);
  const card = await cardOf(identity);
  const r = await identity.login(async () => {
    await ok.deriveSecret(BUCKET);
    await ok.agent.sign(SIGN_LABEL, new Uint8Array(32).fill(7));
    await ok.deriveSecret('something the card does not name');
    await ok.deriveSecret(BUCKET_KEY);
    await ok.agent.sign(SIGN_LABEL, new Uint8Array(32).fill(8));
    return 'opened';
  }, { card, reason: 'log in: web app on box' });
  assert.equal(r.result, 'opened');
  assert.equal(r.paid, 4);
  /* the card's derives in its canonical (sorted) order */
  assert.deepEqual(edge.calls[0].grant, [[codes.OP.DERIVE, 128, 1, BUCKET_KEY], [codes.OP.DERIVE, 128, 1, BUCKET], [codes.OP.SIGN, 201, 2, hex(SIGN_LABEL)]]);
  const paidPayloads = ok.sent.filter((s) => s.paid).map((s) => s.payload);
  assert.deepEqual(edge.calls.filter((c) => c.tx).map((c) => c.tx), paidPayloads.map((p) => hex(sha256(Buffer.from(p, 'hex')))));
  assert.equal(edge.calls.filter((c) => c.receipt !== undefined).length, 4, 'a receipt for each paid use');
  assert.equal(ok.sent[2].paid, false, 'a derive the card does not name is an ordinary request');
  assert.ok(!edge.calls.some((c) => c.revoke), 'every use spent: nothing to end');
});

test('login: a use the login did not need is ended with it; the hook is gone after', async () => {
  const ok = fakeOkcrypto();
  const edge = fakeEdge();
  const identity = await compose(ok, edge);
  const r = await identity.login(async () => { await ok.deriveSecret(BUCKET); }, { card: await cardOf(identity) });
  assert.equal(r.paid, 1);
  assert.ok(edge.calls.some((c) => c.revoke === r.budget.grantId), 'the unspent uses were not ended');
  await ok.deriveSecret(BUCKET);
  assert.equal(ok.sent[ok.sent.length - 1].paid, false, 'the hook outlived the login');
});

test('the login is MANUAL - no budget, each request its own code - without a card, with another device\'s card or one that does not verify', async () => {
  for (const [what, setup] of [
    ['no card', async (identity) => null],
    ['another device\'s card', async (identity) => ({ ...(await cardOf(identity)), thing: { ...(await cardOf(identity)).thing, device: hex(new Uint8Array(16).fill(8)) } })],
    ['a card that does not verify', async (identity) => ({ ...(await cardOf(identity)), bad: true })],
  ]) {
    const ok = fakeOkcrypto();
    const edge = fakeEdge();
    const identity = await compose(ok, edge);
    const r = await identity.login(async () => { await ok.deriveSecret(BUCKET); return 1; }, { card: await setup(identity) });
    assert.deepEqual([r.result, r.budget, r.paid], [1, null, 0], what);
    assert.ok(r.manual, `${what}: no reason given`);
    assert.ok(!edge.calls.some((c) => c.grant), `${what}: a budget was asked`);
    assert.equal(ok.sent[0].paid, false, what);
  }
});

test('login: a key without the login budget, a host with no copy of the chain, or no Edge - manual', async () => {
  const ok = fakeOkcrypto();
  const refused = await compose(ok, fakeEdge({ refuse: 'A budget cannot pay for that operation or slot' }));
  const r = await refused.login(async () => { await ok.deriveSecret(BUCKET); return 1; }, { card: await cardOf(refused) });
  assert.deepEqual([r.result, r.budget, r.paid], [1, null, 0]);
  assert.equal(ok.sent[0].paid, false);
  const fresh = await compose(fakeOkcrypto(), fakeEdge({ head: false }));
  const f = await fresh.login(async () => 3, { card: await cardOf(fresh) });
  assert.deepEqual([f.result, f.budget], [3, null]);
  assert.match(f.manual, /no copy of the chain/);
  const plain = await compose(fakeOkcrypto(), null);
  const p = await plain.login(async () => 2, { card: { thing: {} } });
  assert.deepEqual([p.result, p.budget, p.paid], [2, null, 0]);
});

test('the budget gate: a budget only inside the card (certify.budgetAllowed)', () => {
  const card = { thing: certify.loginCard({ device: hex(new Uint8Array(16).fill(7)), identity: hex(PUB), site: 's', derives: [BUCKET, BUCKET_KEY], signs: { slot: 201, label: hex(SIGN_LABEL), cap: 2 } }) };
  assert.equal(certify.budgetAllowed(card, [{ op: 17, slot: 128, cap: 1, derive: BUCKET }, { op: 1, slot: 201, cap: 2, label: SIGN_LABEL }]).ok, true);
  assert.equal(certify.budgetAllowed(card, [{ op: 17, slot: 128, cap: 1, derive: 'okedge/bucket/v2/another' }]).ok, false, 'a derive not on the card');
  assert.equal(certify.budgetAllowed(card, [{ op: 1, slot: 201, cap: 3, label: SIGN_LABEL }]).ok, false, 'more signs than the card');
  assert.equal(certify.budgetAllowed(card, [{ op: 1, slot: 221, cap: 1, label: SIGN_LABEL }]).ok, false, 'an agent code is no login\'s');
});

test('login: the host is handed the opening before the login runs, and each paid use with the message its receipt hashes', async () => {
  const ok = fakeOkcrypto();
  const edge = fakeEdge();
  const identity = await compose(ok, edge);
  const seen = [];
  const r = await identity.login(async () => {
    seen.push('fn');
    await ok.deriveSecret(BUCKET);
  }, {
    card: await cardOf(identity), reason: 'log in: the web app', ttlMinutes: 3,
    onOpened: async (budget, o) => { seen.push({ opened: budget.grantId, reason: o.reason, scopes: o.scopes.length, lifetime: o.lifetime }); },
    onUse: async (u) => { seen.push(u); },
  });
  assert.deepEqual(seen[0], { opened: r.budget.grantId, reason: 'log in: the web app', scopes: 3, lifetime: 3 }, 'not handed the opening first');
  assert.equal(seen[1], 'fn');
  assert.equal(seen[2].message, 'log in: the web app: derive 1');
  const receipt = edge.calls.find((c) => c.receipt !== undefined);
  assert.equal(receipt.receipt, seen[2].seq, 'the use the note names is not the one receipted');
  assert.equal(receipt.msg, hex(sha256(Buffer.from(seen[2].message))), 'the message handed over is not the one the receipt hashes');
});

test('login: the opening handed to the host survives JSON - its grant hash is the one the key was asked for', async () => {
  const { grants } = require('../edge/src');
  const ok = fakeOkcrypto();
  const edge = fakeEdge();
  const identity = await compose(ok, edge);
  let kept = null;
  const asked = [];
  edge.grant = ((g) => async (o) => { asked.push(o.scopes); return g(o); })(edge.grant);
  await identity.login(async () => { await ok.agent.sign(SIGN_LABEL, new Uint8Array(32).fill(7)); }, {
    card: await cardOf(identity),
    onOpened: async (_b, o) => { kept = JSON.parse(JSON.stringify(o.scopes)); },
  });
  const z = new Uint8Array(32);
  const subject = (scopes) => hex(grants.grantSubject({ scopes, reasonHash: z, genesis: z, lifetime: 2 }));
  assert.equal(subject(kept), subject(asked[0]), 'the kept opening does not hash to the grant');
});
