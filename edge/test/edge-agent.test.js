'use strict';

/*
 * The agent service (edge/cli/agent.js; onlykey-edge APP.md,
 * decided 2026-10-03), on the fake Edge key, with the phone's side in-process.
 * The rules under test:
 * - each exec gets its own endpoint; the budget pays once, only for a sign on
 *   it, bound to a PINNED host and for the bound session;
 * - there is no shared endpoint, and nothing is turned into a press: a sign
 *   no budget pays is refused (budget or no go, CLI.md §3-4, 2026-10-06);
 * - a stale --head is refused before anything runs; the endpoint closes with
 *   the exec, or at its cap;
 * - the gpg shim's token is the exec's: a sign without it is refused.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const { approve, client, codes, chain } = require('../src');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');
const agentProto = require('../../src/protocol/agent');
const wire = require('../../cli/ssh-wire');
const bindLib = require('../../cli/ssh-session-bind');
const { createEdgeAgent } = require('../cli/agent');

const hex = (b) => Buffer.from(b).toString('hex');
const SSH_NAME = 'ssh://claude@test';
const SSH_IDENTITY = { ssh: { user: 'claude', host: 'test' } };
const GPG_IDENTITY = { gpg: 'Claude (agent) <claude@test>' };

/* a host key (github.com stands in) and an ssh connection's bind + userauth data */
function host() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
  const blob = Buffer.concat([wire.string(Buffer.from('ssh-ed25519')), wire.string(raw)]);
  return {
    blob,
    fingerprint: bindLib.fingerprint(blob),
    bind(sessionId, { forge = false } = {}) {
      const sig = crypto.sign(null, forge ? crypto.randomBytes(32) : sessionId, privateKey);
      return Buffer.concat([
        Buffer.of(wire.MSG.EXTENSION), wire.string(Buffer.from(bindLib.SESSION_BIND)),
        wire.string(blob), wire.string(sessionId),
        wire.string(Buffer.concat([wire.string(Buffer.from('ssh-ed25519')), wire.string(sig)])), Buffer.of(0),
      ]);
    },
  };
}
const userauth = (sessionId) => Buffer.concat([wire.string(sessionId), Buffer.of(50), wire.string(Buffer.from('git')), wire.string(Buffer.from('ssh-connection'))]);

/* talk to an agent endpoint like ssh does: one connection, messages in order, the replies */
async function sshClient(sockPath, messages) {
  const sock = net.connect(sockPath);
  await new Promise((resolve, reject) => { sock.once('connect', resolve); sock.once('error', reject); });
  const replies = [];
  const waiting = [];
  const feed = wire.createDeframer((m) => { const w = waiting.shift(); if (w) w(m); else replies.push(m); });
  sock.on('data', (c) => feed(c));
  const out = [];
  for (const m of messages) {
    const got = new Promise((resolve) => waiting.push(resolve));
    sock.write(wire.frame(m));
    out.push(await got);
  }
  sock.destroy();
  return out;
}
const signMsg = (keyBlob, data) => Buffer.concat([Buffer.of(wire.MSG.SIGN_REQUEST), wire.string(keyBlob), wire.string(data), wire.uint32(0)]);

/* the fake key plus derived keys: the device signs with a key per identity and links each sign on the fake key */
let goneAsked = 0;
async function setup({ cap = 4 } = {}) {
  const transport = fakeKey();
  const edge = edgeOver(transport);
  await edge.receipt(0, 0, new Uint8Array(32)); /* the fake starts owing #0 */
  const keys = new Map();
  const keyOf = (identity) => {
    const k = hex(agentProto.identityHash(identity));
    if (!keys.has(k)) keys.set(k, crypto.generateKeyPairSync('ed25519'));
    return keys.get(k);
  };
  const device = {
    async publicKey(identity) { return keyOf(identity).publicKey.export({ format: 'der', type: 'spki' }).subarray(12); },
    async sign(identity, message) {
      transport.use(new Uint8Array([...message, ...agentProto.identityHash(identity)]), { slot: 221 });
      return crypto.sign(null, Buffer.from(message), keyOf(identity).privateKey);
    },
  };
  const seen = new Set();
  /* the phone remembers what it opened, for which paired computer - a continue must match it (approve budgetOf) */
  const opened = new Map();
  const channel = {
    async send(msg) {
      const r = await approve.approveRequest(msg, {
        edge, from: 'pc-nitro16', seen, ask: async () => 'approve',
        verifyCopy: async () => ({ ok: true, head: (await edge.head()).head }), timeoutMs: 2000,
        budgetOf: (id) => opened.get(id) || null,
      });
      if (r.ok && r.budget) opened.set(r.budget.grantId, { from: 'pc-nitro16', scopes: msg.scopes });
      return r.dropped ? null : r;
    },
  };
  /* the agent's budget store (continue reads the budget it continues from here) */
  const saved = new Map();
  const store = { get: async (k) => saved.get(k) ?? null, set: async (k, v) => { saved.set(k, v); }, delete: async (k) => { saved.delete(k); } };
  const c = client.createEdgeClient({ edge, channel, store });
  const b = await c.request({ reason: 'work: push and sign', scopes: [{ op: 'sign', slot: 221, cap, identity: SSH_NAME }], ttlMinutes: 60 });
  const raw = await device.publicKey(SSH_IDENTITY);
  const h = host();
  const logs = [];
  const agent = createEdgeAgent({
    device, edge, pins: [h.fingerprint], log: (l) => logs.push(l),
    onGone: (old) => { goneAsked += 1; return c.continue(old.grantId, {}); },
    ssh: { identity: SSH_IDENTITY, name: SSH_NAME, comment: SSH_NAME, curve: 'ed25519', raw },
  });
  agent.setBudget(b);
  const keyBlob = wire.publicKeyBlob('ed25519', raw);
  const lastLink = async () => { const hd = await edge.head(); return chain.decodeLink((await edge.pickup(hd.seq, 1))[0].link); };
  return { transport, edge, agent, b, h, keyBlob, logs, lastLink };
}

test('session-bind: verified with the host\'s signature over the session id; a forged one is not; pins and the bound session decide', () => {
  const h = host();
  const sid = crypto.randomBytes(32);
  const parse = (msg) => { const r = new wire.Reader(msg); r.uint8(); r.string(); return bindLib.parseSessionBind(r); };
  const good = parse(h.bind(sid));
  assert.equal(good.verified, true);
  assert.equal(good.fingerprint, h.fingerprint);
  assert.equal(parse(h.bind(sid, { forge: true })).verified, false, 'a signature over something else does not verify');
  assert.deepEqual(bindLib.boundToPinned(good, userauth(sid), [h.fingerprint]), { ok: true, host: h.fingerprint });
  assert.match(bindLib.boundToPinned(good, userauth(sid), [host().fingerprint]).reason, /not pinned/);
  assert.match(bindLib.boundToPinned(good, userauth(crypto.randomBytes(32)), [h.fingerprint]).reason, /not for the bound session/);
  assert.match(bindLib.boundToPinned(null, userauth(sid), [h.fingerprint]).reason, /not bound/);
  assert.match(bindLib.boundToPinned({ ...good, forwarding: true }, userauth(sid), [h.fingerprint]).reason, /forwarded/);
});

test('GitHub\'s pinned host key fingerprints are the published ones (checked against ssh-keyscan and known_hosts, 2026-10-03)', () => {
  assert.deepEqual([...bindLib.GITHUB_FINGERPRINTS].sort(), [
    'SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU',
    'SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM',
    'SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s',
  ].sort());
});

test('an exec\'s endpoint: a sign bound to the pinned host is paid by the budget, once; the next sign on it is refused', async () => {
  const { agent, b, h, keyBlob, lastLink } = await setup();
  const ex = await agent.openExec({ head: b.head(), reason: 'push lib to origin/master' });
  const sid = crypto.randomBytes(32);
  const [bound, signed] = await sshClient(ex.sshPath, [h.bind(sid), signMsg(keyBlob, userauth(sid))]);
  assert.equal(bound[0], wire.MSG.SUCCESS);
  assert.equal(signed[0], wire.MSG.SIGN_RESPONSE);
  let f = await lastLink();
  assert.equal(JSON.stringify([f.decision, f.grantId]), JSON.stringify([codes.DECISION.SELF_PRESS, b.grantId]), 'paid by the budget');
  /* a second sign on the same exec: the use is spent - refused (budget or no go), no link */
  const sid2 = crypto.randomBytes(32);
  const [, second] = await sshClient(ex.sshPath, [h.bind(sid2), signMsg(keyBlob, userauth(sid2))]);
  assert.notEqual(second[0], wire.MSG.SIGN_RESPONSE, 'a second sign on a spent exec was signed');
  assert.equal((await lastLink()).seq, f.seq, 'one paid use per exec; the refusal wrote no link');
  const links = await ex.close();
  assert.equal(links.length, 1);
  assert.equal(links[0].paid, true);
});

test('THE FIX, budget or no go: there is no shared endpoint - another process can reach the agent\'s key only through an exec, and its one use pays (2026-10-06)', async () => {
  const { agent, b, h, keyBlob, lastLink } = await setup();
  assert.equal(agent.sharedHandler, undefined, 'the agent still has a shared endpoint');
  const before = (await lastLink()).seq;
  const ex = await agent.openExec({ head: b.head(), reason: 'push lib' });
  const sid = crypto.randomBytes(32);
  await sshClient(ex.sshPath, [h.bind(sid), signMsg(keyBlob, userauth(sid))]);
  const f = await lastLink();
  assert.equal(JSON.stringify([f.decision, f.seq > before]), JSON.stringify([codes.DECISION.SELF_PRESS, true]), 'the exec\'s use was not paid');
  await ex.close();
  assert.deepEqual((await agent.status()).keyOwed, [f.seq], 'the paid use owes its receipt');
});
test('the budget does not pay for a host that is not pinned, a forged bind, no bind, or a request for another session', async () => {
  const { agent, b, h, keyBlob, lastLink } = await setup();
  const cases = [
    ['a host not pinned', (sid) => [host().bind(sid), signMsg(keyBlob, userauth(sid))]],
    ['a forged bind', (sid) => [h.bind(sid, { forge: true }), signMsg(keyBlob, userauth(sid))]],
    ['no bind', (sid) => [signMsg(keyBlob, userauth(sid))]],
    ['another session', (sid) => [h.bind(sid), signMsg(keyBlob, userauth(crypto.randomBytes(32)))]],
  ];
  for (const [name, msgs] of cases) {
    const before = (await lastLink()).seq;
    const ex = await agent.openExec({ head: b.head(), reason: name });
    await sshClient(ex.sshPath, msgs(crypto.randomBytes(32)));
    assert.equal((await lastLink()).seq, before, `${name}: not paid by the budget - an ordinary press, no link`);
    await ex.close();
    /* R16 (2026-10-06): that press is not Edge - nothing owed, so the next exec runs */
    assert.deepEqual((await agent.status()).keyOwed, [], `${name}: nothing owed`);
  }
});

test('a stale --head is refused before anything opens; after a receipt the printed head works', async () => {
  const { agent, b, h, keyBlob } = await setup();
  await assert.rejects(agent.openExec({ head: '00'.repeat(32), reason: 'x' }), { code: 'EEDGE_STALE_HEAD' });
  const before = b.head();
  const ex = await agent.openExec({ head: before, reason: 'push' });
  const sid = crypto.randomBytes(32);
  await sshClient(ex.sshPath, [h.bind(sid), signMsg(keyBlob, userauth(sid))]);
  const [link] = await ex.close();
  /* the receipt is owed: refused for THAT first, before the command runs (daily-loop §3) */
  await assert.rejects(agent.openExec({ head: b.head(), reason: 'next' }), { code: 'EEDGE_RECEIPT_OWED' });
  const next = await agent.receipt(link.seq, { message: 'pushed' });
  /* receipted: the old head is stale now */
  await assert.rejects(agent.openExec({ head: before, reason: 'next' }), { code: 'EEDGE_STALE_HEAD' }, 'the head moved with the use');
  assert.equal(next, b.head());
  await (await agent.openExec({ head: next, reason: 'next push' })).close();
});

test('the endpoint closes with the exec, and at its cap', async () => {
  const { agent, b } = await setup();
  const ex = await agent.openExec({ head: b.head(), reason: 'x' });
  await ex.close();
  await assert.rejects(new Promise((resolve, reject) => { const s = net.connect(ex.sshPath); s.once('connect', () => { s.destroy(); resolve(); }); s.once('error', reject); }));
  const capped = await agent.openExec({ head: b.head(), reason: 'y', capMs: 50 });
  await new Promise((r) => setTimeout(r, 150));
  assert.equal((await agent.status()).execs, 0, 'closed at the cap');
  await assert.rejects(new Promise((resolve, reject) => { const s = net.connect(capped.sshPath); s.once('connect', () => { s.destroy(); resolve(); }); s.once('error', reject); }));
});

test('the gpg shim: with the exec\'s token the budget pays once; without it, refused', async () => {
  const { agent, b, lastLink } = await setup();
  /* the budget covers the ssh identity only, so for this test the shim signs under it too */
  const ex = await agent.openExec({ head: b.head(), reason: 'commit: R19 test' });
  const digest = crypto.randomBytes(32);
  await agent.shimSign(ex.token, SSH_IDENTITY, digest);
  const paid = await lastLink();
  assert.equal(paid.decision, codes.DECISION.SELF_PRESS, 'paid with the token');
  /* an ordinary press is not Edge (2026-10-06): no link */
  /* budget or no go (2026-10-06): spent, or a wrong token - refused, no link */
  await assert.rejects(agent.shimSign(ex.token, SSH_IDENTITY, crypto.randomBytes(32)), { code: 'EEDGE_BUDGET_ONLY' });
  assert.equal((await lastLink()).seq, paid.seq, 'spent: refused, no link');
  await assert.rejects(agent.shimSign('ff'.repeat(32), SSH_IDENTITY, crypto.randomBytes(32)), { code: 'EEDGE_BUDGET_ONLY' });
  assert.equal((await lastLink()).seq, paid.seq, 'a wrong token: refused, no link');
  await ex.close();
  void GPG_IDENTITY;
});

test('POSIX: the exec endpoint is owner-only (directory 0700, socket 0600)', { skip: process.platform === 'win32' && 'a named pipe: Windows\' default security, write for the creator only' }, async () => {
  const { agent, b } = await setup();
  const ex = await agent.openExec({ head: b.head(), reason: 'x' });
  assert.equal(fs.statSync(ex.sshPath).mode & 0o777, 0o600);
  assert.equal(fs.statSync(require('path').dirname(ex.sshPath)).mode & 0o777, 0o700);
  await ex.close();
});

test('after a key restart the budget is gone: the agent asks to continue ONCE, refuses that exec with the new head, and the next exec runs on it', async () => {
  const { agent, b, transport, h, keyBlob, lastLink } = await setup();
  goneAsked = 0;
  transport.restart();
  const err = await agent.openExec({ head: b.head(), reason: 'after a restart' }).catch((e) => e);
  assert.equal(err.code, 'EEDGE_CONTINUED', err.message);
  assert.equal(goneAsked, 1, 'one continue request');
  const nb = agent.budget();
  assert.notEqual(nb.grantId, b.grantId);
  assert.match(err.message, new RegExp(`head = ${nb.head()}`));
  /* the next exec, with the new head, runs - and pays */
  const ex = await agent.openExec({ head: nb.head(), reason: 'after the continue' });
  const sid = crypto.randomBytes(32);
  await sshClient(ex.sshPath, [h.bind(sid), signMsg(keyBlob, userauth(sid))]);
  assert.equal((await lastLink()).decision, codes.DECISION.SELF_PRESS);
  await ex.close();
  assert.equal(goneAsked, 1, 'still one: no retry');
});
