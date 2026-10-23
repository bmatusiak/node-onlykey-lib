'use strict';

/*
 * B4 (2026-10-23): a hard key on USB has no phone - THIS COMPUTER is the Edge host
 * (edge/cli/local-host.js). On the fake key, with the real Edge plugin and the real client:
 * the local host answers what the phone answers - the identity record, the budget sheet
 * (a y/N here, then the key's press), R27 on this computer's own copy of the chain, the
 * openings kept for the next budget's check - and "no phone here" at once for the rest.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { client, identity } = require('../src');
const { createLocalHost, identityKv } = require('../cli/local-host');
const copy = require('../cli/copy');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

const AGENT_ID = 'ssh://agent@nitro16';
const ARMORED = '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEZ...\n-----END PGP PUBLIC KEY BLOCK-----\n';
const record = () => ({
  ssh: AGENT_ID,
  gpgUid: 'Agent (nitro16) <agent@example.com>',
  committer: { name: 'Agent (nitro16)', email: 'agent@example.com' },
  expires: 31536000,
  cert: { armored: ARMORED, fingerprint: '7fbf276c85dd192794b46cc4f75a92949d5603ca', created: 1791085347, expires: 31536000, signPublic: 'AB'.repeat(32) },
});

/* a fresh Edge home in a temp folder (its own bucket), a fake key with one link, and a scripted person */
async function setup({ answers = [] } = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-local-'));
  const transport = fakeKey();
  const edge = edgeOver(transport);
  await edge.receipt(0, 0, new Uint8Array(32));
  const asked = [];
  const said = [];
  const host = createLocalHost({
    edge, home, say: (l) => said.push(l),
    confirm: async (q) => { asked.push(q); return answers.length ? answers.shift() : false; },
  });
  const store = { m: new Map(), async get(k) { return this.m.get(k) || null; }, async set(k, v) { this.m.set(k, v); } };
  return { home, edge, host, asked, said, c: client.createEdgeClient({ edge, channel: host, store }) };
}

test('the host is here: it says so, and answers a note at once', async () => {
  const { host, said } = await setup();
  assert.equal(host.local, true);
  const t0 = Date.now();
  const a = await host.send({ type: 'EDGE_NOTE', v: 1, nonce: '00'.repeat(16), seq: 3, reason: 'push ok-edge' });
  assert.deepEqual(a, { ok: true });
  assert.ok(Date.now() - t0 < 500, 'no 4 s wait for a phone');
  assert.ok(said.some((l) => l.includes('push ok-edge')), 'the intent is shown here');
});

test('identity: none at first; kept on y, not kept on n; GET reads back what was kept', async () => {
  const { host, home, asked } = await setup({ answers: [false, true] });
  assert.deepEqual(await host.send(identity.buildGet()), { ok: true, record: null });
  const no = await host.send(identity.buildSet({ record: record() }));
  assert.equal(no.refusal, 'declined');
  assert.equal(identityKv(home).getItem('record'), null, 'a No keeps nothing');
  assert.deepEqual(await host.send(identity.buildSet({ record: record() })), { ok: true });
  assert.equal(asked.length, 2, 'asked each time');
  const got = await host.send(identity.buildGet());
  assert.ok(got.ok && identity.same(got.record, record()), 'the record kept is the one read back');
});

test('budget: shown here, a y, the press - opened, and its opening kept with this computer\'s copy', async () => {
  const { c, edge, home, asked, said } = await setup({ answers: [true] });
  const b = await c.request({ reason: 'release 0.0.7', scopes: [{ op: 'sign', slot: 222, cap: 2, identity: AGENT_ID }], ttlMinutes: 30 });
  assert.ok(b.grantId > 0 && b.uses === 2, 'the budget opened');
  assert.equal(asked.length, 1, 'one y/N');
  assert.ok(said.some((l) => l.includes('release 0.0.7')), 'the reason shown');
  assert.ok(said.some((l) => /PRESS the key/.test(l)), 'the press asked for');
  const { deviceId } = await edge.publicKey();
  const kept = copy.load(home, deviceId).openings;
  assert.deepEqual(kept.map((o) => o.grantId), [b.grantId], 'the opening kept with the copy');
});

test('budget: a second one after the first - R27 checks the copy WITH the first opening, and passes', async () => {
  const { c, asked } = await setup({ answers: [true, true] });
  const first = await c.request({ reason: 'one', scopes: [{ op: 'sign', slot: 222, cap: 1, identity: AGENT_ID }], ttlMinutes: 30 });
  await first.end();
  const second = await c.request({ reason: 'two', scopes: [{ op: 'sign', slot: 222, cap: 1, identity: AGENT_ID }], ttlMinutes: 30 });
  assert.ok(second.grantId > first.grantId);
  assert.equal(asked.length, 2);
});

test('budget: a No opens nothing - declined, and the key never asked for a press', async () => {
  const { c, said } = await setup({ answers: [false] });
  await assert.rejects(c.request({ reason: 'no thanks', scopes: [{ op: 'sign', slot: 222, cap: 1, identity: AGENT_ID }], ttlMinutes: 30 }), /declined/);
  assert.ok(!said.some((l) => /PRESS the key/.test(l)), 'no press asked');
});

test('what only a phone has is refused at once: a sync, a ping', async () => {
  const { host } = await setup();
  for (const type of ['EDGE_SYNC_HAVE', 'ping']) {
    const a = await host.send({ type, v: 1, nonce: '11'.repeat(16) });
    assert.equal(a.ok, false);
    assert.match(a.detail, /no phone on this link/);
  }
});
