/*
 * The CLI's Key Chain list in the bucket of the key's BUCKET IDENTITY (ok-edge plan S2/S3; Brad, 2026-10-24: "cli and
 * desktop decrypt once, share same bucket stored in filesystem"; 2026-10-25: the "" agent key is the key's identity,
 * "nothing to do with edge"): a derive is recorded into the bucket this computer keeps for that identity - the file
 * the desktop app reads too; the first one kept takes the list from before; a bucket kept under the key's Edge
 * identity id moves to the bucket identity id once. Every test runs in a scratch root.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { ed25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');
const home = require('../../bucket/cli/home');
const bucketLib = require('../../bucket/src/bucket');
const bid = require('../../bucket/src/bucket-identity');
const rec = require('../cli/record');
const list = require('../src/list');

function scratch() {
  delete process.env.ONLYKEY_KEYCHAIN;
  home.setRoot(fs.mkdtempSync(path.join(os.tmpdir(), 'okkc-identity-')));
  rec.setFile(null);
}
test.afterEach(() => { home.setRoot(null); rec.setFile(null); });

/* a key's agent: one key per (backup, identity hash) - so "" gives the backup's bucket identity */
const hashOfIdentity = (identity) => (identity instanceof Uint8Array ? identity : sha256(new TextEncoder().encode(JSON.stringify(identity))));
const agentKey = (seed, identity) => ed25519.getPublicKey(sha256(new Uint8Array([...new TextEncoder().encode(seed), ...hashOfIdentity(identity)])));
const fakeStart = (seed, edge) => async () => ({
  edge,
  services: { okcrypto: { agent: { publicKey: async (identity) => agentKey(seed, identity) } } },
});
const idOf = (seed) => bid.identityIdOf(agentKey(seed, sha256(new Uint8Array(0))));
const derive = async (app) => app.services.okcrypto.agent.publicKey({ ssh: { user: 'me', host: 'host' } }, { keyType: 1 });
const listOf = (id, store = 'keychain') => {
  const text = home.kv(home.identityAt(id, store === 'keychain-test' ? 'test' : 'live', store)).getItem('list');
  return text ? list.parse(text) : [];
};
const entry = (label, fill) => list.createEntry({ kind: 'derived', scheme: 'ssh', label, type: 'ed25519', publicKey: new Uint8Array(32).fill(fill), firstSeen: 'x', lastSeen: 'x', tools: [] });

test('a derive is recorded in the kept bucket of the key\'s bucket identity - any key, no Edge needed; the old list moves in', async () => {
  scratch();
  rec.save([entry('old@host', 1)]);
  const app = await rec.recordingStart(fakeStart('backup-1', undefined), { tool: 'test' })({});
  await derive(app);
  const ID = idOf('backup-1');
  assert.deepEqual(home.keptIdentities('live'), [ID]);
  assert.deepEqual(listOf(ID).map((e) => e.label).sort(), ['me@host', 'old@host']);
  assert.equal(home.kv(home.at('keychain')).getItem('list'), null);
  assert.ok(!listOf(ID).some((e) => e.scheme === 'hash'), 'reading the bucket identity is not recorded as a derive');
  rec.setFile(null);
  assert.equal(rec.load().length, 2, 'no key now: the one bucket identity kept');
});

test('two bucket identities kept: a list with no key asks which; --identity takes an id\'s first characters', async () => {
  scratch();
  for (const seed of ['backup-1', 'backup-2']) {
    await derive(await rec.recordingStart(fakeStart(seed, undefined), { tool: 'test' })({}));
    rec.setFile(null);
  }
  assert.throws(() => rec.load(), /more than one identity/);
  rec.setIdentity(idOf('backup-1').slice(0, 12));
  assert.equal(rec.load().length, 1);
});

test('the identity plugin\'s one read names the list; reading the identity label itself is not a Key Chain entry', async () => {
  scratch();
  let loads = 0;
  const start = async () => {
    const app = await fakeStart('backup-1', undefined)();
    app.services.identity = { load: async () => { loads += 1; return { id: idOf('backup-1') }; } };
    return app;
  };
  const app = await rec.recordingStart(start, { tool: 'test' })({});
  /* the identity plugin reads the "" label through the same okcrypto: never listed */
  await app.services.okcrypto.agent.publicKey(sha256(new Uint8Array(0)), { keyType: 1 });
  await derive(app);
  await derive(app);
  assert.equal(loads, 1, 'the held read, once');
  assert.deepEqual(listOf(idOf('backup-1')).map((e) => e.label), ['me@host']);
});

test('the testnet\'s list is its own', async () => {
  scratch();
  rec.setFile(rec.testFile());
  await derive(await rec.recordingStart(fakeStart('backup-1', undefined), { tool: 'test' })({}));
  assert.deepEqual(home.keptIdentities('test'), [idOf('backup-1')]);
  assert.deepEqual(home.keptIdentities('live'), []);
});

test('learnIdentityOf: an edge command (no learning at its first record) picks the key\'s identity when two are kept - the read itself records nothing', async () => {
  scratch();
  for (const seed of ['backup-1', 'other']) home.keepIdentityBucket(idOf(seed), 'live', bucketLib.create({ owner: idOf(seed) }));
  const seen = [];
  const recordFn = (f) => { seen.push(f.label); return rec.record(f); };
  const app = await rec.recordingStart(fakeStart('backup-1', undefined), { tool: 'test', recordFn, learnIdentity: false })({});
  assert.strictEqual(await rec.learnIdentityOf(app), idOf('backup-1'));
  assert.deepStrictEqual(seen, [], 'reading the bucket identity is not a derive to record');
  await derive(app);
  assert.deepStrictEqual(listOf(idOf('backup-1')).map((e) => e.label), ['me@host']);
  assert.deepStrictEqual(listOf(idOf('other')), []);
});
