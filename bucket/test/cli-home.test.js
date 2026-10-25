/*
 * The CLI's bucket (bucket/cli/home.js): the one-time move of the files the CLI kept before
 * (Brad, 2026-10-21: "one-time move"), where each Edge home's state lives, one writer at a time,
 * and a cleared store that stays cleared through a merge. Every test runs in a scratch root.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const bucket = require('../src/bucket');
const home = require('../cli/home');

function scratch() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'okbucket-home-'));
  home.setRoot(dir);
  return dir;
}
const write = (f, v) => { fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, typeof v === 'string' ? v : JSON.stringify(v)); };

test.afterEach(() => home.setRoot(null));

test('the one-time move: each old file into its store, renamed .moved, never read again', () => {
  const dir = scratch();
  write(path.join(dir, 'keychain.json'), '{"format":"live list"}');
  write(path.join(dir, 'keychain-test.json'), '{"format":"test list"}');
  write(path.join(dir, 'edge', 'budgets.json'), { v: 1, 'okedge.budget.3': { grantId: 3 } });
  write(path.join(dir, 'edge', 'pointers.json'), { v: 1, 'okedge.pointer.budget.aa': '21' });
  write(path.join(dir, 'edge', `copy-${'a'.repeat(16)}.json`), { v: 1, deviceId: 'a'.repeat(32), links: [] });
  write(path.join(dir, 'edge-test', `copy-${'b'.repeat(16)}.json`), { v: 1, deviceId: 'b'.repeat(32), links: [] });
  /* machine files and the dead agent.json stay as they are */
  write(path.join(dir, 'edge', 'control.key'), 'c0ffee');
  write(path.join(dir, 'edge', 'agent.json'), { v: 1 });
  write(path.join(dir, 'bt-pairing.json'), {});

  const b = home.read();
  const get = (store, key) => bucket.kv(b, store).getItem(key);
  assert.equal(get('keychain', 'list'), '{"format":"live list"}');
  assert.equal(get('keychain-test', 'list'), '{"format":"test list"}');
  assert.deepEqual(JSON.parse(get('edge.budgets', 'okedge.budget.3')), { grantId: 3 });
  assert.equal(get('edge.pointers', 'okedge.pointer.budget.aa'), '21');
  assert.equal(JSON.parse(get('edge.copies', 'a'.repeat(16))).deviceId, 'a'.repeat(32));
  assert.equal(JSON.parse(get('edge-test.copies', 'b'.repeat(16))).deviceId, 'b'.repeat(32));

  for (const f of ['keychain.json', 'keychain-test.json', 'edge/budgets.json', 'edge/pointers.json', `edge/copy-${'a'.repeat(16)}.json`]) {
    assert.ok(!fs.existsSync(path.join(dir, f)), `${f} is still there`);
    assert.ok(fs.existsSync(path.join(dir, `${f}.moved`)), `${f}.moved is missing`);
  }
  for (const f of ['edge/control.key', 'edge/agent.json', 'bt-pairing.json']) assert.ok(fs.existsSync(path.join(dir, f)), `${f} was moved`);

  /* never read again: a file put back is not taken a second time */
  write(path.join(dir, 'keychain.json'), '{"format":"put back"}');
  home.setRoot(dir);
  assert.equal(bucket.kv(home.read(), 'keychain').getItem('list'), '{"format":"live list"}');
});

test('a file from before the clean start (no v: 1) is not moved', () => {
  const dir = scratch();
  write(path.join(dir, 'edge', 'budgets.json'), { 'okedge.budget.1': { grantId: 1 } });
  write(path.join(dir, 'keychain.json'), '{"format":"list"}');
  const b = home.read();
  assert.equal(bucket.kv(b, 'edge.budgets').keys().length, 0);
  assert.ok(fs.existsSync(path.join(dir, 'edge', 'budgets.json')), 'left where it was');
});

test('nothing to move: no bucket file is made until something is written', () => {
  const dir = scratch();
  fs.mkdirSync(dir, { recursive: true });
  home.read();
  assert.ok(!fs.existsSync(path.join(dir, home.FILE)));
  home.kv(home.at('keychain')).setItem('list', '[]');
  assert.ok(fs.existsSync(path.join(dir, home.FILE)));
});

test('the default homes share this computer\'s bucket; any other home keeps its own, its old files moved into it', () => {
  const dir = scratch();
  assert.deepEqual(home.edgeAt(path.join(dir, 'edge'), 'copies'), { file: path.join(dir, home.FILE), store: 'edge.copies' });
  assert.deepEqual(home.edgeAt(path.join(dir, 'edge-test'), 'budgets'), { file: path.join(dir, home.FILE), store: 'edge-test.budgets' });
  const own = fs.mkdtempSync(path.join(os.tmpdir(), 'okbucket-own-'));
  write(path.join(own, 'pointers.json'), { v: 1, p: '7' });
  const at = home.edgeAt(own, 'pointers');
  assert.deepEqual(at, { file: path.join(own, home.FILE), store: 'edge.pointers' });
  assert.equal(home.kv(at).getItem('p'), '7');
  assert.ok(fs.existsSync(path.join(own, 'pointers.json.moved')));
});

test('one writer at a time: writes from two kv handles both land', () => {
  scratch();
  const a = home.kv(home.at('edge.budgets'));
  const b = home.kv(home.at('edge.budgets'));
  for (let i = 0; i < 20; i++) { a.setItem(`a${i}`, String(i)); b.setItem(`b${i}`, String(i)); }
  assert.equal(home.kv(home.at('edge.budgets')).keys().length, 40);
});

test('one writer at a time across processes: two onlykey-js writing at once lose nothing', async () => {
  const dir = scratch();
  const { spawn } = require('child_process');
  const writer = (tag) => new Promise((resolve, reject) => {
    const code = `const h = require(${JSON.stringify(path.resolve(__dirname, '../cli/home'))}); h.setRoot(${JSON.stringify(dir)});
      const kv = h.kv(h.at('edge.budgets')); for (let i = 0; i < 25; i++) kv.setItem('${tag}' + i, String(i));`;
    const p = spawn(process.execPath, ['-e', code], { stdio: 'inherit' });
    p.on('exit', (c) => (c === 0 ? resolve() : reject(new Error(`writer ${tag} exited ${c}`))));
  });
  await Promise.all([writer('a'), writer('b')]);
  assert.equal(home.kv(home.at('edge.budgets')).keys().length, 50);
});

test('a lock left by a process that died is taken over after it goes stale', () => {
  const dir = scratch();
  const file = path.join(dir, home.FILE);
  write(`${file}.lock`, '');
  const old = (Date.now() - 60000) / 1000;
  fs.utimesSync(`${file}.lock`, old, old);
  home.kv(home.at('keychain')).setItem('list', '[]');
  assert.equal(home.kv(home.at('keychain')).getItem('list'), '[]');
  assert.ok(!fs.existsSync(`${file}.lock`));
});

test('clear: the stores empty, each key a dated removal - a merge with an older bucket does not bring it back', () => {
  const dir = scratch();
  const kc = home.kv(home.at('keychain-test'));
  kc.setItem('list', '[1]');
  const older = home.read();
  home.clear(path.join(dir, home.FILE), ['keychain-test']);
  assert.equal(kc.getItem('list'), null);
  const now = home.read();
  /* an older copy of the bucket, made before the clear, merged in */
  older.stores['keychain-test'].list.at = '2000-01-01T00:00:00.000Z';
  const merged = bucket.merge(now, older).bucket;
  assert.equal(bucket.kv(merged, 'keychain-test').getItem('list'), null);
});

test('identity buckets: one file per identity per net, kept once, read and written per store; only an identity id names one', () => {
  const dir = scratch();
  const { ID_HEX } = require('../../edge/src/identity-id');
  const id = 'ab'.repeat(ID_HEX / 2);
  assert.equal(home.hasIdentityBucket(id, 'live'), false);
  const b = bucket.create({ owner: id });
  bucket.kv(b, 'keychain').setItem('list', 'opened by the key');
  assert.equal(home.keepIdentityBucket(id, 'live', b), true);
  /* a second keep (another process kept it first) does not replace it */
  assert.equal(home.keepIdentityBucket(id, 'live', bucket.create({ owner: id })), false);
  assert.equal(home.hasIdentityBucket(id.toUpperCase(), 'live'), true);
  assert.equal(home.hasIdentityBucket(id, 'test'), false);
  const kv = home.kv(home.identityAt(id, 'live', 'keychain'));
  assert.equal(kv.getItem('list'), 'opened by the key');
  kv.setItem('list', 'changed by the CLI');
  assert.equal(home.kv(home.identityAt(id, 'live', 'keychain')).getItem('list'), 'changed by the CLI');
  assert.equal(home.identityFile(id, 'test'), path.join(dir, 'buckets', 'test', `${id}.json`));
  assert.throws(() => home.identityFile('../../etc/passwd', 'live'), /identity id/);
  /* the plain Edge records are not touched by it */
  assert.equal(fs.existsSync(path.join(dir, home.FILE)), false);
});
