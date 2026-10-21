/*
 * `onlykey-js bucket …` through the CLI itself, in a scratch home: show, an unsealed import (a
 * development checkout only) merged without dropping anything, a sealed file refused without
 * the key, and the dump being the Edge chain alone. Export and a sealed import need the key's
 * derive - the kit and the phone run cover those (bucket.test.js covers seal/open themselves).
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const FAKE_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'okbucket-cli-home-'));
os.homedir = () => FAKE_HOME;
const { main } = require('../../cli/index');
const bucket = require('../src/bucket');
const home = require('../cli/home');

const noDevice = () => { throw new Error('opened a device'); };
async function run(argv) {
  const out = [];
  const err = [];
  const code = await main(argv, { out: (l) => out.push(l), err: (l) => err.push(l), start: noDevice });
  return { code, out, err };
}
const scratchFile = (name, text) => { const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'okbucket-in-')), name); fs.writeFileSync(f, text); return f; };

test('bucket show: each store and its count, no values', async () => {
  home.kv(home.at('keychain')).setItem('list', '{"secret-looking":"value"}');
  const r = await run(['bucket', 'show']);
  assert.equal(r.code, 0, r.err.join('\n'));
  const text = r.out.join('\n');
  assert.match(text, /keychain\s+1 entry/);
  assert.ok(!text.includes('secret-looking'), 'show prints counts, never values');
});

test('bucket import (unsealed, a development checkout): merged, nothing of this computer\'s dropped', async () => {
  const theirs = bucket.create();
  bucket.kv(theirs, 'edge.budgets').setItem('okedge.budget.5', '{"grantId":5}');
  bucket.kv(theirs, 'settings').setItem('theme', 'dark');
  const f = scratchFile('theirs.json', bucket.serialize(theirs));
  const r = await run(['bucket', 'import', f]);
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.match(r.out.join('\n'), /imported: .*edge\.budgets 1/);
  const mine = home.read();
  assert.equal(bucket.kv(mine, 'edge.budgets').getItem('okedge.budget.5'), '{"grantId":5}');
  assert.equal(bucket.kv(mine, 'keychain').getItem('list'), '{"secret-looking":"value"}', 'this computer\'s store is kept');
});

test('a sealed bucket needs the key: import asks for the device, it is never read another way', async () => {
  const key = new Uint8Array(32).fill(7);
  const sealed = bucket.seal(bucket.create(), key, (n) => new Uint8Array(n).fill(1));
  const f = scratchFile('sealed.json', sealed);
  const r = await run(['bucket', 'import', f]);
  assert.notEqual(r.code, 0);
  assert.match(r.err.join('\n'), /opened a device/);
});

test('bucket dump: the Edge chain only, JSON - an empty chain is an empty list', async () => {
  const r = await run(['bucket', 'dump']);
  /* a build without the Edge folder has no chain to dump, and says so */
  if (!fs.existsSync(path.join(__dirname, '..', '..', 'edge'))) {
    assert.notEqual(r.code, 0);
    assert.match(r.err.join('\n'), /no Edge folder/);
    return;
  }
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.deepEqual(JSON.parse(r.out.join('\n')), []);
});

test('bucket export never writes over a file', async () => {
  const f = scratchFile('there.json', 'x');
  const r = await run(['bucket', 'export', f]);
  assert.notEqual(r.code, 0);
  assert.match(r.err.join('\n'), /never writes over a file/);
  assert.equal(fs.readFileSync(f, 'utf8'), 'x');
});
