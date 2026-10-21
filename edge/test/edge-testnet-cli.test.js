/*
 * `onlykey-js edge --test-mode` (BLOCKS.md; Brad, 2026-10-07: "we should treat
 * --test-mode as test net for cli for edge"; "everthing for test is throwaway"):
 * its own home, its own Key Chain file, TESTNET said first - and the next run
 * without it is back on the live chain.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const os = require('os');
const path = require('path');
const fs = require('fs');
/*
 * A HOME OF ITS OWN, before the CLI loads: the clear test below really removes
 * <home>/.onlykey-js/edge-test, and with the real home it removed this computer's testnet agent,
 * copies and Key Chain file on every `npm test` (found 2026-10-10). The homes are read from
 * os.homedir() at each call, so this one line moves every one of them.
 */
const FAKE_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'oktestnet-home-'));
os.homedir = () => FAKE_HOME;
const { main } = require('../../cli/index');
const control = require('../cli/control');
const record = require('../../keychain/cli/record');

const noDevice = () => { throw new Error('opened a device'); };
async function run(argv) {
  const out = [];
  const err = [];
  const code = await main(argv, { out: (l) => out.push(l), err: (l) => err.push(l), start: noDevice });
  return { code, out, err };
}
const base = path.join(os.homedir(), '.onlykey-js');
/* the testnet's Key Chain: a store in the CLI's bucket (bucket/cli/home.js) */
const TEST_KC = path.join(base, 'bucket.json') + ' (keychain-test)';

test('--test-mode: the testnet home and Key Chain file, said first; the next run is live again', async () => {
  const t = await run(['edge', '--test-mode', 'blocks']);
  assert.match(t.err[0], /^edge: TESTNET - the test chain/);
  assert.equal(control.edgeHome(), path.join(base, 'edge-test'));
  assert.equal(String(record.keychainFile()), TEST_KC);
  const l = await run(['edge', 'blocks']);
  assert.ok(!l.err.some((x) => /TESTNET/.test(x)));
  assert.equal(control.edgeHome(), path.join(base, 'edge'));
  assert.notEqual(String(record.keychainFile()), TEST_KC);
});

/*
 * A hint followed as printed must stay on the chain it came from, and the
 * testnet's Key Chain file must be readable; the testnet's home chosen by hand
 * without --test-mode is refused, not quietly put back to live.
 */
test('--test-mode: hints carry it, keychain --test-mode reads the testnet list, the test home without it is refused', async () => {
  let r = await run(['edge', '--test-mode', 'nope']);
  assert.equal(r.code, 2);
  assert.match(r.err.join('\n'), /onlykey-js edge --test-mode help/);
  r = await run(['edge', 'nope']);
  assert.match(r.err.join('\n'), /onlykey-js edge help/);

  await run(['keychain', '--test-mode', 'list']);
  assert.equal(String(record.keychainFile()), TEST_KC);
  await run(['keychain', 'list']);
  assert.notEqual(String(record.keychainFile()), TEST_KC);

  try {
    r = await run(['edge', '--edge-home', path.join(base, 'edge-test'), 'blocks']);
    assert.equal(r.code, 2);
    assert.match(r.err.join('\n'), /testnet's home - add --test-mode/);
  } finally {
    control.setHome(null); /* --edge-home sticks within one process; the CLI is one run per process */
  }
});

test('--test-mode keeps a home chosen with --edge-home (dev), and only before --', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'oktestnet-'));
  try {
    await run(['edge', '--edge-home', home, '--test-mode', 'blocks']);
    assert.equal(control.edgeHome(), path.resolve(home));
  } finally {
    control.setHome(null);
    fs.rmSync(home, { recursive: true, force: true });
  }
  const after = await run(['edge', 'help', '--', '--test-mode']);
  assert.ok(!after.err.some((x) => /TESTNET/.test(x)), 'a --test-mode after -- is the command\'s, not the CLI\'s');
});

test('edge clear: the testnet\'s only - refused live; with --test-mode it removes the testnet home and Key Chain file, nothing else', async () => {
  const live = await run(['edge', 'clear']);
  assert.notEqual(live.code, 0);
  assert.match(live.err.join('\n'), /clear is the testnet's only/);
  const testHome = path.join(base, 'edge-test');
  fs.mkdirSync(testHome, { recursive: true });
  fs.writeFileSync(path.join(testHome, 'marker'), 'x');
  /* the testnet's data and the live side's, both in the bucket */
  const bucketHome = require('../../bucket/cli/home');
  bucketHome.kv(bucketHome.at('keychain-test')).setItem('list', '[]');
  bucketHome.kv(bucketHome.at('edge-test.copies')).setItem('0'.repeat(16), '{"v":1}');
  bucketHome.kv(bucketHome.at('keychain')).setItem('list', '[]');
  bucketHome.kv(bucketHome.at('edge.copies')).setItem('1'.repeat(16), '{"v":1}');
  /* what the live side holds before - it must hold the same after */
  const liveHome = path.join(base, 'edge');
  const liveSide = () => {
    const b = bucketHome.read();
    return { home: fs.existsSync(liveHome) && fs.readdirSync(liveHome).sort().join(','), kc: JSON.stringify(b.stores.keychain), copies: JSON.stringify(b.stores['edge.copies']) };
  };
  const before = liveSide();
  const c = await run(['edge', '--test-mode', 'clear']);
  assert.equal(c.code, 0, c.err.join('\n'));
  assert.ok(!fs.existsSync(testHome));
  assert.match(c.out.join('\n'), /testnet cleared on this computer/);
  assert.equal(bucketHome.kv(bucketHome.at('keychain-test')).getItem('list'), null, 'the testnet Key Chain left the bucket');
  assert.equal(bucketHome.kv(bucketHome.at('edge-test.copies')).keys().length, 0, 'the testnet copies left the bucket');
  assert.deepEqual(liveSide(), before, 'the live home and the live stores are not touched');
});
