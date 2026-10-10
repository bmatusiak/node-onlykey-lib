/*
 * `onlykey-js edge --test-mode` (BLOCKS.md §5; Brad, 2026-10-07: "we should treat
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

test('--test-mode: the testnet home and Key Chain file, said first; the next run is live again', async () => {
  const t = await run(['edge', '--test-mode', 'blocks']);
  assert.match(t.err[0], /^edge: TESTNET - the test chain/);
  assert.equal(control.edgeHome(), path.join(base, 'edge-test'));
  assert.equal(record.keychainFile(), path.join(base, 'keychain-test.json'));
  const l = await run(['edge', 'blocks']);
  assert.ok(!l.err.some((x) => /TESTNET/.test(x)));
  assert.equal(control.edgeHome(), path.join(base, 'edge'));
  assert.notEqual(record.keychainFile(), path.join(base, 'keychain-test.json'));
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
  /* what the live side holds before - it must hold the same after */
  const liveHome = path.join(base, 'edge');
  const liveKc = record.keychainFile();
  const before = { home: fs.existsSync(liveHome) && fs.readdirSync(liveHome).sort().join(','), kc: fs.existsSync(liveKc) && fs.statSync(liveKc).mtimeMs };
  const c = await run(['edge', '--test-mode', 'clear']);
  assert.equal(c.code, 0, c.err.join('\n'));
  assert.ok(!fs.existsSync(testHome));
  assert.match(c.out.join('\n'), /testnet cleared on this computer/);
  const after = { home: fs.existsSync(liveHome) && fs.readdirSync(liveHome).sort().join(','), kc: fs.existsSync(liveKc) && fs.statSync(liveKc).mtimeMs };
  assert.deepEqual(after, before, 'the live home and the live Key Chain file are not touched');
});
