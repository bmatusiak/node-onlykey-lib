'use strict';

/* CLI.md §1, §2, §7 (decided 2026-10-06): one CLI, onlykey-js - okedge, onlykey-edge-gpg, edge-agent and pairing are gone */
const test = require('node:test');
const assert = require('node:assert');
const pkg = require('../package.json');
const { main } = require('../cli/index.js');

const run = async (argv) => {
  const lines = [];
  const code = await main(argv, {
    out: (l) => lines.push(l), err: (l) => lines.push(`ERR ${l}`),
    start: () => { throw new Error('connected to a device'); },
    keychainRecord: null,
  });
  return { code, text: lines.join('\n') };
};

test('one CLI: the only bin is onlykey-js', () => {
  assert.deepEqual(Object.keys(pkg.bin), ['onlykey-js']);
});

test('help lists edge and pair; no okedge, edge-agent or pairing', async () => {
  const r = await run(['help']);
  assert.match(r.text, /^\s*edge\s/m);
  assert.match(r.text, /^\s*pair\s/m);
  for (const gone of ['okedge', 'edge-agent', 'pairing']) assert.doesNotMatch(r.text, new RegExp(`^\s*${gone}\s`, 'm'), gone);
});

test('pairing and edge-agent are unknown commands', async () => {
  for (const c of ['pairing', 'edge-agent']) {
    const r = await run([c]);
    assert.equal(r.code, 2, c);
    assert.match(r.text, /unknown command/, c);
  }
});

test('an unknown edge subcommand is refused before anything connects', async () => {
  const r = await run(['edge', 'nonsense']);
  assert.equal(r.code, 2);
  assert.match(r.text, /unknown edge command "nonsense"/);
});
