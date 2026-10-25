'use strict';
/*
 * `pair` takes no computer name. Every other command introduces this computer
 * by its hostname, and the phone revokes a pairing used under a different
 * name than it was made with (test/clipair.test.js, reason 'name'). So a name
 * chosen at pair time could only ever make a pairing that breaks on first
 * use - which `pair --name zbox` did on the ZBOX, 2026-10-20. Refused here,
 * before anything reaches a phone.
 */
const test = require('node:test');
const assert = require('node:assert');
const os = require('os');
const { main } = require('../cli/index');
const store = require('../cli/clipair-store');

async function run(argv) {
  const out = [];
  const err = [];
  const code = await main(argv, { out: (l) => out.push(l), err: (l) => err.push(l) });
  return { code, out, err };
}

test('pair --name is a usage error, with or without --ble', async () => {
  for (const argv of [['pair', '--name', 'zbox'], ['--ble', 'pair', '--name', 'zbox'], ['--ble', '--address', 'aa:bb:cc:00:11:22', 'pair', '--name=zbox']]) {
    const r = await run(argv);
    assert.equal(r.code, 2, `${argv.join(' ')} must be refused`);
    assert.match(r.err.join('\n'), /name/, 'the refusal names the option');
  }
});

test('the usage no longer offers a name', async () => {
  const { COMMANDS } = require('../cli/index');
  assert.doesNotMatch(COMMANDS.pair.usage, /--name/);
  assert.equal(COMMANDS.pair.options, undefined);
});

test('the name a pairing is made with is the one every command sends: the hostname', () => {
  assert.equal(store.computerName(), os.hostname());
});
