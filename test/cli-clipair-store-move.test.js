/*
 * The cli pairs' file was bt-pairing.json before it got its own name (Brad, 2026-10-25: "we can't call 2 different
 * things the same thing"): a computer paired then keeps its pairings - the old file is renamed once.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const store = require('../cli/clipair-store');

test('an old bt-pairing.json becomes cli-pairing.json once, with its pairings; a newer cli-pairing.json is never replaced', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'okt-clipair-move-'));
  const dir = path.join(home, '.onlykey-js');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'bt-pairing.json'), '{"pairings":{"aa":{"phoneName":"Pixel 6a"}}}');
  const file = store.fileOf(home);
  assert.equal(file, path.join(dir, 'cli-pairing.json'));
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).pairings.aa.phoneName, 'Pixel 6a');
  assert.equal(fs.existsSync(path.join(dir, 'bt-pairing.json')), false);
  fs.writeFileSync(path.join(dir, 'bt-pairing.json'), '{"pairings":{}}');
  store.fileOf(home);
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).pairings.aa.phoneName, 'Pixel 6a', 'the newer file stays');
});
