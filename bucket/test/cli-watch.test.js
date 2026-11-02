/*
 * The kept buckets' watch (bucket/cli/watch.js): a burst of writes is one change; the member's own write (noteOwn) is
 * not a change; a write that changes nothing is none either.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { watchBuckets } = require('../cli/watch');

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

function setUp() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'okbucket-watch-'));
  const file = path.join(dir, '0123456789abcdef0123456789abcdef.json');
  fs.writeFileSync(file, '{"v":1}');
  let fire = null;
  const watch = (d, cb) => { fire = cb; return { close() {} }; };
  const changes = [];
  const w = watchBuckets({ dir, watch, debounceMs: 20, onChange: () => changes.push(Date.now()) });
  return { file, fire: () => fire(), changes, w };
}

test('a burst of writes is one change', async () => {
  const { file, fire, changes, w } = setUp();
  for (const v of [2, 3, 4]) { fs.writeFileSync(file, `{"v":${v}}`); fire(); }
  await wait(80);
  assert.equal(changes.length, 1);
  w.stop();
});

test('the member\'s own write is not a change; a write that changes nothing is none', async () => {
  const { file, fire, changes, w } = setUp();
  fs.writeFileSync(file, '{"v":"traded"}');
  w.noteOwn();
  fire();
  await wait(60);
  assert.equal(changes.length, 0, 'its own write');
  fs.writeFileSync(file, '{"v":"traded"}');
  fire();
  await wait(60);
  assert.equal(changes.length, 0, 'the same contents again');
  fs.writeFileSync(file, '{"v":"a password added"}');
  fire();
  await wait(60);
  assert.equal(changes.length, 1, 'a real change');
  w.stop();
});
