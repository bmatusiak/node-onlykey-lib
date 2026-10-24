'use strict';

/* cli/prompt.js from a pipe: one line per prompt, the rest kept for the next (setbackuppassphrase asks twice) */

const test = require('node:test');
const assert = require('node:assert/strict');
const { PassThrough } = require('stream');
const { promptSecret } = require('../cli/prompt');

const pipe = () => { const s = new PassThrough(); s.isTTY = false; return s; };
const ask = (input) => promptSecret('', { input, output: new PassThrough() });

test('two prompts read two lines that arrived in ONE chunk (printf "p\\np\\n" | onlykey-js setbackuppassphrase)', async () => {
  const input = pipe();
  input.end('dummy-pass-123\ndummy-pass-123\n');
  assert.equal(await ask(input), 'dummy-pass-123');
  assert.equal(await ask(input), 'dummy-pass-123');
});

test('lines split across chunks, CRLF endings, and a last line with no newline', async () => {
  const input = pipe();
  const first = ask(input);
  input.write('on');
  input.write('e\r\ntw');
  assert.equal(await first, 'one');
  input.end('o');
  assert.equal(await ask(input), 'two');
  assert.equal(await ask(input), '', 'past the end: nothing, not a hang');
});
