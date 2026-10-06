'use strict';
/* A request nobody answered lets the link go; the key or phone speaking never does (Brad, 2026-10-06). */
const test = require('node:test');
const assert = require('node:assert');
const { isSilence } = require('../cli/edge-agent');

test('isSilence: nothing came back - yes; a refusal, a press that ran out, a cut-short reply - no', () => {
  assert.strictEqual(isSilence(Object.assign(new Error('no answer'), { code: 'ETIMEDOUT', partial: 0 })), true);
  assert.strictEqual(isSilence(Object.assign(new Error('did not answer'), { code: 'EEDGE_UNSUPPORTED' })), true);
  assert.strictEqual(isSilence(Object.assign(new Error('wrapped'), { cause: Object.assign(new Error('x'), { code: 'ETIMEDOUT' }) })), true);
  assert.strictEqual(isSilence(Object.assign(new Error('press ran out'), { code: 'ETIMEDOUT', pressTimeout: true })), false);
  assert.strictEqual(isSilence(Object.assign(new Error('refused press'), { code: 'ETIMEDOUT', pressRefused: true })), false);
  assert.strictEqual(isSilence(Object.assign(new Error('cut short'), { code: 'ETIMEDOUT', partial: 2 })), false);
  assert.strictEqual(isSilence(Object.assign(new Error('refused'), { code: 'EKEYREFUSED' })), false);
});
