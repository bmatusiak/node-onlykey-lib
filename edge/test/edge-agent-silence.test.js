'use strict';
/* A request nobody answered lets the link go; the key or phone speaking never does (Brad, 2026-10-06). */
const test = require('node:test');
const assert = require('node:assert');
const { isSilence } = require('../cli/agent');

test('isSilence: nothing came back - yes; a refusal, a press that ran out, a cut-short reply - no', () => {
  assert.strictEqual(isSilence(Object.assign(new Error('no answer'), { code: 'ETIMEDOUT', partial: 0 })), true);
  assert.strictEqual(isSilence(Object.assign(new Error('did not answer'), { code: 'EEDGE_UNSUPPORTED' })), true);
  assert.strictEqual(isSilence(Object.assign(new Error('wrapped'), { cause: Object.assign(new Error('x'), { code: 'ETIMEDOUT' }) })), true);
  assert.strictEqual(isSilence(Object.assign(new Error('press ran out'), { code: 'ETIMEDOUT', pressTimeout: true })), false);
  assert.strictEqual(isSilence(Object.assign(new Error('refused press'), { code: 'ETIMEDOUT', pressRefused: true })), false);
  assert.strictEqual(isSilence(Object.assign(new Error('cut short'), { code: 'ETIMEDOUT', partial: 2 })), false);
  assert.strictEqual(isSilence(Object.assign(new Error('refused'), { code: 'EKEYREFUSED' })), false);
});

/* Brad, 2026-10-06: a restart that met the phone still dropping the old link (ENOVENDOR) tries once more after ~5 s */
test('openWithOneRetry: ENOVENDOR once -> a second try; twice, or any other error -> thrown', async () => {
  const { openWithOneRetry } = require('../cli/agent');
  const enovendor = () => Object.assign(new Error('Pixel 6a has no OnlyKey vendor service (x). Is it the phone'), { code: 'ENOVENDOR' });
  const logs = [];
  let n = 0;
  assert.equal(await openWithOneRetry(async () => { if (++n === 1) throw enovendor(); return 'app'; }, { waitMs: 5, log: (l) => logs.push(l) }), 'app');
  assert.equal(n, 2);
  assert.match(logs[0], /no OnlyKey vendor service \(x\) - the phone may still be dropping the last link; trying once more/);
  n = 0;
  await assert.rejects(openWithOneRetry(async () => { n++; throw enovendor(); }, { waitMs: 5 }), { code: 'ENOVENDOR' });
  assert.equal(n, 2, 'once more, not forever');
  n = 0;
  await assert.rejects(openWithOneRetry(async () => { n++; throw Object.assign(new Error('locked'), { code: 'ELOCKED' }); }, { waitMs: 5 }), { code: 'ELOCKED' });
  assert.equal(n, 1, 'other errors are not retried');
});
