'use strict';

/*
 * A receipt carries the use's result (edge/src/receipts.js resultMessage / readResult; Brad, 2026-11-02: "the receipt
 * contains the result like reject, success, warnings, and any additional data"). One line, then fields; read back as
 * written; within the message limit with the fields kept whole; plain text the key hashes like any other message.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { receipts, note } = require('../src');

test('a result reads back as written: the line and every field', () => {
  const m = receipts.resultMessage({ line: 'signed onlykey-testing c1b7a8e device: keep 256 reports', fields: { repo: 'onlykey-testing', commit: 'a'.repeat(40), was: 'c1b7a8e', ts: '2026-11-02T20:00:00Z' } });
  assert.equal(m, `signed onlykey-testing c1b7a8e device: keep 256 reports | repo=onlykey-testing; commit=${'a'.repeat(40)}; was=c1b7a8e; ts=2026-11-02T20:00:00Z`);
  assert.deepEqual(receipts.readResult(m), { line: 'signed onlykey-testing c1b7a8e device: keep 256 reports', fields: { repo: 'onlykey-testing', commit: 'a'.repeat(40), was: 'c1b7a8e', ts: '2026-11-02T20:00:00Z' } });
});

test('separators and line breaks in a value are cleaned, empty fields left out', () => {
  const m = receipts.resultMessage({ line: 'pushed\nmain', fields: { refs: 'a..b main -> main; x=y | z', warning: '', none: null } });
  assert.equal(m, 'pushed main | refs=a..b main -> main x y z');
  assert.deepEqual(receipts.readResult(m).fields, { refs: 'a..b main -> main x y z' });
});

test('within the message limit: the line is shortened, the fields stay whole', () => {
  assert.equal(receipts.RESULT_MAX, note.MAX_RECEIPT_MSG);
  const m = receipts.resultMessage({ line: 'x'.repeat(2000), fields: { commit: 'f'.repeat(40) } });
  assert.ok(m.length <= receipts.RESULT_MAX);
  assert.match(m, /…\s\| commit=f{40}$/);
});

test('a message that is not a result reads as a line', () => {
  assert.deepEqual(receipts.readResult('signed it'), { line: 'signed it', fields: {} });
});
