'use strict';

/*
 * Testnet-only host pins (edge/cli/agent.js pinsFor): the live net never reads ssh-pins.json; the testnet adds its valid
 * entries to GitHub's; anything not a SHA256 fingerprint is left out; no file or nothing valid = the default.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { pinsFor, PINS_FILE } = require('../cli/agent');
const { GITHUB_FINGERPRINTS } = require('../../cli/ssh-session-bind');

const FP = 'SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ';
const reader = (text) => (f) => { assert.equal(path.basename(f), PINS_FILE); return text; };

test('the live net never reads the pins file', () => {
  assert.equal(pinsFor({ net: 'live', home: '/x', read: () => { throw new Error('read on the live net'); } }), null);
});

test('the testnet adds its valid pins to GitHub\'s; invalid entries are left out', () => {
  assert.deepEqual(pinsFor({ net: 'test', home: '/x', read: reader(JSON.stringify([FP, 'not-a-pin', 7])) }), [...GITHUB_FINGERPRINTS, FP]);
});

test('no file, not a list, or nothing valid: the default (null)', () => {
  assert.equal(pinsFor({ net: 'test', home: '/x', read: () => { throw new Error('ENOENT'); } }), null);
  assert.equal(pinsFor({ net: 'test', home: '/x', read: reader('{"a":1}') }), null);
  assert.equal(pinsFor({ net: 'test', home: '/x', read: reader('["nope"]') }), null);
});
