'use strict';

/*
 * The local MCP's record (desktop/trust.js local-mcp-<what>.json): an mcp-server on 127.0.0.1 says where it runs, one
 * file per kind ('computer', 'ble'), so agents and the CLI on this machine find it - a record whose process is gone reads
 * as none, and only its own process removes it.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const trust = require('../desktop/trust');

const scratch = () => fs.mkdtempSync(path.join(os.tmpdir(), 'local-mcp-'));

test('the local MCP says where it runs, one file per kind; a gone process reads as none; only its own process removes the record', () => {
  const root = scratch();
  assert.equal(trust.readLocalMcp(root, 'computer'), null, 'none yet');
  trust.writeLocalMcp({ root, url: 'http://127.0.0.1:41234', what: 'computer' });
  trust.writeLocalMcp({ root, url: 'http://127.0.0.1:8792', what: 'ble' });
  assert.deepEqual({ ...trust.readLocalMcp(root, 'computer'), pid: 0 }, { v: 1, url: 'http://127.0.0.1:41234', pid: 0, what: 'computer' });
  assert.equal(trust.readLocalMcp(root, 'ble').url, 'http://127.0.0.1:8792', 'one file per kind: both stand');
  assert.equal(trust.readLocalMcp(root, 'computer', { isAlive: () => false }), null, 'its process is gone: stale');
  trust.removeLocalMcp({ root, what: 'computer', pid: process.pid + 1 });
  assert.ok(trust.readLocalMcp(root, 'computer'), 'another process does not remove it');
  trust.removeLocalMcp({ root, what: 'computer' });
  assert.equal(trust.readLocalMcp(root, 'computer'), null, 'its own process removed it');
  assert.ok(trust.readLocalMcp(root, 'ble'), 'the other kind stays');
  assert.throws(() => trust.writeLocalMcp({ root, url: 'http://0.0.0.0:80', what: 'computer' }), /on 127\.0\.0\.1/);
  assert.throws(() => trust.writeLocalMcp({ root, url: 'http://127.0.0.1:1', what: 'stand-in' }), /computer or ble/);
});
