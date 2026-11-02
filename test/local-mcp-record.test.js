'use strict';

/*
 * The local MCP's record (desktop/trust.js local-mcp.json): an mcp-server on 127.0.0.1 says where it runs, so agents and
 * the CLI on this machine find it - a record whose process is gone reads as none, and only its own process removes it.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const trust = require('../desktop/trust');

const scratch = () => fs.mkdtempSync(path.join(os.tmpdir(), 'local-mcp-'));

test('the local MCP says where it runs; a gone process reads as none; only its own process removes the record', () => {
  const root = scratch();
  assert.equal(trust.readLocalMcp(root), null, 'none yet');
  trust.writeLocalMcp({ root, url: 'http://127.0.0.1:41234', what: 'desktop' });
  assert.deepEqual({ ...trust.readLocalMcp(root), pid: 0 }, { v: 1, url: 'http://127.0.0.1:41234', pid: 0, what: 'desktop' });
  assert.equal(trust.readLocalMcp(root, { isAlive: () => false }), null, 'its process is gone: stale');
  trust.removeLocalMcp({ root, pid: process.pid + 1 });
  assert.ok(trust.readLocalMcp(root), 'another process does not remove it');
  trust.removeLocalMcp({ root });
  assert.equal(trust.readLocalMcp(root), null, 'its own process removed it');
  assert.throws(() => trust.writeLocalMcp({ root, url: 'http://0.0.0.0:80' }), /on 127\.0\.0\.1/);
});
