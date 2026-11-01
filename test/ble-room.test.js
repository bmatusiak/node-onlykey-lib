'use strict';

/*
 * cli/ble-room.js - `onlykey-js --ble` finding the phone's room (the mcp-server end, with a real room and a phone's
 * key session, is ok-edge mcp-server/test/ble.test.js). Here: the agent key file, and each way the local mcp-server's
 * /ble answer stops the CLI with what to do.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { phoneChannel, agentKey } = require('../cli/ble-room');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'ble-room-'));
const answer = (status, body, type = 'application/json') => async () => ({
  status, ok: status === 200, headers: { get: () => type }, json: async () => body, text: async () => String(body),
});

test('the agent key: made once, owner-only, the same on every later run', () => {
  const root = tmp();
  const k = agentKey(root);
  assert.match(k, /^[0-9a-f]{64}$/);
  assert.equal(agentKey(root), k);
  if (process.platform !== 'win32') assert.equal(fs.statSync(path.join(root, 'agent-key')).mode & 0o777, 0o600);
});

test('no mcp-server, one without Bluetooth, no phone, two phones: each says what to do', async () => {
  const root = tmp();
  const refused = async () => { throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }); };
  await assert.rejects(phoneChannel({ url: 'http://127.0.0.1:1', root, fetch: refused }), /no mcp-server at http:\/\/127\.0\.0\.1:1 \(ECONNREFUSED\) - start it with --ble/);
  await assert.rejects(phoneChannel({ root, fetch: answer(404, 'x', 'text/html') }), /has no Bluetooth - start it with --ble/);
  await assert.rejects(phoneChannel({ root, fetch: answer(200, { host: 'box', phones: [] }) }), /no phone has joined the room over Bluetooth \(box\) - on the phone: the Bluetooth tab, Bluetooth MCP on/);
  const two = { host: 'box', phones: [{ room: 'a', device: { id: '1', name: 'Pixel' } }, { room: 'b', device: { id: '2', name: 'A13' } }] };
  await assert.rejects(phoneChannel({ root, fetch: answer(200, two) }), /more than one phone joined over Bluetooth \(Pixel, A13\)/);
});
