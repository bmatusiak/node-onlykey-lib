'use strict';

/*
 * This computer's member (desktop/member.js; S5b): one of the desktop app and `--service` at a time is the computer in
 * the room. A second service stands by and takes over when the member ends; the desktop app takes the place of a
 * service that serves (it steps down first, then the app serves); a hello without the home's token is dropped.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { createMember, endpoint } = require('../desktop/member');

const until = async (what, cond, ms = 5000) => {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error(`timed out: ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
};

function member(root, who, priority, log) {
  const events = [];
  const m = createMember({
    root, who, priority,
    onServe: () => { events.push('serve'); },
    onStandBy: async (by) => { events.push(`standby:${by}`); },
    log: (l) => log.push(`${who}: ${l}`),
  });
  return { m, events };
}

test('a second service stands by, and takes over when the member ends', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'okmember-'));
  const log = [];
  const a = member(root, 'service A', 'service', log);
  const b = member(root, 'service B', 'service', log);
  await a.m.start();
  assert.equal(a.m.serving, true);
  void b.m.start();
  await until('B stands by', () => log.some((l) => l.startsWith('service B: this computer\'s member is service A')));
  assert.equal(b.m.serving, false);
  await a.m.stop();
  await until('B serves', () => b.m.serving);
  assert.deepEqual(b.events, ['serve']);
  await b.m.stop();
});

test('the desktop app takes the place of a serving service; the service serves again when the app quits', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'okmember-'));
  const log = [];
  const svc = member(root, 'the service', 'service', log);
  const app = member(root, 'the desktop app', 'desktop', log);
  await svc.m.start();
  assert.equal(svc.m.serving, true);
  void app.m.start();
  await until('the app serves', () => app.m.serving);
  assert.deepEqual(svc.events, ['serve', 'standby:the desktop app'], 'the service let go first');
  await until('the service stands by on the app', () => log.some((l) => l.startsWith('the service: this computer\'s member is the desktop app')));
  assert.equal(svc.m.serving, false);
  await app.m.stop();
  await until('the service serves again', () => svc.m.serving);
  assert.deepEqual(svc.events, ['serve', 'standby:the desktop app', 'serve']);
  await svc.m.stop();
});

test('a hello without the home\'s token is dropped', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'okmember-'));
  const log = [];
  const svc = member(root, 'the service', 'service', log);
  await svc.m.start();
  const sock = net.connect(endpoint(root));
  const said = [];
  sock.setEncoding('utf8');
  sock.on('data', (d) => said.push(d));
  sock.on('error', () => {});
  await new Promise((r) => sock.once('connect', r));
  sock.write(`${JSON.stringify({ t: 'hello', token: 'not-it', who: 'someone', priority: 'desktop' })}\n`);
  await new Promise((r) => sock.once('close', r));
  assert.deepEqual(said, [], 'nothing answered');
  assert.equal(svc.m.serving, true, 'the member did not step down');
  await svc.m.stop();
});
