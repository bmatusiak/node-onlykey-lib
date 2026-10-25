'use strict';

/*
 * The ok-edge desktop app's side of --desktop (desktop/serve.js) and the CLI's (cli/transport-desktop.js),
 * over a real local socket, with a fake key (a pipe) and a fake host. What the CLI's wire channel and
 * local-host.js do on top is their own tests'; here: the trust file, the hello, the key's reports both
 * ways, the host's answer in 0xF7 pieces with the request's net, and the key muted while the host has it.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const trust = require('../desktop/trust');
const { createDesktopServer } = require('../desktop/serve');
const { createDesktopPipe } = require('../cli/transport-desktop');
const wire = require('../edge/src/wire');
const { DIR } = require('../src/transport/contract');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'okjs-desk-'));

/* a key on a pipe: it answers a write with the same bytes + 1 on byte 0 (dir OUT), after the echo (dir IN) */
function fakeKeyPipe() {
  const listeners = new Set();
  const writes = [];
  const emit = (ev) => { for (const l of [...listeners]) l(ev); };
  return {
    writes,
    emit,
    isRunning: () => true,
    async start() {},
    async write(iface, bytes) {
      writes.push({ iface, bytes: Uint8Array.from(bytes) });
      emit({ iface, dir: DIR.IN, bytes });
      const reply = Uint8Array.from(bytes); reply[0] = (reply[0] + 1) & 0xff;
      setImmediate(() => emit({ iface, dir: DIR.OUT, bytes: reply }));
      return bytes.length + 1;
    },
    on(event, l) { if (event === 'stream') { listeners.add(l); return () => listeners.delete(l); } return () => {}; },
    device: { path: 'fake-key', product: 'ONLYKEY' },
    interfaces: () => [{ iface: 2 }],
  };
}

const until = async (cond, ms = 3000) => {
  const end = Date.now() + ms;
  while (!cond()) { if (Date.now() > end) throw new Error('timed out'); await new Promise((r) => setTimeout(r, 10)); }
};

test('trust: written owner-only with a fresh token; live while its app runs; stale when not; removed only by its own app', () => {
  const root = tmp();
  try {
    assert.equal(trust.liveTrust(root), null);
    const rec = trust.writeTrust({ root, socket: path.join(root, 'x.sock') });
    assert.match(rec.token, /^[0-9a-f]{64}$/);
    assert.deepEqual(trust.readTrust(root), rec);
    assert.equal(trust.liveTrust(root, { platform: 'win32' }).token, rec.token);
    assert.equal(trust.liveTrust(root, { platform: 'win32', isAlive: () => false }), null, 'its app is gone: stale');
    assert.equal(trust.liveTrust(root, { platform: 'linux' }), null, 'no socket file: not live');
    assert.ok(trust.tokenMatches(rec, rec.token));
    assert.ok(!trust.tokenMatches(rec, 'f'.repeat(64)));
    trust.removeTrust({ token: 'a'.repeat(64) }, root);
    assert.ok(trust.readTrust(root), 'another app\'s record does not remove it');
    trust.removeTrust(rec, root);
    assert.equal(trust.readTrust(root), null);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('desktop: the hello needs the token; one CLI at a time; the key\'s reports both ways, the echo kept local', async () => {
  const root = tmp();
  const key = fakeKeyPipe();
  const server = createDesktopServer({ pipe: key, root, hostFor: () => ({ send: async () => null }) });
  const rec = await server.start();
  try {
    await assert.rejects(createDesktopPipe({ record: { ...rec, token: 'f'.repeat(64) } }).start(), /refused: not this app's token/);

    const cli = createDesktopPipe({ root: undefined, record: rec });
    const seen = [];
    cli.on('stream', (ev) => seen.push(ev));
    await cli.start();
    assert.ok(cli.isRunning());
    assert.equal(cli.device.path, 'fake-key');
    await assert.rejects(createDesktopPipe({ record: rec }).start(), /refused: busy/);

    const report = new Uint8Array(64); report[0] = 7;
    await cli.write(2, report);
    await until(() => seen.some((e) => e.dir === DIR.OUT));
    assert.equal(key.writes.length, 1);
    assert.equal(key.writes[0].bytes[0], 7);
    assert.deepEqual(seen.map((e) => [e.dir, e.bytes[0]]), [[DIR.IN, 7], [DIR.OUT, 8]], 'the echo here, the key\'s answer from the app - never the app\'s echo');
    await cli.stop();
  } finally {
    await server.stop();
    fs.rmSync(root, { recursive: true, force: true });
  }
  assert.equal(trust.readTrust(root), null, 'desktop.json goes with the app');
});

test('desktop: an 0xF7 request goes to the host of ITS net, never to the key; the answer comes back stamped; the key is muted meanwhile', async () => {
  const root = tmp();
  const key = fakeKeyPipe();
  const asked = [];
  const hostFor = (n) => ({
    async send(message) {
      asked.push({ net: n, type: message.type });
      /* the host uses the key: its report must not reach the CLI */
      key.emit({ iface: 2, dir: DIR.OUT, bytes: new Uint8Array(64).fill(0x33) });
      return { ok: true, record: null };
    },
  });
  const server = createDesktopServer({ pipe: key, root, hostFor });
  const rec = await server.start();
  try {
    const cli = createDesktopPipe({ record: rec });
    const asm = wire.createAssembler();
    let answer = null;
    const strays = [];
    cli.on('stream', (ev) => {
      if (ev.dir !== DIR.OUT) return;
      if (!wire.isEdgeRequestFrame(ev.bytes)) { strays.push(ev); return; }
      const got = asm.push(ev.bytes);
      if (got && got.kind === wire.KIND.ANSWER) answer = got.message;
    });
    await cli.start();
    const request = { type: 'EDGE_IDENTITY_GET', v: 1, nonce: 'ab'.repeat(16), wire: { dev: 'cli', id: 'r1', ts: Date.now(), net: 'test' } };
    for (const frame of wire.encode(wire.KIND.REQUEST, request)) await cli.write(2, frame);
    await until(() => answer);
    await server.idle();
    assert.deepEqual(asked, [{ net: 'test', type: 'EDGE_IDENTITY_GET' }]);
    assert.equal(key.writes.length, 0, 'the host\'s message never reached the key');
    assert.equal(answer.ok, true);
    assert.deepEqual(answer.wire.re, { dev: 'cli', id: 'r1' });
    assert.equal(answer.wire.net, 'test');
    assert.equal(strays.length, 0, 'the key\'s report while the host had it stayed in the app');
    await cli.stop();
  } finally {
    await server.stop();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

/* the desktop app is the key's GUI (Brad, 2026-10-24): while it runs, plain goes through it and --path is refused */
test('cli: with a live desktop app, plain goes through it and --path is refused', async () => {
  const { main } = require('../cli/index.js');
  const root = tmp();
  const was = { desk: process.env.ONLYKEY_JS_DESKTOP, at: process.env.ONLYKEY_JS_TRUST_ROOT };
  delete process.env.ONLYKEY_JS_DESKTOP;
  process.env.ONLYKEY_JS_TRUST_ROOT = root;
  try {
    const sock = path.join(root, 'desktop.sock');
    fs.writeFileSync(sock, '');
    trust.writeTrust({ root, socket: sock });
    const err = [];
    const asked = [];
    const io = { out: () => {}, err: (l) => err.push(l), start: async (o) => { asked.push(o); throw Object.assign(new Error('stop here'), { code: 'ESTOP' }); } };
    assert.equal(await main(['--path', 'x', 'status'], io), 2);
    assert.match(err.join('\n'), /desktop app is running - it holds the key and is its GUI; run without --path/);
    assert.deepEqual(asked, [], '--path never opened anything');
    await main(['status'], io);
    assert.deepEqual(asked, [{ desktop: true, auto: true }], 'plain: the desktop app');
  } finally {
    if (was.desk === undefined) delete process.env.ONLYKEY_JS_DESKTOP; else process.env.ONLYKEY_JS_DESKTOP = was.desk;
    if (was.at === undefined) delete process.env.ONLYKEY_JS_TRUST_ROOT; else process.env.ONLYKEY_JS_TRUST_ROOT = was.at;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

/* the app learns when a CLI's conversation begins and ends (onClient), to keep its own key traffic out of it */
test('desktop: onClient is told when a CLI is accepted and when it goes - not for a refused one', async () => {
  const root = tmp();
  const told = [];
  const server = createDesktopServer({ pipe: fakeKeyPipe(), root, hostFor: () => ({ send: async () => null }), onClient: (c) => told.push(c) });
  const rec = await server.start();
  try {
    await assert.rejects(createDesktopPipe({ record: { ...rec, token: 'f'.repeat(64) } }).start(), /refused/);
    assert.deepEqual(told, [], 'a refused hello is no conversation');
    const cli = createDesktopPipe({ record: rec });
    await cli.start();
    await until(() => told.length === 1);
    await cli.stop();
    await until(() => told.length === 2);
    assert.deepEqual(told, [true, false]);
  } finally {
    await server.stop();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

/* a report the app's own read left behind, arriving just after a CLI connects, is not that CLI's answer */
test('desktop: a newly connected CLI gets the key\'s reports only from its own first write on', async () => {
  const root = tmp();
  const key = fakeKeyPipe();
  const server = createDesktopServer({ pipe: key, root, hostFor: () => ({ send: async () => null }) });
  const rec = await server.start();
  try {
    const cli = createDesktopPipe({ record: rec });
    const seen = [];
    cli.on('stream', (ev) => { if (ev.dir === DIR.OUT) seen.push(ev.bytes[0]); });
    await cli.start();
    const stale = new Uint8Array(64); stale[0] = 0x55;
    key.emit({ iface: 2, dir: DIR.OUT, bytes: stale });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(seen, [], 'the app\'s leftover reply is not relayed');
    const mine = new Uint8Array(64); mine[0] = 7;
    await cli.write(2, mine);
    await until(() => seen.length === 1);
    assert.deepEqual(seen, [8], 'its own answer is');
    await cli.stop();
  } finally {
    await server.stop();
    fs.rmSync(root, { recursive: true, force: true });
  }
});
