/*
 * A device in its identity's room (bucket/src/room-client.js, ok-edge plan M2), against an in-memory server that
 * speaks the protocol of ok-edge mcp-server/ (challenge, room.checkJoin, frames by device id): two devices of one
 * identity join and a request gets its answer; the server sees only sealed bodies; a wrong identity is refused; a
 * frame not sealed by the identity is dropped; a device that leaves fails the requests waiting on it.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { ed25519, x25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');
const bid = require('../src/bucket-identity');
const room = require('../src/room');
const { connectRoom } = require('../src/room-client');

const rnd = (n) => new Uint8Array(crypto.randomBytes(n));
const URL_ = 'https://ok-edge.example.workers.dev';
const HOST = new URL(URL_).host;

async function identity(seed) {
  const secretOf = (label, keyType) => sha256(new Uint8Array([...new TextEncoder().encode(seed), ...label, keyType]));
  const key = { deriveSecret: async (label, { rpId } = {}) => sha256(new TextEncoder().encode(`${seed}|${label}|${rpId}`)), keySite: async () => ({ on: true, site: 'okt.example' }), agent: {
    publicKey: async (label, { keyType }) => (keyType === 1 ? ed25519.getPublicKey(secretOf(label, 1)) : x25519.getPublicKey(secretOf(label, 4))),
    ecdh: async (label, peer) => x25519.getSharedSecret(secretOf(label, 4), peer),
    sign: async (label, message) => ed25519.sign(message, secretOf(label, 1)),
  } };
  const { publicKey, id } = await bid.readIdentity(key);
  const bucketKey = await bid.deriveBucketKeyAt(key, publicKey, 'okt.example');
  const certificate = await bid.certify(key, publicKey, bucketKey.publicKey);
  return { id, identityPublicKey: publicKey, bucketKey, certificate };
}

/* the server, as mcp-server/src/index.js behaves, in memory; `seen` keeps every frame body it passed */
function fakeServer() {
  const sockets = new Set();
  const seen = [];
  /* the agents each room knows, and every mcp-re the server got */
  const agents = new Map();
  const mcpSeen = [];
  /* an agent's message to a room's joined devices, as /mcp sends it */
  const toRoom = (roomId, msg) => { for (const s of joined(roomId)) s.deliver({ t: 'mcp', ...msg }); };
  const joined = (roomId) => [...sockets].filter((s) => s.room === roomId && s.device);
  class FakeWS {
    constructor(url) {
      const u = new URL(url);
      this.room = u.pathname.split('/').pop();
      sockets.add(this);
      const { nonce, message } = room.challenge(rnd);
      this.nonce = nonce;
      setImmediate(() => this.deliver(message));
    }
    deliver(m) { if (this.onmessage) this.onmessage({ data: JSON.stringify(m) }); }
    send(text) {
      const m = JSON.parse(text);
      if (!this.device) {
        const c = room.checkJoin(this.room, m, { nonce: this.nonce, host: HOST });
        if (!c.ok) { this.deliver({ t: 'refused' }); return this.close(); }
        const peers = joined(this.room).map((s) => s.device);
        this.device = c.device;
        this.deliver({ t: 'joined', you: c.device.id, peers });
        for (const s of joined(this.room)) if (s !== this) s.deliver({ t: 'peer', up: c.device });
        return;
      }
      if (m.t === 'ping') return this.deliver({ t: 'pong' });
      /* the owner's answers to the agents, as the room answers them: its broadcast first (the sender hears it too),
       * then the reply carrying the device's re */
      if (m.t === 'mcp-re') {
        mcpSeen.push(m);
        const reply = (r) => this.deliver({ ...r, re: m.re });
        if (m.op === 'agents') return reply({ t: 'mcp', ev: 'agents', agents: agents.get(this.room) || [], plans: [] });
        if (m.op === 'agent') {
          const list = agents.get(this.room) || [];
          const a = list.find((x) => x.id === m.agent);
          if (!a) return reply({ t: 'error', why: 'no such agent here' });
          a.state = m.state;
          for (const s of joined(this.room)) s.deliver({ t: 'mcp', ev: 'agent', agent: a });
          return reply({ t: 'mcp', ev: 'ok', op: 'agent' });
        }
        if (m.op === 'plan') return reply({ t: 'mcp', ev: 'ok', op: 'plan' });
        /* an answer the room is slow with: no reply yet */
        if (m.op === 'slow') return undefined;
        return reply({ t: 'error', why: 'unknown op' });
      }
      if (m.t === 'frame') {
        seen.push(m.body);
        const to = joined(this.room).find((s) => s.device.id === m.to);
        return to ? to.deliver({ t: 'frame', from: this.device.id, body: m.body }) : this.deliver({ t: 'gone', to: m.to });
      }
    }
    close() {
      if (!sockets.delete(this)) return;
      if (this.device) for (const s of joined(this.room)) s.deliver({ t: 'peer', down: this.device.id });
      setImmediate(() => this.onclose && this.onclose({}));
    }
  }
  return { FakeWS, seen, sockets, agents, mcpSeen, toRoom };
}

const dev = (name, kind) => ({ id: crypto.randomBytes(8).toString('hex'), name, kind });

test('two devices of one identity meet; a request is answered; the server passes only sealed bodies', async () => {
  const me = await identity('backup A');
  const { FakeWS, seen } = fakeServer();
  const cli = dev('zbox', 'cli');
  const web = dev('Chromium', 'webapp');
  const a = await connectRoom({ url: URL_, me, device: cli, WebSocket: FakeWS, randomBytes: rnd });
  const ups = [];
  a.on('peer', (p) => ups.push(p));
  const b = await connectRoom({ url: URL_, me, device: web, WebSocket: FakeWS, randomBytes: rnd });
  assert.deepEqual(b.peers(), [cli]);
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(ups, [{ up: web }]);

  b.serve(async (from, message) => ({ echo: message.say, from }));
  const answer = await a.request(web.id, { type: 'okbucket.hello', say: 'secret-ish words' });
  assert.deepEqual(answer, { echo: 'secret-ish words', from: cli.id });
  assert.equal(seen.length, 2);
  for (const body of seen) assert.ok(!body.includes(Buffer.from('secret-ish').toString('hex')) && !/secret/.test(body), 'a body went through the server readable');
  a.close();
  b.close();
});

test('another identity is refused; a frame not sealed by the identity is dropped; a leaving device fails its requests', async () => {
  const me = await identity('backup A');
  const other = await identity('backup B');
  const { FakeWS, sockets } = fakeServer();

  /* a key of another backup asking for this identity's room */
  await assert.rejects(connectRoom({ url: URL_, me: { ...other, id: me.id }, device: dev('x', 'cli'), WebSocket: FakeWS, randomBytes: rnd }), /refused the join/);

  const a = await connectRoom({ url: URL_, me, device: dev('zbox', 'cli'), WebSocket: FakeWS, randomBytes: rnd });
  const web = dev('Chromium', 'webapp');
  const b = await connectRoom({ url: URL_, me, device: web, WebSocket: FakeWS, randomBytes: rnd });
  let served = 0;
  b.serve(async () => { served++; return 'answered'; });

  /* a body sealed with another identity's frame key reaches b and is dropped, unanswered */
  const wrongKey = room.frameKey(other.bucketKey, me.id);
  const forged = room.sealFrame(wrongKey, { room: me.id, from: a.you, to: web.id }, { id: 1, message: 'hi' }, rnd);
  const bSock = [...sockets].find((s) => s.device && s.device.id === web.id);
  bSock.deliver({ t: 'frame', from: a.you, body: forged });
  /* and a real frame relabelled as coming from another device: its sender is in the sealed data */
  const real = room.sealFrame(room.frameKey(me.bucketKey, me.id), { room: me.id, from: a.you, to: web.id }, { id: 2, message: 'hi' }, rnd);
  bSock.deliver({ t: 'frame', from: 'ffffffffffffffff', body: real });
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(served, 0, 'b answered a frame not sealed by this identity for this sender');

  /* a request to a device that then leaves is rejected, not left hanging */
  const waiting = a.request(web.id, { type: 'slow' }, { timeoutMs: 5000 });
  b.serve(() => new Promise(() => {})); /* never answers */
  b.close();
  await assert.rejects(waiting, /left the room|not in the room|no answer/);
  a.close();
});

test('the agents: their messages reach every device; the owner\'s answers get their own reply, past the broadcasts', async () => {
  const me = await identity('backup A');
  const { FakeWS, agents, mcpSeen, toRoom } = fakeServer();
  const a = await connectRoom({ url: URL_, me, device: dev('Chromium', 'webapp'), WebSocket: FakeWS, randomBytes: rnd });
  const b = await connectRoom({ url: URL_, me, device: dev('Pixel', 'android'), WebSocket: FakeWS, randomBytes: rnd });
  const heardA = [];
  const heardB = [];
  a.on('mcp', (m) => heardA.push(m));
  b.on('mcp', (m) => heardB.push(m));

  /* an agent's plan, live in the room */
  const plan = { id: 'p1', title: 'sign two commits', agent: { id: 'a'.repeat(64), name: 'Claude' }, items: [] };
  agents.set(me.id, [{ id: plan.agent.id, name: 'Claude', state: 'pending' }]);
  toRoom(me.id, { ev: 'plan', plan });
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(heardA, [{ ev: 'plan', plan }]);
  assert.deepEqual(heardB, [{ ev: 'plan', plan }]);

  /* the list, for a device that joins later */
  assert.deepEqual(await a.agents(), { agents: [{ id: plan.agent.id, name: 'Claude', state: 'pending' }], plans: [] });

  /* accept: the room's broadcast reaches both devices (the sender too) before the reply - the reply is the waiter's */
  await a.setAgent(plan.agent.id, 'accepted');
  assert.deepEqual(heardA.slice(1), [{ ev: 'agent', agent: { id: plan.agent.id, name: 'Claude', state: 'accepted' } }]);
  assert.equal(heardB.length, 2);

  /* a plan's progress back to its agent, and a refusal that rejects */
  await a.planUpdate('p1', { state: 'done', results: [{ item: 1, signature: 'sig' }], receipts: [{ seq: 4, code: 'OK' }] });
  assert.deepEqual(mcpSeen.at(-1), { t: 'mcp-re', op: 'plan', re: mcpSeen.at(-1).re, plan: 'p1', state: 'done', results: [{ item: 1, signature: 'sig' }], receipts: [{ seq: 4, code: 'OK' }] });
  await assert.rejects(a.setAgent('f'.repeat(64), 'blocked'), /refused it: no such agent here/);

  /* a closing room fails what waits on it */
  const waiting = b.mcp('slow', {}, { timeoutMs: 5000 });
  b.close();
  await assert.rejects(waiting, /closed|did not answer/);
  a.close();
});
